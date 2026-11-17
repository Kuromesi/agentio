# Copyright 2026 The Kruise Authors
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("cloud_build", Path(__file__).with_name("cloud-build.py"))
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
IMAGE = "docker.io/kuromesi/agentio-envoy"
REFERENCE = IMAGE + "@sha256:" + "a" * 64


class CloudBuildTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.args = argparse.Namespace(
            phase="build", kubeconfig="test.kubeconfig", revision="b" * 40,
            image=IMAGE, tag="v1.40.2-review-123", arch="arm64", amd64_image="",
            arm64_image="", output=str(Path(self.directory.name) / "image.txt"),
        )

    def test_success_records_digest_and_deletes_job(self):
        complete = json.dumps({"status": {"conditions": [{"type": "Complete", "status": "True"}]}})
        output = "log\nAGENTIO_IMAGE=" + REFERENCE + "\n"
        with mock.patch.object(BUILD, "kubectl", side_effect=["", complete, output, ""]) as kubectl:
            self.assertEqual(BUILD.run(self.args), REFERENCE)
        self.assertEqual(kubectl.call_args.args[1], "delete")
        self.assertEqual(Path(self.args.output).read_text(), REFERENCE + "\n")
        self.assertEqual(Path(self.args.output).with_suffix(".log").read_text(), output)

    def test_failed_job_or_missing_result_cannot_publish_digest(self):
        for condition, output in [("Failed", "compile failed"), ("Complete", "no result")]:
            with self.subTest(condition=condition):
                terminal = json.dumps({"status": {"conditions": [{"type": condition, "status": "True"}]}})
                with mock.patch.object(BUILD, "kubectl", side_effect=["", terminal, output, ""]) as kubectl:
                    with self.assertRaises(RuntimeError):
                        BUILD.run(self.args)
                self.assertEqual(kubectl.call_args.args[1], "delete")
                self.assertFalse(Path(self.args.output).exists())

    def test_interrupted_poll_deletes_job_and_daemon(self):
        with mock.patch.object(BUILD, "kubectl", side_effect=["", KeyboardInterrupt(), ""]) as kubectl:
            with self.assertRaises(KeyboardInterrupt):
                BUILD.run(self.args)
        self.assertEqual(kubectl.call_args.args[1], "delete")

    def test_untrusted_values_are_rejected_before_cluster_write(self):
        self.args.tag = "tag; touch /tmp/unexpected"
        with mock.patch.object(BUILD, "kubectl") as kubectl:
            with self.assertRaisesRegex(ValueError, "Invalid tag"):
                BUILD.run(self.args)
            kubectl.assert_not_called()
        self.args.tag = "review"
        self.args.phase = "publish"
        self.args.amd64_image = "other.example/envoy@sha256:" + "a" * 64
        self.args.arm64_image = REFERENCE
        with mock.patch.object(BUILD, "kubectl") as kubectl:
            with self.assertRaisesRegex(ValueError, "configured image repository"):
                BUILD.run(self.args)
            kubectl.assert_not_called()

    def test_native_job_has_bounded_lifetime_and_shared_daemon_paths(self):
        manifest = BUILD.job(self.args, "test")
        self.assertEqual(manifest["spec"]["backoffLimit"], 0)
        self.assertEqual(manifest["spec"]["activeDeadlineSeconds"], 19800)
        pod = manifest["spec"]["template"]["spec"]
        self.assertEqual(pod["nodeSelector"]["kubernetes.io/arch"], "arm64")
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["initContainers"][0]["restartPolicy"], "Always")
        for container in pod["initContainers"] + pod["containers"]:
            self.assertIn({"name": "data", "mountPath": "/disk1"}, container["volumeMounts"])
        self.assertIn(self.args.revision, pod["containers"][0]["command"][-1])

    def test_publish_rejects_wrong_architecture_source_or_manifest(self):
        root = Path(self.directory.name)
        binary = root / "bin"
        binary.mkdir()
        (binary / "flock").write_text("#!/bin/sh\nexit 0\n")
        (binary / "flock").chmod(0o755)
        docker = binary / "docker"
        docker.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
if args[0] == "pull":
    pass
elif args[:2] == ["image", "inspect"]:
    if "Architecture" in args[3]:
        arch = "amd64" if args[-1].endswith("a" * 64) else "arm64"
        print("amd64" if os.environ["CASE"] == "wrong-arch" else arch)
    else:
        print("wrong" if os.environ["CASE"] == "wrong-source" else os.environ["REVISION"])
elif args[:3] == ["buildx", "imagetools", "create"]:
    pathlib.Path(os.environ["MARKER"]).write_text("published")
elif args[:3] == ["buildx", "imagetools", "inspect"]:
    if "--raw" in args:
        arches = ["amd64"] if os.environ["CASE"] == "missing-arm" else ["amd64", "arm64"]
        print(json.dumps({"manifests": [{"platform": {"os": "linux", "architecture": a}} for a in arches]}))
    else:
        print(json.dumps({"digest": "sha256:" + "c" * 64}))
else:
    raise RuntimeError(args)
''')
        docker.chmod(0o755)
        publisher = Path(__file__).with_name("publish.sh").resolve()
        revision = subprocess.check_output(["git", "-C", str(publisher.parent), "rev-parse", "HEAD"], text=True).strip()
        marker = root / "published"
        for case in ("valid", "wrong-arch", "wrong-source", "missing-arm"):
            with self.subTest(case=case):
                marker.unlink(missing_ok=True)
                environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                                   CASE=case, REVISION=revision, MARKER=str(marker), DATA_DIR=str(root))
                result = subprocess.run(
                    ["bash", str(publisher), IMAGE, "review", REFERENCE,
                     IMAGE + "@sha256:" + "b" * 64],
                    env=environment, text=True, capture_output=True,
                )
                if case == "valid":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("AGENTIO_IMAGE=" + IMAGE + "@sha256:" + "c" * 64, result.stdout)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertNotIn("AGENTIO_IMAGE=", result.stdout)
                    if case in ("wrong-arch", "wrong-source"):
                        self.assertFalse(marker.exists())

    def test_failed_compile_container_cannot_reach_image_publication(self):
        root = Path(self.directory.name)
        binary = root / "bin"
        binary.mkdir()
        scripts = {
            "flock": "#!/bin/sh\nexit 0\n",
            "uname": "#!/bin/sh\necho x86_64\n",
            "git": "#!/bin/sh\nif [ \"$3\" = rev-parse ]; then echo " + "b" * 40 + "; fi\n",
            "docker": '''#!/usr/bin/env python3
import os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["CALLS"], "a") as log:
    log.write(args[0] + "\\n")
if args[0] == "inspect":
    print(1)
elif args[0] == "rm":
    pathlib.Path(os.environ["CLEANED"]).touch()
elif args[0] not in ("create", "start"):
    raise RuntimeError(args)
''',
        }
        for name, text in scripts.items():
            path = binary / name
            path.write_text(text)
            path.chmod(0o755)
        calls = root / "calls"
        cleaned = root / "cleaned"
        environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                           CALLS=str(calls), CLEANED=str(cleaned), DATA_DIR=str(root))
        result = subprocess.run(
            ["bash", str(Path(__file__).with_name("build.sh")), IMAGE, "review", "amd64"],
            env=environment, text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(calls.read_text().splitlines(), ["create", "start", "inspect", "rm"])
        self.assertTrue(cleaned.exists())


if __name__ == "__main__":
    unittest.main()
