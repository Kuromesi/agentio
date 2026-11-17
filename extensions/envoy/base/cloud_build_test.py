# Copyright 2026 The Kruise Authors
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("cloud_build", Path(__file__).with_name("cloud-build.py"))
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
IMAGE = "registry-cn-hangzhou.ack.aliyuncs.com/dev/agentio-envoy"
REFERENCE = IMAGE + "@sha256:" + "a" * 64


class CloudBuildTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.args = argparse.Namespace(
            phase="build", region="cn-hongkong", instance="i-builder",
            revision="b" * 40, image=IMAGE, tag="v1.40.2-review-123", arch="arm64",
            amd64_image="", arm64_image="", output=str(Path(self.directory.name) / "image.txt"),
        )
        self.success = {
            "InvocationStatus": "Success", "ExitCode": 0, "Dropped": 0,
            "Output": "build log\nAGENTIO_IMAGE=" + REFERENCE + "\n",
        }

    def test_success_records_only_the_immutable_image(self):
        with mock.patch.object(BUILD, "cli", return_value={"InvokeId": "build"}) as cli, \
                mock.patch.object(BUILD, "wait", return_value=self.success):
            self.assertEqual(BUILD.run(self.args), REFERENCE)
        self.assertEqual(cli.call_count, 1)
        self.assertEqual(Path(self.args.output).read_text(), REFERENCE + "\n")

    def test_remote_failure_cleans_up_its_own_container(self):
        failed = dict(self.success, InvocationStatus="Failed", ExitCode=1)
        with mock.patch.object(BUILD, "cli", return_value={"InvokeId": "cleanup"}) as cli, \
                mock.patch.object(BUILD, "wait", side_effect=[failed, self.success]):
            with self.assertRaisesRegex(RuntimeError, "Remote build failed"):
                BUILD.run(self.args)
        cleanup = cli.call_args.args
        self.assertIn("agentio-envoy-arm64-v1.40.2-review-123", cleanup[cleanup.index("--CommandContent") + 1])
        self.assertFalse(Path(self.args.output).exists())

    def test_timeout_stops_invocation_and_cleans_up_container(self):
        with mock.patch.object(BUILD, "cli", return_value={"InvokeId": "build"}) as cli, \
                mock.patch.object(BUILD, "wait", side_effect=[TimeoutError("expired"), self.success]):
            with self.assertRaisesRegex(TimeoutError, "expired"):
                BUILD.run(self.args)
        self.assertEqual([call.args[1] for call in cli.call_args_list],
                         ["RunCommand", "StopInvocation", "RunCommand"])

    def test_truncated_output_does_not_publish_a_result(self):
        truncated = dict(self.success, Dropped=100)
        with mock.patch.object(BUILD, "cli", return_value={"InvokeId": "build"}), \
                mock.patch.object(BUILD, "wait", side_effect=[truncated, self.success]):
            with self.assertRaisesRegex(RuntimeError, "complete image result"):
                BUILD.run(self.args)
        self.assertFalse(Path(self.args.output).exists())

    def test_remote_values_and_foreign_digest_are_rejected_before_execution(self):
        self.args.tag = "review; touch /tmp/unexpected"
        with mock.patch.object(BUILD, "cli") as cli:
            with self.assertRaisesRegex(ValueError, "Invalid tag"):
                BUILD.run(self.args)
            cli.assert_not_called()
        self.args.tag = "review"
        self.args.phase = "publish"
        self.args.amd64_image = "other.example/envoy@sha256:" + "a" * 64
        self.args.arm64_image = REFERENCE
        with mock.patch.object(BUILD, "cli") as cli:
            with self.assertRaisesRegex(ValueError, "configured image repository"):
                BUILD.run(self.args)
            cli.assert_not_called()

    def test_wait_handles_delivery_delay_and_running_status(self):
        def response(items):
            return {"Invocation": {"InvocationResults": {"InvocationResult": items}}}

        with mock.patch.object(BUILD, "cli", side_effect=[
                response([]), response([{"InvocationStatus": "Running"}]), response([self.success])]), \
                mock.patch.object(BUILD.time, "sleep") as sleep:
            self.assertEqual(BUILD.wait("cn-hongkong", "i-builder", "invocation", 60), self.success)
        self.assertEqual(sleep.call_count, 2)

    def test_log_tail_reaches_the_caller_and_preserves_failure_exit_code(self):
        root = Path(self.directory.name)
        binary = root / "bin"
        binary.mkdir()
        (binary / "git").write_text("#!/bin/sh\nexit 0\n")
        (binary / "git").chmod(0o755)
        script = root / "runs" / self.args.revision / "agentio/extensions/envoy/base/build.sh"
        script.parent.mkdir(parents=True)
        script.write_text("#!/bin/bash\nprintf '%020000d\\n' 0\necho EXPECTED_LOG_TAIL\nexit 7\n")
        environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"])
        result = subprocess.run(
            ["bash", "-c", BUILD.command(self.args).replace("/disk1/agentio-envoy", str(root))],
            env=environment, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("EXPECTED_LOG_TAIL", result.stdout)
        self.assertEqual(len(result.stdout), 16000)
        logs = list((root / "logs").glob("*.log"))
        self.assertEqual(len(logs), 1)
        self.assertGreater(logs[0].stat().st_size, 20000)

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
