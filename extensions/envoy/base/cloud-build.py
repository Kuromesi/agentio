#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
"""Run a native Envoy build Job on the dedicated ACK cluster."""

import argparse
import json
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time
import uuid

NAMESPACE = "envoy-build"


def image_reference(value, repository):
    if not re.fullmatch(re.escape(repository) + r"@sha256:[0-9a-f]{64}", value):
        raise ValueError("Expected an immutable digest in the configured image repository")
    return value


def validate(args):
    for field, pattern in {
        "revision": r"[0-9a-f]{40}",
        "image": r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._-]*)+",
        "tag": r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}",
    }.items():
        if not re.fullmatch(pattern, getattr(args, field)):
            raise ValueError(f"Invalid {field}")
    if args.phase == "publish":
        for reference in (args.amd64_image, args.arm64_image):
            image_reference(reference, args.image)


def kubectl(args, *command, document=None):
    completed = subprocess.run(
        ["kubectl", "--kubeconfig", args.kubeconfig, "-n", NAMESPACE, *command],
        input=json.dumps(document) if document is not None else None,
        check=True, text=True, stdout=subprocess.PIPE,
    )
    return completed.stdout


def job(args, name):
    directory = f"/disk1/agentio-envoy/runs/{args.revision}/agentio"
    arguments = ["build.sh", args.image, args.tag, args.arch] if args.phase == "build" else [
        "publish.sh", args.image, args.tag, args.amd64_image, args.arm64_image]
    command = "\n".join([
        "set -euo pipefail",
        "apk add --no-cache bash python3 git util-linux",
        "mkdir -p /root/.docker /disk1/agentio-envoy",
        "cp /registry/config.json /root/.docker/config.json",
        f"mkdir -p {shlex.quote(directory)}",
        f"cd {shlex.quote(directory)}",
        "if [[ ! -d .git ]]; then git init -q; fi",
        "git fetch --depth=1 https://github.com/Kuromesi/agentio.git " + args.revision,
        "git checkout --detach --force FETCH_HEAD",
        shlex.join(["bash", "extensions/envoy/base/" + arguments[0], *arguments[1:]]),
    ])
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "backoffLimit": 0, "activeDeadlineSeconds": 19800 if args.phase == "build" else 900,
            "ttlSecondsAfterFinished": 86400,
            "template": {"spec": {
                "restartPolicy": "Never", "automountServiceAccountToken": False,
                "nodeSelector": {"kubernetes.io/arch": args.arch, "agentio-build": "true"},
                "volumes": [
                    {"name": "data", "persistentVolumeClaim": {"claimName": "envoy-cache-" + args.arch}},
                    {"name": "registry", "secret": {"secretName": "envoy-registry"}},
                ],
                "initContainers": [{
                    "name": "docker", "image": "docker:27-dind", "restartPolicy": "Always",
                    "securityContext": {"privileged": True},
                    "env": [{"name": "DOCKER_TLS_CERTDIR", "value": ""}],
                    "args": ["--host=tcp://127.0.0.1:2375", "--host=unix:///var/run/docker.sock"],
                    "startupProbe": {"exec": {"command": ["docker", "info"]},
                                     "periodSeconds": 2, "failureThreshold": 90},
                    "resources": {"requests": {"cpu": "26", "memory": "112Gi"},
                                  "limits": {"cpu": "28", "memory": "116Gi"}},
                    "volumeMounts": [{"name": "data", "mountPath": "/disk1"},
                                     {"name": "data", "mountPath": "/var/lib/docker", "subPath": "docker"}],
                }],
                "containers": [{
                    "name": "build", "image": "docker:27-cli", "command": ["/bin/sh", "-ec",
                        "apk add --no-cache bash && exec bash -c " + shlex.quote(command)],
                    "env": [{"name": "DOCKER_HOST", "value": "tcp://127.0.0.1:2375"}],
                    "resources": {"requests": {"cpu": "1", "memory": "2Gi"},
                                  "limits": {"cpu": "2", "memory": "2Gi"}},
                    "volumeMounts": [{"name": "data", "mountPath": "/disk1"},
                                     {"name": "registry", "mountPath": "/registry", "readOnly": True}],
                }],
            }},
        },
    }


def run(args):
    validate(args)
    name = f"envoy-{args.phase}-{args.arch}-{args.revision[:12]}-{uuid.uuid4().hex[:8]}"
    manifest = job(args, name)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    log_path = Path(args.output).with_suffix(".log")
    kubectl(args, "create", "-f", "-", document=manifest)
    print(f"ACK Job: {NAMESPACE}/{name}", flush=True)
    try:
        deadline = time.monotonic() + manifest["spec"]["activeDeadlineSeconds"] + 180
        while time.monotonic() < deadline:
            status = json.loads(kubectl(args, "get", "job", name, "-o", "json")).get("status", {})
            conditions = status.get("conditions", [])
            if any(c["status"] == "True" and c["type"] in ("Complete", "Failed") for c in conditions):
                output = kubectl(args, "logs", "job/" + name, "-c", "build")
                log_path.write_text(output)
                print(output[-16000:], flush=True)
                if not any(c["type"] == "Complete" and c["status"] == "True" for c in conditions):
                    raise RuntimeError(f"ACK {args.phase} Job failed; full log: {log_path}")
                references = re.findall(r"^AGENTIO_IMAGE=(.+)$", output, re.MULTILINE)
                if len(references) != 1:
                    raise RuntimeError("Job did not return exactly one image result")
                reference = image_reference(references[0], args.image)
                Path(args.output).write_text(reference + "\n")
                return reference
            time.sleep(15)
        raise TimeoutError(f"ACK Job {name} did not finish")
    finally:
        # Deleting the Pod also stops its daemon-owned compilation containers.
        kubectl(args, "delete", "job", name, "--cascade=foreground", "--wait=true", "--timeout=120s")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["build", "publish"])
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--arch", choices=["amd64", "arm64"], default="amd64")
    parser.add_argument("--amd64-image", default="")
    parser.add_argument("--arm64-image", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, lambda signum, _: sys.exit(128 + signum))
    run(args)


if __name__ == "__main__":
    main()
