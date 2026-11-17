#!/usr/bin/env python3
# Copyright 2026 The Kruise Authors
"""Run the pinned Envoy build on an existing ECS through Cloud Assistant."""

import argparse
import json
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time


def cli(region, operation, *arguments):
    completed = subprocess.run(
        ["aliyun", "ecs", operation, "--region", region, "--RegionId", region,
         *arguments], check=True, text=True, stdout=subprocess.PIPE,
    )
    return json.loads(completed.stdout)


def validate(args):
    patterns = {
        "revision": r"[0-9a-f]{40}",
        "image": r"[a-z0-9][a-z0-9.-]*(?::[0-9]+)?(?:/[a-z0-9][a-z0-9._-]*)+",
        "tag": r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}",
        "instance": r"i-[A-Za-z0-9]+",
    }
    for field, pattern in patterns.items():
        if not re.fullmatch(pattern, getattr(args, field)):
            raise ValueError(f"Invalid {field}")
    if args.phase == "publish":
        for reference in (args.amd64_image, args.arm64_image):
            image_reference(reference, args.image)


def image_reference(value, repository):
    if not re.fullmatch(re.escape(repository) + r"@sha256:[0-9a-f]{64}", value):
        raise ValueError("Expected an immutable digest in the configured image repository")
    return value


def command(args):
    directory = f"/disk1/agentio-envoy/runs/{args.revision}/agentio"
    log = f"/disk1/agentio-envoy/logs/{args.tag}-{args.phase}-{args.arch}.log"
    if args.phase == "build":
        arguments = ["build.sh", args.image, args.tag, args.arch]
    else:
        arguments = ["publish.sh", args.image, args.tag,
                     args.amd64_image, args.arm64_image]
    return "\n".join([
        "set -euo pipefail",
        "mkdir -p /disk1/agentio-envoy/logs",
        f"log={shlex.quote(log)}",
        # Cloud Assistant retains at most 24 KiB of output; keep the full log on ECS.
        "exec 3>&1",
        "trap 'code=$?; tail -c 16000 \"$log\" >&3; exit \"$code\"' EXIT",
        "exec >\"$log\" 2>&1",
        f"mkdir -p {shlex.quote(directory)}",
        f"cd {shlex.quote(directory)}",
        "if [[ ! -d .git ]]; then git init -q; fi",
        "git fetch --depth=1 https://github.com/Kuromesi/agentio.git " + args.revision,
        "git checkout --detach --force FETCH_HEAD",
        shlex.join(["bash", "extensions/envoy/base/" + arguments[0], *arguments[1:]]),
    ])


def wait(region, instance, invocation, timeout):
    deadline = time.monotonic() + timeout
    pending = {"Pending", "Running", "Stopping"}
    while time.monotonic() < deadline:
        response = cli(region, "DescribeInvocationResults", "--InvokeId", invocation,
                       "--InstanceId", instance, "--ContentEncoding", "PlainText")
        results = response["Invocation"]["InvocationResults"]["InvocationResult"]
        if results and results[0]["InvocationStatus"] not in pending:
            return results[0]
        time.sleep(10)
    raise TimeoutError(f"Cloud Assistant invocation {invocation} did not finish")


def run(args):
    validate(args)
    timeout = 19800 if args.phase == "build" else 900
    invocation = cli(args.region, "RunCommand", "--Type", "RunShellScript",
                     "--InstanceId.1", args.instance, "--ContentEncoding", "PlainText",
                     "--CommandContent", command(args), "--Timeout", str(timeout),
                     "--TerminationMode", "ProcessTree", "--KeepCommand", "false")["InvokeId"]
    print(f"Cloud Assistant invocation: {invocation}", flush=True)
    terminal = False
    succeeded = False
    try:
        result = wait(args.region, args.instance, invocation, timeout + 120)
        terminal = True
        print(result["Output"], flush=True)
        if result["InvocationStatus"] != "Success" or result["ExitCode"] != 0:
            raise RuntimeError(f"Remote {args.phase} failed: {result['InvocationStatus']} "
                               f"{result.get('ErrorInfo', '')}")
        references = re.findall(r"^AGENTIO_IMAGE=(.+)$", result["Output"], re.MULTILINE)
        if result.get("Dropped", 0) or len(references) != 1:
            raise RuntimeError("Remote output did not contain exactly one complete image result")
        reference = image_reference(references[0], args.image)
        Path(args.output).write_text(reference + "\n")
        succeeded = True
        return reference
    finally:
        if not terminal:
            cli(args.region, "StopInvocation", "--InvokeId", invocation,
                "--InstanceId.1", args.instance)
        if not succeeded and args.phase == "build":
            # Stopping a Docker CLI process alone does not stop its daemon-owned container.
            container = f"agentio-envoy-{args.arch}-{args.tag}"
            cleanup = (
                "set -euo pipefail\n"
                f"container={shlex.quote(container)}\n"
                'if [[ -n $(docker container ls -aq --filter "name=^/$container$") ]]; then\n'
                '  docker rm --force "$container"\n'
                "fi\n"
            )
            cleanup_id = cli(args.region, "RunCommand", "--Type", "RunShellScript",
                             "--InstanceId.1", args.instance, "--CommandContent", cleanup,
                             "--ContentEncoding", "PlainText", "--Timeout", "60",
                             "--KeepCommand", "false")["InvokeId"]
            cleaned = wait(args.region, args.instance, cleanup_id, 120)
            if cleaned["InvocationStatus"] != "Success" or cleaned["ExitCode"] != 0:
                raise RuntimeError(f"Unable to clean up build container: {cleaned}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["build", "publish"])
    parser.add_argument("--region", default="cn-hongkong")
    parser.add_argument("--instance", required=True)
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
