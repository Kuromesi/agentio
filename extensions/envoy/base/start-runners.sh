#!/usr/bin/env bash
# Copyright 2026 The Kruise Authors
set -euo pipefail
: "${KUBECONFIG:?Set KUBECONFIG to the dedicated ACK administrator configuration}"
base=$(cd "$(dirname "$0")" && pwd)
gh api --method POST repos/Kuromesi/agentio/actions/runners/registration-token |
  python3 -c '
import json, sys
print(json.dumps({"apiVersion": "v1", "kind": "Secret",
                  "metadata": {"name": "envoy-runner-registration", "namespace": "envoy-build"},
                  "stringData": {"token": json.load(sys.stdin)["token"]}}))
' | kubectl apply -f -
kubectl create -f "$base/ack-runner.yaml"
