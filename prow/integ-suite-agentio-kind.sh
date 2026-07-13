#!/usr/bin/env bash

# Copyright 2026 The Kruise Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail
set -x

WD=$(dirname "$0")
WD=$(cd "$WD"; pwd)
ROOT=$(dirname "$WD")

# Reuse stable Git/KinD/registry helpers without routing Agentio through the
# upstream all-purpose integration-suite image selection.
# shellcheck source=prow/lib.sh
source "${ROOT}/prow/lib.sh"
# shellcheck source=common/scripts/kind_provisioner.sh
source "${ROOT}/common/scripts/kind_provisioner.sh"

setup_and_export_git_sha

export ARTIFACTS="${ARTIFACTS:-$(mktemp -d)}"
export BUILD_WITH_CONTAINER="${BUILD_WITH_CONTAINER:-0}"
export CI=true
export DEFAULT_CLUSTER_YAML="${ROOT}/prow/config/default.yaml"
export DEVCONTAINER="${DEVCONTAINER:-}"
export FAST_VM_BUILDS=true
export HUB=localhost:5000
export IP_FAMILIES=IPv4
export ISTIO_DOCKER_BUILDER="${ISTIO_DOCKER_BUILDER:-docker}"
export JOB_TYPE=presubmit
export KIND_IP_FAMILY=ipv4
export KIND_REGISTRY=localhost:5000
export KIND_REGISTRY_DIR=/etc/containerd/certs.d/localhost:5000
export KIND_REGISTRY_NAME=kind-registry
export KIND_REGISTRY_PORT=5000
export METRICS_SERVER_CONFIG_DIR=./prow/config/metrics
export PULL_POLICY=IfNotPresent
export T="${T:--v -count=1}"
export TAG="${TAG:-istio-testing}"
export TEST_ENV=kind-metallb
export VARIANT="${VARIANT:-default}"

CLUSTER_NAME="${CLUSTER_NAME:-istio-testing}"
NODE_IMAGE="${NODE_IMAGE:-gcr.io/istio-testing/kind-node:v1.35.0}"

trace "init" make init
trace "setup kind cluster" setup_kind_cluster_retry "${CLUSTER_NAME}" "${NODE_IMAGE}" ""
trace "setup kind registry" setup_kind_registry

arch=linux/amd64
if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
  arch=linux/arm64
fi

# Agentio deploys proxy and ztunnel from the external image overrides. Build
# only the repository images consumed by this suite and publish them solely to
# the ephemeral KinD-local registry.
trace "build Agentio test images" env \
  DOCKER_ARCHITECTURES="${arch}" \
  DOCKER_BUILD_VARIANTS="${VARIANT}" \
  DOCKER_TARGETS="docker.pilot docker.install-cni docker.app docker.ext-proc" \
  make dockerx.pushx

# Avoid stale negative DNS entries while the suite installs and removes test
# workloads in quick succession.
kubectl get -oyaml -n=kube-system configmap/coredns | \
  sed 's/ttl 30/ttl 0/g' | kubectl apply -f -

trace "test Agentio" make test.integration.agentio.kube
