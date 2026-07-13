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

ROOT_ARTIFACTS="${ARTIFACTS:-$(mktemp -d)}"
mkdir -p "${ROOT_ARTIFACTS}"
export ARTIFACTS="${ROOT_ARTIFACTS}"
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

NODE_IMAGE="${NODE_IMAGE:-gcr.io/istio-testing/kind-node:v1.35.0}"
CURRENT_CLUSTER=""
IMAGES_BUILT=false

# Each scenario gets a fresh cluster so ambient CNI and firewall state cannot
# leak into another scenario. The registry and its images remain available on
# Docker's kind network across cluster recreation.
SCENARIOS=(
  "sidecar-auto:false:auto"
  "ambient-auto:true:auto"
  "ambient-iptables:true:iptables"
)

cleanup_current_cluster() {
  if [[ -z "${CURRENT_CLUSTER}" ]]; then
    return
  fi

  kind export logs --name "${CURRENT_CLUSTER}" "${ARTIFACTS}/kind" -v9 || true
  kind delete cluster --name "${CURRENT_CLUSTER}" -v9 || true

  local clusters
  if ! clusters="$(kind get clusters)"; then
    log "Failed to verify deletion of KinD cluster ${CURRENT_CLUSTER}"
    return 1
  fi
  if grep -Fxq "${CURRENT_CLUSTER}" <<< "${clusters}"; then
    log "KinD cluster ${CURRENT_CLUSTER} still exists; refusing to run another scenario"
    return 1
  fi

  CURRENT_CLUSTER=""
}

cleanup_on_exit() {
  local exit_code=$?
  trap - EXIT
  cleanup_current_cluster
  exit "${exit_code}"
}

run_traced() {
  local label=$1
  shift
  local start
  local elapsed
  local status

  log "Running '${label}'"
  start="$(date_cmd -u +%s.%N)"
  set +e
  tracing::run "${label}" "$@"
  status=$?
  set -e
  elapsed="$(date_cmd +%s.%N --date="${start} seconds ago")"
  log "Command '${label}' complete in ${elapsed}s with exit code ${status}"
  echo "'${label}': ${elapsed}" >> "${ARTIFACTS}/trace.yaml"
  return "${status}"
}

record_summary() {
  local results=("$@")

  echo
  echo "Agentio E2E scenario results:"
  printf '  %s\n' "${results[@]}"

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "### Agentio E2E scenarios"
      echo
      echo "| Scenario | Result |"
      echo "| --- | --- |"
      local result
      for result in "${results[@]}"; do
        echo "| ${result%%:*} | ${result#*:} |"
      done
    } >> "${GITHUB_STEP_SUMMARY}"
  fi
}

run_scenario() {
  local scenario=$1
  local ambient_mode=$2
  local firewall_backend=$3
  local cluster_name="agentio-${scenario}"
  local arch=linux/amd64

  export ARTIFACTS="${ROOT_ARTIFACTS}/${scenario}"
  mkdir -p "${ARTIFACTS}"

  CURRENT_CLUSTER="${cluster_name}"
  run_traced "setup ${scenario} kind cluster" \
    setup_kind_cluster_retry "${cluster_name}" "${NODE_IMAGE}" "" "" false || return $?
  run_traced "setup ${scenario} kind registry" setup_kind_registry || return $?

  if [[ "${IMAGES_BUILT}" == "false" ]]; then
    if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
      arch=linux/arm64
    fi

    # Agentio deploys proxy and ztunnel from external image overrides. Build
    # only repository images consumed by this suite, once, into the shared
    # KinD-local registry.
    run_traced "build Agentio test images" env \
      DOCKER_ARCHITECTURES="${arch}" \
      DOCKER_BUILD_VARIANTS="${VARIANT}" \
      DOCKER_TARGETS="docker.pilot docker.install-cni docker.app docker.ext-proc" \
      make dockerx.pushx || return $?
    IMAGES_BUILT=true
  fi

  # Avoid stale negative DNS entries while the suite installs and removes test
  # workloads in quick succession.
  kubectl get -oyaml -n=kube-system configmap/coredns | \
    sed 's/ttl 30/ttl 0/g' | kubectl apply -f - || return $?

  log "Running Agentio E2E scenario ${scenario}"
  env \
    AMBIENT_MODE="${ambient_mode}" \
    ENABLE_FIREWALL=true \
    FIREWALL_BACKEND="${firewall_backend}" \
    make test.integration.agentio.kube
}

trap cleanup_on_exit EXIT

run_traced "init" make init

failed=0
results=()
for scenario_config in "${SCENARIOS[@]}"; do
  IFS=: read -r scenario ambient_mode firewall_backend <<< "${scenario_config}"

  if run_scenario "${scenario}" "${ambient_mode}" "${firewall_backend}"; then
    results+=("${scenario}:passed")
  else
    results+=("${scenario}:failed")
    failed=1
  fi

  if ! cleanup_current_cluster; then
    results+=("${scenario}-cleanup:failed")
    failed=1
    break
  fi
done

record_summary "${results[@]}"
exit "${failed}"
