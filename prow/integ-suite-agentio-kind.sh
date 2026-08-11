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

WD=$(dirname "$0")
WD=$(cd "$WD"; pwd)
ROOT=$(dirname "$WD")

trim_whitespace() {
  local value=$1
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

configure_scenarios() {
  local requested="${AGENTIO_E2E_SCENARIOS:-sidecar-auto,sidecar-iptables,ambient-auto,ambient-iptables}"
  local raw_scenarios=()
  local selected_names=()
  local raw
  local scenario
  local selected

  SCENARIOS=()
  IFS=',' read -r -a raw_scenarios <<< "${requested}"
  for raw in "${raw_scenarios[@]}"; do
    scenario="$(trim_whitespace "${raw}")"
    if [[ -z "${scenario}" ]]; then
      echo "Agentio E2E scenario list contains an empty item" >&2
      return 1
    fi
    if (( ${#selected_names[@]} > 0 )); then
      for selected in "${selected_names[@]}"; do
        if [[ "${selected}" == "${scenario}" ]]; then
          echo "Duplicate Agentio E2E scenario: ${scenario}" >&2
          return 1
        fi
      done
    fi

    case "${scenario}" in
      sidecar-auto) SCENARIOS+=("sidecar-auto:false:auto") ;;
      sidecar-iptables) SCENARIOS+=("sidecar-iptables:false:iptables") ;;
      ambient-auto) SCENARIOS+=("ambient-auto:true:auto") ;;
      ambient-iptables) SCENARIOS+=("ambient-iptables:true:iptables") ;;
      *)
        echo "unknown Agentio E2E scenario: ${scenario}" >&2
        return 1
        ;;
    esac
    selected_names+=("${scenario}")
  done
}

VALUES_FILE=""
USE_PREBUILT_DATA_PLANE=false
while (( $# > 0 )); do
  case "$1" in
    --values-file)
      if (( $# < 2 )); then
        echo "--values-file requires a path" >&2
        exit 2
      fi
      VALUES_FILE=$2
      shift 2
      ;;
    --use-prebuilt-data-plane)
      USE_PREBUILT_DATA_PLANE=true
      shift
      ;;
    *)
      echo "Unknown Agentio E2E option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "${USE_PREBUILT_DATA_PLANE}" == "true" && -z "${VALUES_FILE}" ]]; then
  echo "--use-prebuilt-data-plane requires --values-file" >&2
  exit 2
fi

ZTUNNEL_BINARY="${AGENTIO_E2E_ZTUNNEL_BINARY:-}"
ZTUNNEL_VERSION="${AGENTIO_E2E_ZTUNNEL_VERSION:-}"
if [[ -n "${ZTUNNEL_BINARY}" || -n "${ZTUNNEL_VERSION}" ]]; then
  if [[ -z "${ZTUNNEL_BINARY}" || -z "${ZTUNNEL_VERSION}" ]]; then
    echo "AGENTIO_E2E_ZTUNNEL_BINARY and AGENTIO_E2E_ZTUNNEL_VERSION must be set together" >&2
    exit 2
  fi
  if [[ ! -f "${ZTUNNEL_BINARY}" || ! -r "${ZTUNNEL_BINARY}" ]]; then
    echo "Agentio ztunnel binary is not a readable regular file: ${ZTUNNEL_BINARY}" >&2
    exit 1
  fi
  if [[ ! "${ZTUNNEL_VERSION}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Invalid Agentio ztunnel version: ${ZTUNNEL_VERSION}" >&2
    exit 1
  fi
  ZTUNNEL_BINARY="$(cd "$(dirname "${ZTUNNEL_BINARY}")"; pwd)/$(basename "${ZTUNNEL_BINARY}")"
fi

PROXY_IMAGE=""
PROXY_DIGEST=""
if [[ "${USE_PREBUILT_DATA_PLANE}" != "true" ]]; then
  PROXY_IMAGE="${AGENTIO_E2E_PROXY_IMAGE:-}"
  PROXY_DIGEST=$(jq -er '.[] | select(.name == "PROXY_IMAGE_DIGEST") | .digest' "${ROOT}/agentio.deps")
  if [[ -z "${PROXY_IMAGE}" ]]; then
    echo "AGENTIO_E2E_PROXY_IMAGE must identify the proxy repository without a tag or digest" >&2
    exit 1
  fi
  if [[ ! "${PROXY_IMAGE}" =~ ^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$ ]]; then
    echo "Invalid Agentio proxy image: ${PROXY_IMAGE}" >&2
    exit 1
  fi
  if [[ ! "${PROXY_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Invalid Agentio proxy digest: ${PROXY_DIGEST}" >&2
    exit 1
  fi
fi

if [[ -n "${VALUES_FILE}" ]]; then
  if [[ ! -r "${VALUES_FILE}" || ! -f "${VALUES_FILE}" ]]; then
    echo "Agentio Helm values file is not a readable regular file: ${VALUES_FILE}" >&2
    exit 1
  fi
  VALUES_FILE="$(cd "$(dirname "${VALUES_FILE}")"; pwd)/$(basename "${VALUES_FILE}")"
  # The resolved path is forwarded through the space-separated INTEGRATION_TEST_FLAGS
  # string, which make expands unquoted into the `go test` command line (see the
  # run-test macro in tests/integration/tests.mk). Whitespace would be word-split and
  # shell metacharacters would be interpreted there, so the checkout must live under a
  # path restricted to this safe character set.
  if [[ "${VALUES_FILE}" == *[[:space:]]* ]]; then
    echo "Agentio Helm values file path must not contain whitespace: ${VALUES_FILE}" >&2
    echo "Move the checkout to a path without spaces to run the local Agentio E2E target." >&2
    exit 1
  fi
  if [[ ! "${VALUES_FILE}" =~ ^[A-Za-z0-9_./-]+$ ]]; then
    echo "Agentio Helm values file path contains unsupported characters: ${VALUES_FILE}" >&2
    echo "Only letters, digits, underscore, dot, slash, and hyphen are supported." >&2
    exit 1
  fi
fi

configure_scenarios

if [[ -n "${INTEGRATION_TEST_FLAGS:-}" ]]; then
  echo "INTEGRATION_TEST_FLAGS is not supported by the Agentio E2E runner" >&2
  exit 1
fi
if [[ -n "${T:-}" ]]; then
  echo "T is not supported by the Agentio E2E runner; use AGENTIO_E2E_TEST or make TEST=TestName" >&2
  exit 1
fi
if [[ -n "${AGENTIO_E2E_TEST:-}" ]]; then
  if [[ ! "${AGENTIO_E2E_TEST}" =~ ^[A-Za-z0-9_./-]+$ ]]; then
    echo "Invalid Agentio E2E test name: test name may contain only letters, digits, underscore, dot, slash, and hyphen" >&2
    exit 1
  fi
  export T="-v -count=1 -run ${AGENTIO_E2E_TEST}"
else
  export T="-v -count=1"
fi

case "${AGENTIO_E2E_VALIDATE_ONLY:-false}" in
  true | false) ;;
  *)
    echo "Invalid AGENTIO_E2E_VALIDATE_ONLY value: expected 'true' or 'false'" >&2
    exit 1
    ;;
esac
if [[ "${AGENTIO_E2E_VALIDATE_ONLY:-false}" == "true" ]]; then
  printf 'VALUES_FILE=%s\n' "${VALUES_FILE}"
  printf 'USE_PREBUILT_DATA_PLANE=%s\n' "${USE_PREBUILT_DATA_PLANE}"
  printf 'ZTUNNEL_BINARY=%s\n' "${ZTUNNEL_BINARY}"
  printf 'ZTUNNEL_VERSION=%s\n' "${ZTUNNEL_VERSION}"
  printf 'PROXY_IMAGE=%s\n' "${PROXY_IMAGE}"
  printf 'PROXY_DIGEST=%s\n' "${PROXY_DIGEST}"
  printf 'AGENTIO_E2E_SCENARIO=%s\n' "${SCENARIOS[@]}"
  printf 'T=%s\n' "${T:-}"
  exit 0
fi

set -x

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

# Each selected scenario gets a fresh cluster so ambient CNI and firewall state
# cannot leak into another scenario. The registry and its images remain
# available on Docker's kind network across cluster recreation.

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

mirror_pinned_proxy() {
  local platform=$1
  local source_image="${PROXY_IMAGE}@${PROXY_DIGEST}"
  local target_image="${HUB}/proxyv2:${TAG}"

  docker pull --platform="${platform}" "${source_image}"
  docker tag "${source_image}" "${target_image}"
  docker push "${target_image}"
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
  run_traced "setup ${scenario} kind registry" setup_kind_registry "${cluster_name}" || return $?

  if [[ "${IMAGES_BUILT}" == "false" ]]; then
    # agentio-epe is built but never deployed here: no scenario sets epe.enabled=true.
    # It keeps the image build itself covered on every presubmit.
    local docker_targets="docker.pilot docker.proxy-init docker.install-cni docker.app docker.ext-proc docker.agentio-epe"
    local target_arch
    if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
      arch=linux/arm64
    fi
    target_arch="${arch#linux/}"

    # A local Helm overlay may point proxy and ztunnel at other prebuilt images.
    # The default CI path mirrors the agentio.deps-pinned proxy and packages the
    # pinned ztunnel binary supplied through AGENTIO_E2E_ZTUNNEL_BINARY.
    if [[ "${USE_PREBUILT_DATA_PLANE}" != "true" ]]; then
      run_traced "mirror pinned Agentio proxy" mirror_pinned_proxy "${arch}" || return $?
      if [[ -n "${ZTUNNEL_BINARY}" ]]; then
        install -D -m 0755 "${ZTUNNEL_BINARY}" "${ROOT}/out/linux_${target_arch}/ztunnel"
        run_traced "package pinned Agentio ztunnel" env \
          SKIP_MAKE=true \
          DOCKER_ARCHITECTURES="${arch}" \
          DOCKER_BUILD_VARIANTS="${VARIANT}" \
          DOCKER_TARGETS="docker.ztunnel" \
          TAG="${TAG}" \
          ./tools/docker --push --ztunnel-version="${ZTUNNEL_VERSION}" || return $?
      else
        docker_targets+=" docker.ztunnel"
      fi
    fi
    run_traced "build Agentio test images" env \
      DOCKER_ARCHITECTURES="${arch}" \
      DOCKER_BUILD_VARIANTS="${VARIANT}" \
      DOCKER_TARGETS="${docker_targets}" \
      make dockerx.pushx || return $?
    IMAGES_BUILT=true
  fi

  # Avoid stale negative DNS entries while the suite installs and removes test
  # workloads in quick succession.
  kubectl get -oyaml -n=kube-system configmap/coredns | \
    sed 's/ttl 30/ttl 0/g' | kubectl apply -f - || return $?

  log "Running Agentio E2E scenario ${scenario}"
  local integration_test_flags=""
  if [[ -n "${VALUES_FILE}" ]]; then
    integration_test_flags="${integration_test_flags:+${integration_test_flags} }--istio.test.kube.agentio.helm.valuesFile=${VALUES_FILE}"
  fi
  env \
    AMBIENT_MODE="${ambient_mode}" \
    ENABLE_FIREWALL=true \
    FIREWALL_BACKEND="${firewall_backend}" \
    INTEGRATION_TEST_FLAGS="${integration_test_flags}" \
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
