#!/usr/bin/env bash
# Test agent lifecycle, dynamic metrics, ADS recovery and Wasm/ECDS using community Envoy or an explicit gateway image.
set -euo pipefail
# Reuse the Dockerfile's pin so unit CI and the packaged runtime stay aligned.
image=${1:-}
build_metrics=false
if [[ -z "$image" ]]; then
  build_metrics=true
  image=$(sed -n "s/^ARG ENVOY_IMAGE=//p" docker/Dockerfile.gateway)
fi
: "${image:?missing Envoy image pin in docker/Dockerfile.gateway}"
artifacts=$(mktemp -d)
trap 'rm -rf "$artifacts"' EXIT
chmod 755 "$artifacts"
module_mount=()
agent_mount=()
if "$build_metrics"; then
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$artifacts/gateway-agent" ./cmd/gateway-agent
  chmod 755 "$artifacts/gateway-agent"
  agent_mount=(--mount "type=bind,src=$artifacts/gateway-agent,dst=/usr/local/bin/gateway-agent,readonly")
  docker build --platform linux/amd64 -f docker/Dockerfile.gateway --target metrics-artifact \
    --output "type=local,dest=$artifacts" .
  chmod 755 "$artifacts" "$artifacts/libagentio_gateway_metrics.so"
  module_mount=(--mount "type=bind,src=$artifacts/libagentio_gateway_metrics.so,dst=/usr/local/lib/libagentio_gateway_metrics.so,readonly")
fi
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$artifacts/gatewayagent.test" ./pkg/gatewayagent
chmod 755 "$artifacts/gatewayagent.test"
docker run --rm --platform linux/amd64 --user 1337:1337 \
  --entrypoint /tests/gatewayagent.test \
  --mount "type=bind,src=$artifacts/gatewayagent.test,dst=/tests/gatewayagent.test,readonly" \
  "${module_mount[@]}" "${agent_mount[@]}" \
  -e AGENTIO_TEST_AGENT_BINARY=/usr/local/bin/gateway-agent \
  -e AGENTIO_TEST_ENVOY_BINARY=/usr/local/bin/envoy \
  -e AGENTIO_TEST_NETWORK_FAULTS=1 \
  "$image" -test.v -test.timeout=90s \
  -test.run='TestGatewayAgentLifecycle|TestCommunityEnvoyWasmECDS|TestADSDetectsSilentBlackhole|TestEnvoyConfiguredBootstrap|TestCommunityEnvoyDynamicMetrics'
