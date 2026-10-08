#!/usr/bin/env bash
# Test ADS recovery and Wasm/ECDS using community Envoy or an explicit gateway image.
set -euo pipefail
# Reuse the Dockerfile's pin so unit CI and the packaged runtime stay aligned.
image=${1:-}
if [[ -z "$image" ]]; then
  image=$(sed -n 's/^ARG ENVOY_IMAGE=//p' docker/Dockerfile.gateway)
fi
: "${image:?missing Envoy image pin in docker/Dockerfile.gateway}"
artifacts=$(mktemp -d)
trap 'rm -rf "$artifacts"' EXIT
chmod 755 "$artifacts"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$artifacts/gatewayagent.test" ./pkg/gatewayagent
chmod 755 "$artifacts/gatewayagent.test"
docker run --rm --platform linux/amd64 --user 1337:1337 \
  --entrypoint /tests/gatewayagent.test \
  --mount "type=bind,src=$artifacts/gatewayagent.test,dst=/tests/gatewayagent.test,readonly" \
  -e AGENTIO_TEST_ENVOY_BINARY=/usr/local/bin/envoy \
  -e AGENTIO_TEST_NETWORK_FAULTS=1 \
  "$image" -test.v -test.timeout=90s \
  -test.run='TestCommunityEnvoyWasmECDS|TestADSDetectsSilentBlackhole'
