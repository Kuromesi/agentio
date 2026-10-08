#!/usr/bin/env bash
# Test the actual gateway image's Envoy runtime and the maintained ADS relay.
set -euo pipefail
image=${1:?usage: test_gateway_runtime.sh IMAGE}
artifacts=$(mktemp -d)
trap 'rm -rf "$artifacts"' EXIT
chmod 755 "$artifacts"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o "$artifacts/gatewayagent.test" ./pkg/gatewayagent
chmod 755 "$artifacts/gatewayagent.test"
docker run --rm --platform linux/amd64 \
  --entrypoint /tests/gatewayagent.test \
  --mount "type=bind,src=$artifacts/gatewayagent.test,dst=/tests/gatewayagent.test,readonly" \
  -e AGENTIO_TEST_ENVOY_BINARY=/usr/local/bin/envoy \
  -e AGENTIO_TEST_NETWORK_FAULTS=1 \
  "$image" -test.v -test.timeout=90s \
  -test.run='TestCommunityEnvoyWasmECDS|TestADSDetectsSilentBlackhole'
