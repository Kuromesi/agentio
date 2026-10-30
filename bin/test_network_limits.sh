#!/usr/bin/env bash
# Run the Go CONNECT regressions against the exact candidate gateway/module image.
set -euo pipefail
image=${1:?usage: bin/test_network_limits.sh IMAGE}
test_arch=${GOARCH:-$(go env GOARCH)}
artifacts=$(mktemp -d)
trap 'rm -rf "$artifacts"' EXIT
chmod 755 "$artifacts"
CGO_ENABLED=0 GOOS=linux GOARCH="$test_arch" go test -c \
  -o "$artifacts/network-limits.test" ./extensions/envoy/network-limits/tests
chmod 755 "$artifacts/network-limits.test"
docker run --rm --platform "linux/$test_arch" --user 1337:1337 \
  --entrypoint /tests/network-limits.test \
  --mount "type=bind,src=$artifacts/network-limits.test,dst=/tests/network-limits.test,readonly" \
  -e AGENTIO_TEST_ENVOY_BINARY=/usr/local/bin/envoy \
  "$image" -test.v -test.timeout=3m
