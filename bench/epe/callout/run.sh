#!/usr/bin/env bash
# Run prebuilt Linux binaries on a Docker host; retain raw output for comparison.
set -euo pipefail
cd "$(dirname "$0")"
image=${ENVOY_IMAGE:-envoyproxy/envoy:v1.39.4}
export GOMAXPROCS=${GOMAXPROCS:-4}
mkdir -p results
./callout.test -test.v -test.run '^TestEnvoyE2E$' -envoy-image "$image" > results/e2e.log 2>&1
run() {
  local name=$1
  shift
  echo "Running $name"
  ./callout.test -test.v -test.run '^TestEnvoyLoad$' -test.timeout 15m -envoy-image "$image" "$@" > "results/$name.log" 2>&1
}
for concurrency in 1 16 64 128 256; do
  run "baseline-c$concurrency" -callout-path /baseline -callout-concurrency "$concurrency" -callout-requests 20000
  run "request-1k-c$concurrency" -callout-concurrency "$concurrency" -callout-requests 20000
done
run headers-c64 -callout-path /headers/continue/closed -callout-concurrency 64 -callout-requests 20000
for phase in request response; do
  run "$phase-64k-c64" -callout-path "/$phase/continue/closed" -callout-body 65536 -callout-concurrency 64 -callout-requests 10000
  run "$phase-1m-c64" -callout-path "/$phase/continue/closed" -callout-body 1048576 -callout-concurrency 64 -callout-requests 2000
done
for mode in status malformed oversize reset delay; do
  for policy in open closed; do
    status=200
    if [[ $policy == closed ]]; then status=500; fi
    run "$mode-$policy" -callout-path "/request/$mode/$policy" -callout-status "$status" -callout-concurrency 128 -callout-requests 2000
  done
done
for trial in 1 2 3; do
  run "steady-baseline-$trial" -callout-path /baseline -callout-concurrency 64 -callout-requests 100000
  run "steady-callout-$trial" -callout-concurrency 64 -callout-requests 100000
done
run soak -callout-rate 1000 -callout-concurrency 64 -callout-requests 30000 -callout-rounds 10
