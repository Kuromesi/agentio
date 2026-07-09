# TrafficPolicy Performance Test Report

**Date:** 2026-06-10
**Cluster:** cluster-xqIgiw (ACK, single node)
**Deployment:** ztunnel sidecar mode (injected via `istio-proxy` container)
**Workloads:** sleep (client), httpbin (server) in `default` namespace

## Baseline

| Metric | Value |
|--------|-------|
| sleep pod CPU | 1m |
| sleep pod Memory | 3Mi |
| Authorization policies loaded | 2 |
| xDS Auth messages | 189 |
| xDS Auth bytes | 19KB |

## Test 1: Batch CR Creation (100 CRs)

Created 100 TrafficPolicy CRs targeting the sleep pod, each with 2 rules (1 TCP allow + 1 UDP deny on distinct CIDRs).

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| CPU | 1m | 2m | +1m |
| Memory | 3Mi | 3Mi | +0 |
| Policies loaded | 2 | 102 | +100 |
| xDS Auth messages | 189 | 196 | +7 |
| xDS Auth bytes | 19KB | 39KB | +20KB |
| Wall-clock (create) | — | 5.5s | — |
| Convergence time | — | <2s | — |

**Key finding:** The control plane debounce mechanism merged 100 CR events into only 7 xDS pushes. Memory impact is negligible.

## Test 2: Rapid Update (50 updates to single CR)

Updated the same TrafficPolicy CR 50 times in 28 seconds (changing CIDR and port each time).

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| CPU | 1m | 9m | +8m |
| Memory | 4Mi | 5Mi | +1Mi |
| xDS Auth messages | 197 | 247 | +50 |

**Key finding:** Each update triggers one xDS push (no debounce for sequential updates). CPU spikes to 9m during the burst but remains in the single-digit millicore range. Memory increase is 1Mi.

## Test 3: Single CR with 200 Rules

Applied one TrafficPolicy containing 200 egress rules (each with a unique CIDR and TCP port).

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| CPU | 7m | 7m | +0 |
| Memory | 5Mi | 5Mi | +0 |
| xDS Auth messages | 247 | 248 | +1 |
| xDS Auth bytes | 48KB | 55KB | +7KB |
| CR apply time | — | 820ms | — |

**Key finding:** A single large CR produces one xDS push of ~7KB. No measurable CPU or memory impact on ztunnel.

## Test 4: Rule Effectiveness at Scale

With 100 noise CRs (200 rules total) loaded, verified that actual allow/deny policies work correctly.

| Test Case | Expected | Result |
|-----------|----------|--------|
| httpbin:8000/get (TCP, in allow list) | 200 | PASS |
| httpbin:8000/headers (same port, different path) | 200 | PASS |
| kubernetes:443 (catch-all deny) | blocked | PASS |
| 1.1.1.1:80 (external IP, deny) | blocked | PASS |
| DNS resolution (priority-1 allow) | ok | PASS |
| sleep:80 (not in allow list) | blocked | PASS |

**Result: 6/6 passed.** Policy matching remains correct with 100+ CRs loaded.

## Summary

| Dimension | Scale Tested | Impact | Verdict |
|-----------|-------------|--------|---------|
| CR count | 100 CRs | CPU +1m, Memory +0 | Negligible |
| Update frequency | 50 updates/28s | CPU peak 9m | Acceptable |
| Rules per CR | 200 rules | +7KB xDS, no CPU/mem change | Negligible |
| Rule correctness | 100 noise CRs + 6 assertions | 6/6 passed | Correct |

The ztunnel sidecar handles TrafficPolicy at scale with minimal overhead. The control plane's debounce mechanism effectively batches CR events, and ztunnel's memory footprint remains stable regardless of policy count.
