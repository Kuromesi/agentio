# TrafficPolicy Performance Test

Stress-test script for evaluating ztunnel sidecar performance under large numbers of TrafficPolicy CRs and rules.

## Files

| File | Description |
|------|-------------|
| `perf-trafficpolicy.sh` | Test harness — creates/updates/deletes CRs and collects metrics |
| `perf-trafficpolicy-report.md` | Results from the 2026-06-10 test run |

## Prerequisites

- `kubectl` configured with cluster access
- Target namespace has pods with ztunnel sidecar injection (`istio-proxy` container)
- TrafficPolicy CRD registered in the cluster

## Usage

```bash
export KUBECONFIG=~/.kube/my-config/<cluster>

# Optional: override target pod and namespace
export NS=default
export TARGET_POD=sleep-xxx-yyy
export TARGET_CONTAINER=istio-proxy
```

### Test Scenarios

```bash
# 1. Batch create — measures xDS push batching and resource impact
./perf-trafficpolicy.sh create 100

# 2. Rapid update — measures convergence under high-frequency changes
./perf-trafficpolicy.sh update 50

# 3. Large rule set — measures single-CR with many rules
./perf-trafficpolicy.sh large 200

# 4. Collect current metrics without creating anything
./perf-trafficpolicy.sh metrics

# 5. Cleanup all test CRs
./perf-trafficpolicy.sh delete 100
```

## What It Measures

| Metric | Source | Description |
|--------|--------|-------------|
| CPU / Memory | `kubectl top pod` | Pod-level resource consumption |
| xDS message count | ztunnel `:15020/metrics` | Number of Authorization xDS pushes received |
| xDS bytes | ztunnel `:15020/metrics` | Total bytes received for Authorization type |
| Policy count | ztunnel `:15000/config_dump` | Number of authorization policies loaded |
| Convergence time | Script timing | Time from last CR apply to policy appearing in config dump |

## Interpreting Results

- **xDS messages << CR count** means the control plane debounce is working (good).
- **Memory flat** under load means ztunnel policy storage is efficient.
- **CPU spikes** during rapid updates are expected and should settle within seconds.
- Run `metrics` after each test to compare against the baseline in the report.
