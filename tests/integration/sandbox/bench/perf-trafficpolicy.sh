#!/bin/bash
# TrafficPolicy performance benchmark script
# Usage: KUBECONFIG=<path> ./perf-trafficpolicy.sh [create|update|large|delete|metrics] [count]
#
# Test dimensions:
#   1. create  — batch-create many TrafficPolicy CRs, measure xDS push and ztunnel resource usage
#   2. update  — rapid-fire updates to a single CR, measure control-plane convergence
#   3. large   — single CR with many rules, measure per-policy parse overhead
#   4. delete  — clean up all benchmark CRs
#   5. metrics — collect current metrics snapshot

set -euo pipefail

ACTION=${1:-create}
COUNT=${2:-100}
NS=${NS:-default}
TARGET_POD=${TARGET_POD:-sleep-cc94b7646-bggjz}
TARGET_CONTAINER=${TARGET_CONTAINER:-istio-proxy}

KC="kubectl"

collect_metrics() {
    echo "=== $(date +%H:%M:%S) Metrics ==="
    echo "--- Resource Usage ---"
    $KC top pod -n "$NS" --no-headers 2>/dev/null || true
    echo "--- xDS Messages ---"
    $KC exec -n "$NS" "$TARGET_POD" -c "$TARGET_CONTAINER" -- \
        curl -s localhost:15020/metrics 2>/dev/null | \
        grep -E 'istio_xds_message_total|istio_xds_message_bytes_total' || true
    echo "--- Policy Count in Config Dump ---"
    $KC exec -n "$NS" "$TARGET_POD" -c "$TARGET_CONTAINER" -- \
        curl -s localhost:15000/config_dump 2>/dev/null | \
        python3 -c "
import sys, json
data = json.load(sys.stdin)
policies = data.get('policies', data.get('authorization_policies', []))
if isinstance(policies, list):
    print(f'Authorization policies loaded: {len(policies)}')
elif isinstance(policies, dict):
    print(f'Authorization policies loaded: {sum(len(v) for v in policies.values())}')
else:
    print('Cannot determine policy count')
" 2>/dev/null || echo "(could not parse policy count)"
    echo ""
}

create_batch() {
    echo "=== Baseline Metrics ==="
    collect_metrics

    echo "=== Creating $COUNT TrafficPolicies ==="
    START=$(date +%s%N)

    for i in $(seq 1 "$COUNT"); do
        cat <<EOF | $KC apply -n "$NS" -f - > /dev/null 2>&1 &
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-perf-test-${i}
spec:
  priority: $((500 + i))
  selector:
    matchLabels:
      app: sleep
  egress:
    rules:
      - action: allow
        to:
          - cidr: "10.${i}.0.0/16"
        ports:
          - protocol: TCP
            port: $((8000 + i % 1000))
      - action: allow
        to:
          - cidr: "172.${i}.0.0/16"
        ports:
          - protocol: UDP
            port: $((9000 + i % 1000))
EOF
        if (( i % 20 == 0 )); then
            wait
            echo "  created $i/$COUNT ..."
        fi
    done
    wait

    END=$(date +%s%N)
    ELAPSED=$(( (END - START) / 1000000 ))
    echo "=== All $COUNT CRs created in ${ELAPSED}ms ==="
    echo ""
    echo "=== Waiting 15s for xDS convergence ==="
    sleep 15
    echo "=== Post-Create Metrics ==="
    collect_metrics
}

update_rapid() {
    echo "=== Rapid Update Test: $COUNT updates ==="

    cat <<EOF | $KC apply -n "$NS" -f - > /dev/null
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-rapid-update
spec:
  priority: 999
  selector:
    matchLabels:
      app: sleep
  egress:
    rules:
      - action: allow
        to:
          - cidr: "10.0.0.0/8"
EOF
    sleep 2
    collect_metrics

    START=$(date +%s%N)
    for i in $(seq 1 "$COUNT"); do
        cat <<EOF | $KC apply -n "$NS" -f - > /dev/null 2>&1
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-rapid-update
spec:
  priority: 999
  selector:
    matchLabels:
      app: sleep
  egress:
    rules:
      - action: allow
        to:
          - cidr: "10.${i}.0.0/16"
        ports:
          - protocol: TCP
            port: $((8000 + i % 1000))
EOF
    done
    END=$(date +%s%N)
    ELAPSED=$(( (END - START) / 1000000 ))
    echo "=== $COUNT updates completed in ${ELAPSED}ms ==="
    sleep 10
    echo "=== Post-Update Metrics ==="
    collect_metrics
}

create_large_rule() {
    echo "=== Large Rule Test: $COUNT rules in single CR ==="
    collect_metrics

    RULES=""
    for i in $(seq 1 "$COUNT"); do
        RULES="${RULES}
      - action: allow
        to:
          - cidr: \"10.$((i / 256)).$((i % 256)).0/24\"
        ports:
          - protocol: TCP
            port: $((8000 + i % 1000))"
    done

    START=$(date +%s%N)
    cat <<EOF | $KC apply -n "$NS" -f - > /dev/null
apiVersion: network.alibabacloud.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-large-rules
spec:
  priority: 100
  selector:
    matchLabels:
      app: sleep
  egress:
    rules:${RULES}
EOF
    END=$(date +%s%N)
    ELAPSED=$(( (END - START) / 1000000 ))
    echo "=== CR with $COUNT rules applied in ${ELAPSED}ms ==="
    sleep 15
    echo "=== Post-Apply Metrics ==="
    collect_metrics
}

delete_all() {
    echo "=== Deleting all perf-test TrafficPolicies ==="
    $KC delete trafficpolicy -n "$NS" tp-rapid-update tp-large-rules 2>/dev/null || true
    for i in $(seq 1 "${COUNT}"); do
        $KC delete trafficpolicy -n "$NS" "tp-perf-test-${i}" 2>/dev/null &
        if (( i % 20 == 0 )); then wait; fi
    done
    wait
    echo "=== Cleanup done ==="
    sleep 10
    collect_metrics
}

case "$ACTION" in
    create)    create_batch ;;
    update)    update_rapid ;;
    large)     create_large_rule ;;
    delete)    delete_all ;;
    metrics)   collect_metrics ;;
    *)         echo "Usage: $0 [create|update|large|delete|metrics] [count]"; exit 1 ;;
esac
