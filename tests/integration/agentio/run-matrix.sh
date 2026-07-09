#!/bin/bash
# Run agentio integration tests across a matrix of configurations.
#
# Usage:
#   ./run-matrix.sh                    # run full matrix
#   ./run-matrix.sh -run TestXxx       # pass extra go test flags
#
# Environment overrides:
#   MODES          space-separated list of modes (default: "sidecar ambient")
#   BACKENDS       space-separated list of firewall backends (default: "auto iptables")
#   TEST_FLAGS     extra flags passed to go test
#   TIMEOUT        per-combination timeout (default: 30m)

set -euo pipefail

MODES="${MODES:-sidecar ambient}"
BACKENDS="${BACKENDS:-auto iptables}"
TIMEOUT="${TIMEOUT:-30m}"
TEST_PKG="./tests/integration/sandbox/..."
EXTRA_FLAGS="${*}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

results=()
total=0
passed=0
failed=0

for mode in ${MODES}; do
  for backend in ${BACKENDS}; do
    total=$((total + 1))
    combo="${mode}/firewall=${backend}"
    echo -e "\n${YELLOW}=== [$total] Running: ${combo} ===${NC}\n"

    env_vars=(
      "FIREWALL_BACKEND=${backend}"
    )
    if [ "$mode" = "ambient" ]; then
      env_vars+=("AMBIENT_MODE=true")
    else
      env_vars+=("AMBIENT_MODE=false")
    fi

    if env "${env_vars[@]}" \
        go test -tags integ -timeout "${TIMEOUT}" ${TEST_PKG} ${EXTRA_FLAGS}; then
      echo -e "${GREEN}=== PASS: ${combo} ===${NC}"
      results+=("PASS  ${combo}")
      passed=$((passed + 1))
    else
      echo -e "${RED}=== FAIL: ${combo} ===${NC}"
      results+=("FAIL  ${combo}")
      failed=$((failed + 1))
    fi
  done
done

echo -e "\n${YELLOW}=== Matrix Results ===${NC}"
for r in "${results[@]}"; do
  if [[ "$r" == PASS* ]]; then
    echo -e "  ${GREEN}${r}${NC}"
  else
    echo -e "  ${RED}${r}${NC}"
  fi
done
echo -e "\nTotal: ${total}  Passed: ${passed}  Failed: ${failed}"

if [ "$failed" -gt 0 ]; then
  exit 1
fi
