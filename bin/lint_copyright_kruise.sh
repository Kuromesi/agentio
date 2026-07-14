#!/usr/bin/env bash
# Verifies every Go file added or modified relative to a base ref carries the
# agentio (Kruise Authors) copyright/modification notice AND an Apache 2.0
# license header. Runs in CI on PRs and pushes. macOS bash 3.2 compatible.
set -euo pipefail

BASE="${1:-${BASE_REF:-}}"
if [[ -z "${BASE}" ]]; then
  if git rev-parse --verify -q origin/master >/dev/null 2>&1; then
    BASE="$(git merge-base origin/master HEAD)"
  else
    BASE="HEAD~1"
  fi
fi

FILES=()
while IFS= read -r line; do
  [[ -n "${line}" ]] && FILES+=("${line}")
done < <(git diff --name-only --diff-filter=ACM "${BASE}" -- '*.go' || true)

ec=0
checked=0
for f in ${FILES[@]+"${FILES[@]}"}; do
  [[ -f "${f}" ]] || continue
  case "${f}" in
    common/*|licenses/*|vendor/*|*/testdata/*) continue ;;
  esac
  if head -n 20 "${f}" | grep -qE 'Code generated .* DO NOT EDIT'; then
    continue
  fi
  checked=$((checked + 1))
  if ! grep -q "Kruise Authors" "${f}"; then
    echo "::error file=${f}::missing Kruise copyright notice (new files need the full 'Copyright 2026 The Kruise Authors' header; modified Istio files need a '// Modifications Copyright 2026 The Kruise Authors' line)"
    ec=1
  fi
  if ! grep -q "Apache License, Version 2" "${f}"; then
    echo "::error file=${f}::missing Apache License 2.0 header"
    ec=1
  fi
done

if [[ ${ec} -ne 0 ]]; then
  echo ""
  echo "Copyright check FAILED. To fix: ./bin/fix_copyright_kruise.sh ${BASE}"
  exit 1
fi
echo "Copyright check passed (${checked} changed Go file(s) verified against ${BASE})."
