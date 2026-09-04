#!/usr/bin/env bash
# Verifies every Go or protobuf source file added or modified relative to a base
# ref carries the appropriate Agentio copyright notice and an Apache 2.0
# license header.
# Istio-derived infrastructure keeps the upstream notice and adds a Kruise
# modification notice. Runs in CI on PRs and pushes. macOS bash 3.2 compatible.
set -euo pipefail

YEAR="2026"
HOLDER="The Kruise Authors"
COPYLINE="// Copyright ${YEAR} ${HOLDER}"
MODLINE="// Modifications Copyright ${YEAR} ${HOLDER}"
ISTIOLINE="// Copyright Istio Authors"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DERIVED_FILE_LIST="${SCRIPT_DIR}/istio-derived-files.txt"

BASE="${1:-${BASE_REF:-}}"
if [[ -z "${BASE}" ]]; then
  if git rev-parse --verify -q origin/main >/dev/null 2>&1; then
    BASE="$(git merge-base origin/main HEAD)"
  elif git rev-parse --verify -q origin/master >/dev/null 2>&1; then
    BASE="$(git merge-base origin/master HEAD)"
  else
    BASE="HEAD~1"
  fi
fi

FILES=()
while IFS= read -r line; do
  [[ -n "${line}" ]] && FILES+=("${line}")
done < <(
  {
    git diff --name-only --diff-filter=ACM "${BASE}" -- '*.go' '*.proto' || true
    git ls-files --others --exclude-standard -- '*.go' '*.proto' || true
  } | sort -u
)

ec=0
checked=0

is_istio_derived() {
  grep -Fxq -- "$1" "${DERIVED_FILE_LIST}"
}

if [[ ! -f NOTICE ]] || ! grep -qF 'Portions of this product are derived from Istio' NOTICE; then
  echo "::error file=NOTICE::missing Istio-derived source attribution"
  ec=1
fi

if [[ ! -f "${DERIVED_FILE_LIST}" ]]; then
  echo "::error file=bin/istio-derived-files.txt::missing Istio-derived file manifest"
  exit 1
fi

previous=""
while IFS= read -r f; do
  [[ -z "${f}" || "${f}" == \#* ]] && continue
  if [[ ! -f "${f}" ]]; then
    echo "::error file=bin/istio-derived-files.txt::listed file does not exist: ${f}"
    ec=1
  fi
  if [[ -n "${previous}" && "${previous}" > "${f}" ]]; then
    echo "::error file=bin/istio-derived-files.txt::entries must be sorted: ${f}"
    ec=1
  fi
  previous="${f}"
done < "${DERIVED_FILE_LIST}"

for f in ${FILES[@]+"${FILES[@]}"}; do
  [[ -f "${f}" ]] || continue
  case "${f}" in
    common/*|licenses/*|vendor/*|*/testdata/*) continue ;;
  esac
  if head -n 20 "${f}" | grep -qE 'Code generated .* DO NOT EDIT'; then
    continue
  fi
  checked=$((checked + 1))
  if is_istio_derived "${f}"; then
    istio_count="$(grep -cFx "${ISTIOLINE}" "${f}" || true)"
    modification_count="$(grep -cFx "${MODLINE}" "${f}" || true)"
    if [[ "${istio_count}" -ne 1 || "${modification_count}" -ne 1 ]]; then
      echo "::error file=${f}::Istio-derived files require exactly one '${ISTIOLINE}' and one '${MODLINE}'"
      ec=1
    fi
  else
    copyright_count="$(grep -cFx "${COPYLINE}" "${f}" || true)"
    if [[ "${copyright_count}" -ne 1 ]]; then
      echo "::error file=${f}::expected exactly one '${COPYLINE}' notice, found ${copyright_count}"
      ec=1
    fi
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
echo "Copyright check passed (${checked} changed source file(s) verified against ${BASE})."
