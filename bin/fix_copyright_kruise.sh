#!/usr/bin/env bash
# Adds the correct copyright header to Go files added/modified vs a base ref:
#   - file already contains a Copyright + Apache header -> insert a Modifications line
#   - file has no header                               -> prepend the full Kruise banner
# Generated / synced / vendored files are skipped. macOS bash 3.2 compatible.
set -euo pipefail

YEAR="2026"
HOLDER="The Kruise Authors"
MODLINE="// Modifications Copyright ${YEAR} ${HOLDER}"

read -r -d '' BANNER <<EOF || true
// Copyright ${YEAR} ${HOLDER}
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
EOF

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

for f in ${FILES[@]+"${FILES[@]}"}; do
  [[ -f "${f}" ]] || continue
  case "${f}" in
    common/*|licenses/*|vendor/*|*/testdata/*) continue ;;
  esac
  if head -n 20 "${f}" | grep -qE 'Code generated .* DO NOT EDIT'; then
    continue
  fi
  if grep -q "Kruise Authors" "${f}"; then
    continue
  fi
  if grep -q "Copyright" "${f}" && grep -q "Apache License, Version 2" "${f}"; then
    awk -v ml="${MODLINE}" 'BEGIN{done=0} (!done && /Copyright/){print; print ml; done=1; next} {print}' "${f}" > "${f}.kruise.tmp"
    mv "${f}.kruise.tmp" "${f}"
    echo "Added modification notice: ${f}"
  elif head -n 1 "${f}" | grep -q '^//go:build'; then
    awk -v banner="${BANNER}" 'BEGIN{ins=0} NR==1{print; next} (!ins && /^package /){print banner; print ""; print; ins=1; next} {print}' "${f}" > "${f}.kruise.tmp"
    mv "${f}.kruise.tmp" "${f}"
    echo "Added Kruise banner (build-tagged): ${f}"
  else
    printf '%s\n\n%s\n' "${BANNER}" "$(cat "${f}")" > "${f}.kruise.tmp"
    mv "${f}.kruise.tmp" "${f}"
    echo "Added Kruise banner: ${f}"
  fi
done
