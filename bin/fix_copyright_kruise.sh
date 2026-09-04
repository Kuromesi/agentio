#!/usr/bin/env bash
# Adds or normalizes the copyright header in Go or protobuf source files
# added/modified vs a base ref:
#   - Agentio-original files keep one Kruise notice
#   - Istio-derived infrastructure keeps the Istio notice plus a Kruise
#     modification notice
#   - files without a header receive the appropriate complete banner
# Generated / synced / vendored files are skipped. macOS bash 3.2 compatible.
set -euo pipefail

YEAR="2026"
HOLDER="The Kruise Authors"
COPYLINE="// Copyright ${YEAR} ${HOLDER}"
MODLINE="// Modifications Copyright ${YEAR} ${HOLDER}"
ISTIOLINE="// Copyright Istio Authors"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DERIVED_FILE_LIST="${SCRIPT_DIR}/istio-derived-files.txt"

if [[ ! -f "${DERIVED_FILE_LIST}" ]]; then
  echo "missing Istio-derived file manifest: ${DERIVED_FILE_LIST}" >&2
  exit 1
fi

is_istio_derived() {
  grep -Fxq -- "$1" "${DERIVED_FILE_LIST}"
}

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

for f in ${FILES[@]+"${FILES[@]}"}; do
  [[ -f "${f}" ]] || continue
  case "${f}" in
    common/*|licenses/*|vendor/*|*/testdata/*) continue ;;
  esac
  if head -n 20 "${f}" | grep -qE 'Code generated .* DO NOT EDIT'; then
    continue
  fi
  style="kruise"
  if is_istio_derived "${f}"; then
    style="istio"
  fi
  if grep -qE '^// (Modifications )?Copyright ' "${f}" && grep -q "Apache License, Version 2" "${f}"; then
    awk -v style="${style}" -v copyline="${COPYLINE}" -v istio="${ISTIOLINE}" -v modification="${MODLINE}" '
      BEGIN { seen=0 }
      /^\/\/ (Modifications )?Copyright / {
        if (!seen) {
          if (style == "istio") {
            print istio
            print modification
          } else {
            print copyline
          }
          seen=1
        }
        next
      }
      { print }
    ' "${f}" > "${f}.kruise.tmp"
    if cmp -s "${f}" "${f}.kruise.tmp"; then
      rm "${f}.kruise.tmp"
    else
      mv "${f}.kruise.tmp" "${f}"
      echo "Normalized Kruise banner: ${f}"
    fi
  else
    awk -v style="${style}" -v copyline="${COPYLINE}" -v istio="${ISTIOLINE}" -v modification="${MODLINE}" '
      BEGIN {
        if (style == "istio") {
          print istio
          print modification
        } else {
          print copyline
        }
        print "//"
        print "// Licensed under the Apache License, Version 2.0 (the \"License\");"
        print "// you may not use this file except in compliance with the License."
        print "// You may obtain a copy of the License at"
        print "//"
        print "//     http://www.apache.org/licenses/LICENSE-2.0"
        print "//"
        print "// Unless required by applicable law or agreed to in writing, software"
        print "// distributed under the License is distributed on an \"AS IS\" BASIS,"
        print "// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied."
        print "// See the License for the specific language governing permissions and"
        print "// limitations under the License."
        print ""
      }
      { print }
    ' "${f}" > "${f}.kruise.tmp"
    mv "${f}.kruise.tmp" "${f}"
    echo "Added Kruise banner: ${f}"
  fi
done
