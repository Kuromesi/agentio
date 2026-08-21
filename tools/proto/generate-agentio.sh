#!/usr/bin/env bash

# Copyright 2026 The Kruise Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
EXTENSIONS_PROTO_DIR="pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
SUBSTRATE_PROTO_DIR="pilot/pkg/serviceregistry/kube/controller/agentio/substrateapi"
PROTO_FILES=(
  "${EXTENSIONS_PROTO_DIR}/extensions.proto"
  "${EXTENSIONS_PROTO_DIR}/agentioconfig.proto"
  "${SUBSTRATE_PROTO_DIR}/ateapi.proto"
)

cd "${REPO_ROOT}"

ISTIO_API="$(go mod download -json istio.io/api | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"
if [[ -z "${ISTIO_API}" ]]; then
  echo "failed to locate the istio.io/api module" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# Buf's configured roots do not include the external istio.io/api module.
# Build a descriptor image so Buf can resolve that import without vendoring it.
protoc \
  -I. \
  -I"${ISTIO_API}" \
  -I"${ISTIO_API}/common-protos" \
  --include_imports \
  --include_source_info \
  --descriptor_set_out="${TMP_DIR}/agentio.binpb" \
  "${PROTO_FILES[@]}"

buf generate "${TMP_DIR}/agentio.binpb" \
  --path "${EXTENSIONS_PROTO_DIR}" \
  --template tools/proto/buf.golang-json.yaml

buf generate "${TMP_DIR}/agentio.binpb" \
  --path "${SUBSTRATE_PROTO_DIR}" \
  --template tools/proto/buf.golang.yaml
