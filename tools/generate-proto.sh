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

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
proto_files=(
  api/security/v1/authorization.proto
  api/extensions/v1/extensions.proto
  api/extensions/v1/egresspolicy.proto
  api/extensions/v1/snipolicy.proto
  api/config/v1/agentioconfig.proto
)

cd "$repo_root"

istio_api="$(go mod download -json istio.io/api | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')"
if [[ -z "$istio_api" ]]; then
  echo "failed to locate the istio.io/api module" >&2
  exit 1
fi

temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT

GOBIN="$temporary_dir/bin" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
export PATH="$temporary_dir/bin:$PATH"

protoc \
  -I. \
  -I"$istio_api" \
  -I"$istio_api/common-protos" \
  --include_imports \
  --include_source_info \
  --descriptor_set_out="$temporary_dir/agentio.binpb" \
  "${proto_files[@]}"

buf generate "$temporary_dir/agentio.binpb" \
  --path api/security/v1/authorization.proto \
  --path api/extensions/v1/extensions.proto \
  --path api/extensions/v1/egresspolicy.proto \
  --path api/extensions/v1/snipolicy.proto \
  --path api/config/v1/agentioconfig.proto \
  --template buf.gen.yaml
