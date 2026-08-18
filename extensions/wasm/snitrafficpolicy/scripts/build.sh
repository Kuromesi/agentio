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

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate_dir="$(cd "${script_dir}/.." && pwd)"
target="wasm32-wasip1"

command -v cargo >/dev/null 2>&1 || {
  echo "cargo is required to build the SNI policy Wasm module" >&2
  exit 1
}
command -v rustup >/dev/null 2>&1 || {
  echo "rustup is required to install the ${target} target" >&2
  exit 1
}

rustup target add "${target}"
cargo fmt --manifest-path "${crate_dir}/Cargo.toml" -- --check
cargo clippy --locked --manifest-path "${crate_dir}/Cargo.toml" --all-targets -- -D warnings
cargo test --locked --manifest-path "${crate_dir}/Cargo.toml"
cargo build --locked --release --target "${target}" --manifest-path "${crate_dir}/Cargo.toml"

artifact="${crate_dir}/target/${target}/release/agentio_sni_policy_wasm.wasm"
if [[ ! -s "${artifact}" ]]; then
  echo "Wasm artifact was not produced: ${artifact}" >&2
  exit 1
fi
if [[ -n "${AGENTIO_WASM_OUTPUT:-}" ]]; then
  mkdir -p "$(dirname "${AGENTIO_WASM_OUTPUT}")"
  cp "${artifact}" "${AGENTIO_WASM_OUTPUT}"
  artifact="${AGENTIO_WASM_OUTPUT}"
fi
printf '%s\n' "${artifact}"
