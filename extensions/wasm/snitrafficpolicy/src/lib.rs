// Copyright 2026 The Kruise Authors
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

pub mod abi {
    include!(concat!(
        env!("OUT_DIR"),
        "/kruise.networking.gateway_policy.v1.rs"
    ));
}

pub mod filter_state {
    include!(concat!(
        env!("OUT_DIR"),
        "/envoy.source.extensions.common.wasm.rs"
    ));
}

pub mod config;
pub mod host;
pub mod matcher;
pub mod normalize;
pub mod policy;
pub mod stream;

#[cfg(target_arch = "wasm32")]
proxy_wasm::main! {{
    host::register();
}}
