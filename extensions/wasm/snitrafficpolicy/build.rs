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

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc is available");
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }
    let policy_snapshot_proto = "api/v1/policy_snapshot.proto";
    let filter_state_proto = "proto/set_envoy_filter_state.proto";
    println!("cargo:rerun-if-changed={policy_snapshot_proto}");
    println!("cargo:rerun-if-changed={filter_state_proto}");
    prost_build::compile_protos(
        &[policy_snapshot_proto, filter_state_proto],
        &["api", "proto"],
    )
    .expect("gateway policy FilterState protobuf compiles");
}
