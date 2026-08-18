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

use agentio_sni_policy_wasm::config::RouteConfig;

#[test]
fn parses_control_plane_cluster_mapping() {
    let config = RouteConfig::from_json(
        br#"{
            "termination_cluster": "termination-from-control-plane",
            "passthrough_cluster": "passthrough-from-control-plane"
        }"#,
    )
    .unwrap();

    assert_eq!(
        config.termination_cluster(),
        "termination-from-control-plane"
    );
    assert_eq!(
        config.passthrough_cluster(),
        "passthrough-from-control-plane"
    );
}

#[test]
fn rejects_missing_or_empty_cluster_mapping() {
    for input in [
        br#"{}"#.as_slice(),
        br#"{"termination_cluster":"termination"}"#.as_slice(),
        br#"{"termination_cluster":"","passthrough_cluster":"passthrough"}"#.as_slice(),
        br#"{"termination_cluster":"termination","passthrough_cluster":"  "}"#.as_slice(),
    ] {
        assert!(RouteConfig::from_json(input).is_err());
    }
}
