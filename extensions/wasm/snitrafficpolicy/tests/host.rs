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

use agentio_sni_policy_wasm::filter_state::{LifeSpan, SetEnvoyFilterStateArguments};
use agentio_sni_policy_wasm::host::{
    POLICY_SNAPSHOT_PROPERTY, REQUESTED_SERVER_NAME_PROPERTY, encode_cluster_state,
    requested_server_name_from_property,
};
use prost::Message;

#[test]
fn constants_pin_the_trusted_properties() {
    assert_eq!(
        REQUESTED_SERVER_NAME_PROPERTY,
        ["connection", "requested_server_name"]
    );
    assert_eq!(
        POLICY_SNAPSHOT_PROPERTY,
        ["filter_state", "agentio.bound_policies"]
    );
}

#[test]
fn encodes_envoy_tcp_proxy_cluster_filter_state() {
    let bytes = encode_cluster_state("PassthroughCluster");
    let arguments = SetEnvoyFilterStateArguments::decode(bytes.as_slice()).unwrap();
    assert_eq!(arguments.path, "envoy.tcp_proxy.cluster");
    assert_eq!(arguments.value, "PassthroughCluster");
    assert_eq!(arguments.span, LifeSpan::FilterChain as i32);
}

#[test]
fn decodes_requested_server_name_property() {
    assert_eq!(requested_server_name_from_property(None).unwrap(), None);
    assert_eq!(
        requested_server_name_from_property(Some(b"")).unwrap(),
        None
    );
    assert_eq!(
        requested_server_name_from_property(Some(b"api.example.com")).unwrap(),
        Some("api.example.com".to_string())
    );
    assert!(requested_server_name_from_property(Some(&[0xff])).is_err());
}
