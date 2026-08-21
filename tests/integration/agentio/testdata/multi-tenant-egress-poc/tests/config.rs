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

use agentio_multi_tenant_egress_poc::config::parse_and_validate_yaml;
use serde_json::json;

const VALID_CONFIG: &str = r#"
version: v1
configSourceNamespace: sandbox-traffic-system
httpGateway:
  namespace: sandbox-traffic-system
  name: egress-gateway
udpGateway:
  namespace: udp-hbone-poc
  name: waypoint
udpTarget:
  host: udp-echo.udp-hbone-poc.svc.cluster.local
  port: 9000
tenants:
- id: tenant-a
  generation: 1
  mark: 40961
  workloads:
  - namespace: sandbox
    name: client-v1
  - namespace: udp-hbone-poc
    name: udp-client-a
- id: tenant-b
  generation: 2
  mark: 40962
  workloads:
  - namespace: sandbox
    name: server-v1
"#;

#[test]
fn valid_config_maps_exact_workloads_and_derives_generation_names() {
    let config = parse_and_validate_yaml(VALID_CONFIG).expect("valid configuration");

    let tenant_a = config
        .tenant_for("udp-hbone-poc", "udp-client-a")
        .expect("tenant-a binding");
    assert_eq!(tenant_a.route_key(), "tenant-a-g1");
    assert_eq!(tenant_a.http_cluster_name(), "poc_http_tenant-a_g1_v4");
    assert_eq!(tenant_a.udp_cluster_name(), "poc_udp_tenant-a_g1");
    assert_eq!(tenant_a.mark, 40961);

    let tenant_b = config
        .tenant_for("sandbox", "server-v1")
        .expect("tenant-b binding");
    assert_eq!(tenant_b.route_key(), "tenant-b-g2");
    assert!(config.tenant_for("sandbox", "unknown").is_none());
}

#[test]
fn plugin_config_contains_only_runtime_identity_bindings() {
    let config = parse_and_validate_yaml(VALID_CONFIG).expect("valid configuration");
    let actual = serde_json::to_value(config.plugin_config()).expect("serialize plugin config");

    assert_eq!(
        actual,
        json!({
            "udpPath": "/.well-known/masque/udp/udp-echo.udp-hbone-poc.svc.cluster.local/9000/",
            "bindings": [
                {"namespace": "sandbox", "name": "client-v1", "routeKey": "tenant-a-g1"},
                {"namespace": "udp-hbone-poc", "name": "udp-client-a", "routeKey": "tenant-a-g1"},
                {"namespace": "sandbox", "name": "server-v1", "routeKey": "tenant-b-g2"}
            ]
        })
    );
}

#[test]
fn rejects_duplicate_tenant_ids() {
    let input = VALID_CONFIG.replace("id: tenant-b", "id: tenant-a");
    let error = parse_and_validate_yaml(&input).expect_err("duplicate tenant id must fail");
    assert!(error.to_string().contains("duplicate tenant id tenant-a"));
}

#[test]
fn rejects_duplicate_marks() {
    let input = VALID_CONFIG.replace("mark: 40962", "mark: 40961");
    let error = parse_and_validate_yaml(&input).expect_err("duplicate mark must fail");
    assert!(error.to_string().contains("duplicate mark 40961"));
}

#[test]
fn rejects_workload_bound_to_multiple_tenants() {
    let input = VALID_CONFIG.replace("name: server-v1", "name: client-v1");
    let error = parse_and_validate_yaml(&input).expect_err("duplicate workload must fail");
    assert!(error
        .to_string()
        .contains("workload sandbox/client-v1 is bound more than once"));
}

#[test]
fn rejects_invalid_tenant_ids() {
    for invalid in ["Tenant-A", "tenant_a", "-tenant", "tenant-", ""] {
        let input = if invalid.is_empty() {
            VALID_CONFIG.replace("id: tenant-a", "id: \"\"")
        } else {
            VALID_CONFIG.replace("tenant-a", invalid)
        };
        let error = parse_and_validate_yaml(&input).expect_err("invalid tenant id must fail");
        assert!(
            error.to_string().contains("invalid tenant id"),
            "unexpected error for {invalid:?}: {error}"
        );
    }
}

#[test]
fn rejects_zero_generation_and_mark() {
    let zero_generation = VALID_CONFIG.replacen("generation: 1", "generation: 0", 1);
    let error = parse_and_validate_yaml(&zero_generation).expect_err("zero generation must fail");
    assert!(error
        .to_string()
        .contains("generation must be greater than zero"));

    let zero_mark = VALID_CONFIG.replacen("mark: 40961", "mark: 0", 1);
    let error = parse_and_validate_yaml(&zero_mark).expect_err("zero mark must fail");
    assert!(error.to_string().contains("mark must be greater than zero"));
}

#[test]
fn rejects_empty_tenant_and_workload_sets() {
    let no_tenants = VALID_CONFIG.replace(
        VALID_CONFIG
            .split_once("tenants:")
            .expect("tenants section")
            .1,
        " []\n",
    );
    let error = parse_and_validate_yaml(&no_tenants).expect_err("empty tenants must fail");
    assert!(error
        .to_string()
        .contains("at least one tenant is required"));

    let no_workloads = VALID_CONFIG.replace(
        "  workloads:\n  - namespace: sandbox\n    name: server-v1",
        "  workloads: []",
    );
    let error = parse_and_validate_yaml(&no_workloads).expect_err("empty workloads must fail");
    assert!(error
        .to_string()
        .contains("tenant tenant-b must bind at least one workload"));
}

#[test]
fn rejects_blank_workload_identity_and_unsupported_version() {
    let blank_namespace = VALID_CONFIG.replacen("  - namespace: sandbox", "  - namespace: ' '", 1);
    let error = parse_and_validate_yaml(&blank_namespace).expect_err("blank namespace must fail");
    assert!(error
        .to_string()
        .contains("workload namespace and name must be non-empty"));

    let wrong_version = VALID_CONFIG.replace("version: v1", "version: v2");
    let error = parse_and_validate_yaml(&wrong_version).expect_err("unknown version must fail");
    assert!(error.to_string().contains("unsupported version v2"));
}
