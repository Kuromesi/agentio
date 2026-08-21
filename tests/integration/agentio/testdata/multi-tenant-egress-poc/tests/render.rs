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
use agentio_multi_tenant_egress_poc::render::render_config_map;
use serde::Deserialize;
use serde_json::{json, Value};

const CONFIG: &str = r#"
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
  - namespace: udp-hbone-poc
    name: udp-client-a
- id: tenant-b
  generation: 2
  mark: 40962
  workloads:
  - namespace: udp-hbone-poc
    name: udp-client-b
"#;

#[test]
fn renders_two_targeted_envoy_filters_with_the_same_plugin_configuration() {
    let config = parse_and_validate_yaml(CONFIG).expect("valid config");
    let output = render_config_map(&config, &[0, 1, 2, 3]).expect("render config map");
    let outer: Value = serde_yaml::from_str(&output).expect("parse outer ConfigMap");

    assert_eq!(outer["kind"], "ConfigMap");
    assert_eq!(outer["metadata"]["name"], "poc-multi-tenant-egress");
    assert_eq!(outer["metadata"]["namespace"], "sandbox-traffic-system");
    assert_eq!(
        outer["metadata"]["labels"]["manifests.agents.kruise.io/kube-source"],
        "true"
    );

    let resources = embedded_resources(&outer);
    assert_eq!(resources.len(), 2);
    let http = resource_named(&resources, "poc-multi-tenant-http");
    let udp = resource_named(&resources, "poc-multi-tenant-udp");
    assert_eq!(http["metadata"]["namespace"], "sandbox-traffic-system");
    assert_eq!(udp["metadata"]["namespace"], "udp-hbone-poc");
    assert_eq!(http["spec"]["targetRefs"][0]["name"], "egress-gateway");
    assert_eq!(udp["spec"]["targetRefs"][0]["name"], "waypoint");

    let expected_plugin = json!({
        "udpPath": "/.well-known/masque/udp/udp-echo.udp-hbone-poc.svc.cluster.local/9000/",
        "bindings": [
            {"namespace": "udp-hbone-poc", "name": "udp-client-a", "routeKey": "tenant-a-g1"},
            {"namespace": "udp-hbone-poc", "name": "udp-client-b", "routeKey": "tenant-b-g2"}
        ]
    });
    for resource in [http, udp] {
        let patch = patches(resource)
            .iter()
            .find(|patch| patch["applyTo"] == "HTTP_FILTER")
            .expect("Wasm HTTP filter patch");
        let typed = &patch["patch"]["value"]["typed_config"];
        assert_eq!(
            typed["config"]["vm_config"]["code"]["local"]["inline_bytes"],
            "AAECAw=="
        );
        let plugin: Value = serde_json::from_str(
            typed["config"]["configuration"]["value"]
                .as_str()
                .expect("plugin config string"),
        )
        .expect("parse plugin config");
        assert_eq!(plugin, expected_plugin);
    }
}

#[test]
fn renders_independent_http_and_udp_clusters_with_tenant_marks() {
    let config = parse_and_validate_yaml(CONFIG).expect("valid config");
    let output = render_config_map(&config, &[0, 1, 2, 3]).expect("render config map");
    let outer: Value = serde_yaml::from_str(&output).expect("parse outer ConfigMap");
    let resources = embedded_resources(&outer);
    let http = resource_named(&resources, "poc-multi-tenant-http");
    let udp = resource_named(&resources, "poc-multi-tenant-udp");

    for (resource, expected) in [
        (
            http,
            vec![
                ("poc_http_tenant-a_g1_v4", 40961),
                ("poc_http_tenant-b_g2_v4", 40962),
            ],
        ),
        (
            udp,
            vec![
                ("poc_udp_tenant-a_g1", 40961),
                ("poc_udp_tenant-b_g2", 40962),
            ],
        ),
    ] {
        for (name, mark) in expected {
            let cluster = patches(resource)
                .iter()
                .find(|patch| {
                    patch["applyTo"] == "CLUSTER" && patch["patch"]["value"]["name"] == name
                })
                .unwrap_or_else(|| panic!("missing cluster {name}"));
            let option = &cluster["patch"]["value"]["upstream_bind_config"]["socket_options"][0];
            assert_eq!(option["level"], 1);
            assert_eq!(option["name"], 36);
            assert_eq!(option["int_value"], mark);
            assert_eq!(option["state"], "STATE_PREBIND");
        }
    }
}

#[test]
fn renders_route_recalculation_before_http_rbac_and_after_connect_authority() {
    let config = parse_and_validate_yaml(CONFIG).expect("valid config");
    let output = render_config_map(&config, &[0, 1, 2, 3]).expect("render config map");
    let outer: Value = serde_yaml::from_str(&output).expect("parse outer ConfigMap");
    let resources = embedded_resources(&outer);
    let http = resource_named(&resources, "poc-multi-tenant-http");
    let udp = resource_named(&resources, "poc-multi-tenant-udp");

    let http_filter = patches(http)
        .iter()
        .find(|patch| patch["applyTo"] == "HTTP_FILTER")
        .expect("HTTP Wasm patch");
    assert_eq!(http_filter["patch"]["operation"], "INSERT_BEFORE");
    assert_eq!(
        http_filter["match"]["listener"]["filterChain"]["filter"]["subFilter"]["name"],
        "envoy.filters.http.rbac"
    );

    let udp_filter = patches(udp)
        .iter()
        .find(|patch| patch["applyTo"] == "HTTP_FILTER")
        .expect("UDP Wasm patch");
    assert_eq!(udp_filter["patch"]["operation"], "INSERT_AFTER");
    assert_eq!(udp_filter["match"]["listener"]["name"], "connect_terminate");
    assert_eq!(
        udp_filter["match"]["listener"]["filterChain"]["filter"]["subFilter"]["name"],
        "connect_authority"
    );
}

#[test]
fn renders_exact_tenant_http_and_connect_udp_routes() {
    let config = parse_and_validate_yaml(CONFIG).expect("valid config");
    let output = render_config_map(&config, &[0, 1, 2, 3]).expect("render config map");
    let outer: Value = serde_yaml::from_str(&output).expect("parse outer ConfigMap");
    let resources = embedded_resources(&outer);
    let http = resource_named(&resources, "poc-multi-tenant-http");
    let udp = resource_named(&resources, "poc-multi-tenant-udp");

    let http_route = route_named(http, "poc-http-tenant-a-g1");
    assert_eq!(http_route["route"]["cluster"], "poc_http_tenant-a_g1_v4");
    assert_eq!(
        http_route["match"]["headers"][0]["string_match"]["exact"],
        "tenant-a-g1"
    );
    assert_eq!(
        http_route["request_headers_to_remove"][0],
        "x-agentio-poc-route"
    );

    let udp_route = route_named(udp, "poc-connect-udp-tenant-b-g2");
    assert_eq!(
        udp_route["match"]["path"],
        "/.well-known/masque/udp/udp-echo.udp-hbone-poc.svc.cluster.local/9000/"
    );
    assert_eq!(udp_route["route"]["cluster"], "poc_udp_tenant-b_g2");
    assert_eq!(
        udp_route["route"]["upgrade_configs"][0]["upgrade_type"],
        "connect-udp"
    );
    assert!(udp_route["match"]["headers"]
        .as_array()
        .expect("route headers")
        .iter()
        .any(|header| {
            header["name"] == "x-agentio-poc-route"
                && header["string_match"]["exact"] == "tenant-b-g2"
        }));
    for (name, value) in [
        (":method", "GET"),
        ("upgrade", "connect-udp"),
        ("capsule-protocol", "?1"),
    ] {
        assert!(
            udp_route["match"]["headers"]
                .as_array()
                .expect("route headers")
                .iter()
                .any(|header| {
                    header["name"] == name && header["string_match"]["exact"] == value
                }),
            "missing header match {name}={value}"
        );
    }
}

fn embedded_resources(config_map: &Value) -> Vec<Value> {
    let sources = config_map["data"]["sources"]
        .as_str()
        .expect("embedded sources string");
    serde_yaml::Deserializer::from_str(sources)
        .map(|document| Value::deserialize(document).expect("parse embedded resource"))
        .collect()
}

fn resource_named<'a>(resources: &'a [Value], name: &str) -> &'a Value {
    resources
        .iter()
        .find(|resource| resource["metadata"]["name"] == name)
        .unwrap_or_else(|| panic!("missing resource {name}"))
}

fn patches(resource: &Value) -> &Vec<Value> {
    resource["spec"]["configPatches"]
        .as_array()
        .expect("config patches")
}

fn route_named<'a>(resource: &'a Value, name: &str) -> &'a Value {
    &patches(resource)
        .iter()
        .find(|patch| patch["applyTo"] == "HTTP_ROUTE" && patch["patch"]["value"]["name"] == name)
        .unwrap_or_else(|| panic!("missing route {name}"))["patch"]["value"]
}
