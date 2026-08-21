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

use std::error::Error;
use std::fmt::{Display, Formatter};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use crate::config::{GatewayRef, Tenant, ValidatedConfig};

const INTERNAL_ROUTE_HEADER: &str = "x-agentio-poc-route";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderError(String);

impl Display for RenderError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for RenderError {}

pub fn render_config_map(
    config: &ValidatedConfig,
    wasm_bytes: &[u8],
) -> Result<String, RenderError> {
    if wasm_bytes.is_empty() {
        return Err(RenderError("Wasm module is empty".into()));
    }
    let plugin_json = serde_json::to_string(config.plugin_config())
        .map_err(|error| RenderError(format!("serialize plugin configuration: {error}")))?;
    let wasm_base64 = STANDARD.encode(wasm_bytes);
    let http = http_envoy_filter(config, &wasm_base64, &plugin_json);
    let udp = udp_envoy_filter(config, &wasm_base64, &plugin_json);
    let http_yaml = serde_yaml::to_string(&http)
        .map_err(|error| RenderError(format!("serialize HTTP EnvoyFilter: {error}")))?;
    let udp_yaml = serde_yaml::to_string(&udp)
        .map_err(|error| RenderError(format!("serialize UDP EnvoyFilter: {error}")))?;
    let sources = format!(
        "{}---\n{}",
        http_yaml.trim_start_matches("---\n"),
        udp_yaml.trim_start_matches("---\n")
    );
    let config_map = json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "poc-multi-tenant-egress",
            "namespace": config.config_source_namespace,
            "labels": {
                "manifests.agents.kruise.io/kube-source": "true",
                "app.kubernetes.io/managed-by": "agentio-poc-renderer"
            }
        },
        "data": {"sources": sources}
    });
    serde_yaml::to_string(&config_map)
        .map_err(|error| RenderError(format!("serialize ConfigMap: {error}")))
}

fn http_envoy_filter(config: &ValidatedConfig, wasm_base64: &str, plugin_json: &str) -> Value {
    let mut patches = Vec::new();
    for tenant in &config.tenants {
        patches.push(cluster_patch(http_cluster(tenant)));
    }
    patches.push(wasm_filter_patch(
        json!({
            "context": "SIDECAR_INBOUND",
            "listener": {
                "name": "main_forward",
                "filterChain": {
                    "name": "forward-http",
                    "filter": {
                        "name": "envoy.filters.network.http_connection_manager",
                        "subFilter": {"name": "envoy.filters.http.rbac"}
                    }
                }
            }
        }),
        "INSERT_BEFORE",
        wasm_base64,
        plugin_json,
    ));
    for tenant in &config.tenants {
        patches.push(http_route_patch(tenant));
    }
    envoy_filter("poc-multi-tenant-http", &config.http_gateway, patches)
}

fn udp_envoy_filter(config: &ValidatedConfig, wasm_base64: &str, plugin_json: &str) -> Value {
    let mut patches = Vec::new();
    for tenant in &config.tenants {
        patches.push(cluster_patch(udp_cluster(config, tenant)));
    }
    patches.push(wasm_filter_patch(
        json!({
            "context": "SIDECAR_INBOUND",
            "listener": {
                "name": "connect_terminate",
                "filterChain": {
                    "name": "default",
                    "filter": {
                        "name": "envoy.filters.network.http_connection_manager",
                        "subFilter": {"name": "connect_authority"}
                    }
                }
            }
        }),
        "INSERT_AFTER",
        wasm_base64,
        plugin_json,
    ));
    for tenant in &config.tenants {
        patches.push(udp_route_patch(config, tenant));
    }
    envoy_filter("poc-multi-tenant-udp", &config.udp_gateway, patches)
}

fn envoy_filter(name: &str, gateway: &GatewayRef, patches: Vec<Value>) -> Value {
    json!({
        "apiVersion": "networking.istio.io/v1alpha3",
        "kind": "EnvoyFilter",
        "metadata": {"name": name, "namespace": gateway.namespace},
        "spec": {
            "targetRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "name": gateway.name
            }],
            "configPatches": patches
        }
    })
}

fn cluster_patch(cluster: Value) -> Value {
    json!({
        "applyTo": "CLUSTER",
        "match": {"context": "SIDECAR_INBOUND"},
        "patch": {"operation": "ADD", "value": cluster}
    })
}

fn socket_bind_config(mark: u32) -> Value {
    json!({
        "socket_options": [{
            "description": "tenant SO_MARK",
            "level": 1,
            "name": 36,
            "int_value": mark,
            "state": "STATE_PREBIND"
        }]
    })
}

fn http_cluster(tenant: &Tenant) -> Value {
    json!({
        "name": tenant.http_cluster_name(),
        "connect_timeout": "10s",
        "lb_policy": "CLUSTER_PROVIDED",
        "circuit_breakers": {
            "thresholds": [{
                "max_connections": 4294967295_u64,
                "max_pending_requests": 4294967295_u64,
                "max_requests": 4294967295_u64,
                "max_retries": 4294967295_u64
            }]
        },
        "upstream_bind_config": socket_bind_config(tenant.mark),
        "transport_socket": {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                "common_tls_context": {
                    "tls_params": {"tls_minimum_protocol_version": "TLSv1_2"},
                    "validation_context": {
                        "trusted_ca": {"filename": "/etc/ssl/certs/ca-certificates.crt"}
                    },
                    "alpn_protocols": ["h2", "http/1.1"]
                }
            }
        },
        "typed_extension_protocol_options": {
            "envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
                "@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
                "common_http_protocol_options": {"idle_timeout": "300s"},
                "upstream_http_protocol_options": {
                    "auto_sni": true,
                    "auto_san_validation": true
                },
                "auto_config": {
                    "http_protocol_options": {},
                    "http2_protocol_options": {}
                }
            }
        },
        "cluster_type": {
            "name": "envoy.clusters.dynamic_forward_proxy",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig",
                "dns_cache_config": {
                    "name": "sandbox_dns_cache_v4",
                    "dns_lookup_family": "V4_ONLY"
                }
            }
        }
    })
}

fn udp_cluster(config: &ValidatedConfig, tenant: &Tenant) -> Value {
    let name = tenant.udp_cluster_name();
    json!({
        "name": name,
        "connect_timeout": "5s",
        "type": "STRICT_DNS",
        "dns_lookup_family": "V4_ONLY",
        "lb_policy": "ROUND_ROBIN",
        "upstream_bind_config": socket_bind_config(tenant.mark),
        "load_assignment": {
            "cluster_name": name,
            "endpoints": [{
                "lb_endpoints": [{
                    "endpoint": {
                        "address": {
                            "socket_address": {
                                "address": config.udp_target.host,
                                "port_value": config.udp_target.port
                            }
                        }
                    }
                }]
            }]
        }
    })
}

fn wasm_filter_patch(
    filter_match: Value,
    operation: &str,
    wasm_base64: &str,
    plugin_json: &str,
) -> Value {
    json!({
        "applyTo": "HTTP_FILTER",
        "match": filter_match,
        "patch": {
            "operation": operation,
            "value": {
                "name": "poc_tenant_router",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm",
                    "config": {
                        "name": "poc_tenant_router",
                        "root_id": "poc_tenant_router",
                        "fail_open": false,
                        "configuration": {
                            "@type": "type.googleapis.com/google.protobuf.StringValue",
                            "value": plugin_json
                        },
                        "vm_config": {
                            "vm_id": "poc_tenant_router",
                            "runtime": "envoy.wasm.runtime.v8",
                            "code": {"local": {"inline_bytes": wasm_base64}}
                        }
                    }
                }
            }
        }
    })
}

fn http_route_patch(tenant: &Tenant) -> Value {
    let route_key = tenant.route_key();
    json!({
        "applyTo": "HTTP_ROUTE",
        "match": {
            "context": "SIDECAR_INBOUND",
            "routeConfiguration": {
                "name": "tls_connect_originate",
                "vhost": {
                    "name": "inbound|http|0",
                    "route": {"name": "default", "action": "ROUTE"}
                }
            }
        },
        "patch": {
            "operation": "INSERT_BEFORE",
            "value": {
                "name": format!("poc-http-{route_key}"),
                "match": {
                    "prefix": "/",
                    "headers": [{
                        "name": INTERNAL_ROUTE_HEADER,
                        "string_match": {"exact": route_key}
                    }]
                },
                "route": {"cluster": tenant.http_cluster_name(), "timeout": "0s"},
                "request_headers_to_remove": [INTERNAL_ROUTE_HEADER],
                "response_headers_to_add": [{
                    "header": {"key": "x-agentio-poc-cluster", "value": tenant.id},
                    "append_action": "OVERWRITE_IF_EXISTS_OR_ADD"
                }]
            }
        }
    })
}

fn udp_route_patch(config: &ValidatedConfig, tenant: &Tenant) -> Value {
    let route_key = tenant.route_key();
    let original_route = format!(
        "connect-udp:{}:{}",
        config.udp_target.host, config.udp_target.port
    );
    json!({
        "applyTo": "HTTP_ROUTE",
        "match": {
            "context": "SIDECAR_INBOUND",
            "routeConfiguration": {
                "name": "default",
                "vhost": {
                    "name": "default",
                    "route": {"name": original_route, "action": "ROUTE"}
                }
            }
        },
        "patch": {
            "operation": "INSERT_BEFORE",
            "value": {
                "name": format!("poc-connect-udp-{route_key}"),
                "match": {
                    "path": config.plugin_config().udp_path,
                    "headers": [
                        {"name": INTERNAL_ROUTE_HEADER, "string_match": {"exact": route_key}},
                        {"name": ":method", "string_match": {"exact": "GET"}},
                        {"name": "upgrade", "string_match": {"exact": "connect-udp"}},
                        {"name": "capsule-protocol", "string_match": {"exact": "?1"}}
                    ]
                },
                "route": {
                    "cluster": tenant.udp_cluster_name(),
                    "timeout": "0s",
                    "upgrade_configs": [{
                        "upgrade_type": "connect-udp",
                        "connect_config": {}
                    }]
                },
                "request_headers_to_remove": [INTERNAL_ROUTE_HEADER]
            }
        }
    })
}
