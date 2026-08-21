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

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantConfig {
    pub version: String,
    pub config_source_namespace: String,
    pub http_gateway: GatewayRef,
    pub udp_gateway: GatewayRef,
    pub udp_target: UdpTarget,
    pub tenants: Vec<Tenant>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayRef {
    pub namespace: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tenant {
    pub id: String,
    pub generation: u32,
    pub mark: u32,
    pub workloads: Vec<WorkloadBinding>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadBinding {
    pub namespace: String,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginConfig {
    pub udp_path: String,
    pub bindings: Vec<PluginBinding>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginBinding {
    pub namespace: String,
    pub name: String,
    pub route_key: String,
}

#[derive(Clone, Debug)]
pub struct ValidatedConfig {
    pub config_source_namespace: String,
    pub http_gateway: GatewayRef,
    pub udp_gateway: GatewayRef,
    pub udp_target: UdpTarget,
    pub tenants: Vec<Tenant>,
    plugin_config: PluginConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError(String);

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ConfigError {}

impl Tenant {
    pub fn route_key(&self) -> String {
        format!("{}-g{}", self.id, self.generation)
    }

    pub fn http_cluster_name(&self) -> String {
        format!("poc_http_{}_g{}_v4", self.id, self.generation)
    }

    pub fn udp_cluster_name(&self) -> String {
        format!("poc_udp_{}_g{}", self.id, self.generation)
    }
}

impl PluginConfig {
    pub fn route_for(&self, namespace: &str, name: &str) -> Option<&str> {
        self.bindings
            .iter()
            .find(|binding| binding.namespace == namespace && binding.name == name)
            .map(|binding| binding.route_key.as_str())
    }
}

impl ValidatedConfig {
    pub fn tenant_for(&self, namespace: &str, name: &str) -> Option<&Tenant> {
        self.tenants.iter().find(|tenant| {
            tenant
                .workloads
                .iter()
                .any(|workload| workload.namespace == namespace && workload.name == name)
        })
    }

    pub fn plugin_config(&self) -> &PluginConfig {
        &self.plugin_config
    }
}

pub fn parse_and_validate_yaml(input: &str) -> Result<ValidatedConfig, ConfigError> {
    let config: TenantConfig = serde_yaml::from_str(input)
        .map_err(|error| ConfigError::new(format!("invalid tenant configuration: {error}")))?;
    validate(config)
}

fn validate(config: TenantConfig) -> Result<ValidatedConfig, ConfigError> {
    if config.version != "v1" {
        return Err(ConfigError::new(format!(
            "unsupported version {}",
            config.version
        )));
    }
    validate_non_empty("configSourceNamespace", &config.config_source_namespace)?;
    validate_gateway("httpGateway", &config.http_gateway)?;
    validate_gateway("udpGateway", &config.udp_gateway)?;
    validate_non_empty("udpTarget.host", &config.udp_target.host)?;
    if config.udp_target.port == 0 {
        return Err(ConfigError::new("udpTarget.port must be greater than zero"));
    }
    if config.tenants.is_empty() {
        return Err(ConfigError::new("at least one tenant is required"));
    }

    let mut tenant_ids = HashSet::new();
    let mut marks = HashSet::new();
    let mut workloads = HashSet::new();
    let mut bindings = Vec::new();

    for tenant in &config.tenants {
        if !valid_tenant_id(&tenant.id) {
            return Err(ConfigError::new(format!(
                "invalid tenant id {:?}",
                tenant.id
            )));
        }
        if !tenant_ids.insert(tenant.id.clone()) {
            return Err(ConfigError::new(format!(
                "duplicate tenant id {}",
                tenant.id
            )));
        }
        if tenant.generation == 0 {
            return Err(ConfigError::new(format!(
                "tenant {} generation must be greater than zero",
                tenant.id
            )));
        }
        if tenant.mark == 0 {
            return Err(ConfigError::new(format!(
                "tenant {} mark must be greater than zero",
                tenant.id
            )));
        }
        if !marks.insert(tenant.mark) {
            return Err(ConfigError::new(format!("duplicate mark {}", tenant.mark)));
        }
        if tenant.workloads.is_empty() {
            return Err(ConfigError::new(format!(
                "tenant {} must bind at least one workload",
                tenant.id
            )));
        }

        let route_key = tenant.route_key();
        for workload in &tenant.workloads {
            if workload.namespace.trim().is_empty() || workload.name.trim().is_empty() {
                return Err(ConfigError::new(
                    "workload namespace and name must be non-empty",
                ));
            }
            let key = (workload.namespace.clone(), workload.name.clone());
            if !workloads.insert(key) {
                return Err(ConfigError::new(format!(
                    "workload {}/{} is bound more than once",
                    workload.namespace, workload.name
                )));
            }
            bindings.push(PluginBinding {
                namespace: workload.namespace.clone(),
                name: workload.name.clone(),
                route_key: route_key.clone(),
            });
        }
    }

    let udp_path = format!(
        "/.well-known/masque/udp/{}/{}/",
        config.udp_target.host, config.udp_target.port
    );
    Ok(ValidatedConfig {
        config_source_namespace: config.config_source_namespace,
        http_gateway: config.http_gateway,
        udp_gateway: config.udp_gateway,
        udp_target: config.udp_target,
        tenants: config.tenants,
        plugin_config: PluginConfig { udp_path, bindings },
    })
}

fn validate_gateway(field: &str, gateway: &GatewayRef) -> Result<(), ConfigError> {
    validate_non_empty(&format!("{field}.namespace"), &gateway.namespace)?;
    validate_non_empty(&format!("{field}.name"), &gateway.name)
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::new(format!("{field} must be non-empty")));
    }
    Ok(())
}

fn valid_tenant_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 32 {
        return false;
    }
    let bytes = id.as_bytes();
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    alphanumeric(bytes[0])
        && alphanumeric(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .all(|byte| alphanumeric(*byte) || *byte == b'-')
}
