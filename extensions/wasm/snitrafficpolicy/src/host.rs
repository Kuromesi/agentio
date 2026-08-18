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

use prost::Message;

use crate::filter_state::{LifeSpan, SetEnvoyFilterStateArguments};

pub const REQUESTED_SERVER_NAME_PROPERTY: [&str; 2] = ["connection", "requested_server_name"];
pub const POLICY_SNAPSHOT_PROPERTY: [&str; 2] = ["filter_state", "agentio.bound_policies"];
#[cfg(target_arch = "wasm32")]
const SET_FILTER_STATE_FOREIGN_FUNCTION: &str = "set_envoy_filter_state";
const TCP_PROXY_CLUSTER_PATH: &str = "envoy.tcp_proxy.cluster";

pub fn requested_server_name_from_property(value: Option<&[u8]>) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = std::str::from_utf8(value).map_err(|error| error.to_string())?;
    if value.is_empty() {
        return Ok(None);
    }
    Ok(Some(value.into()))
}

pub fn encode_cluster_state(cluster: &str) -> Vec<u8> {
    SetEnvoyFilterStateArguments {
        path: TCP_PROXY_CLUSTER_PATH.into(),
        value: cluster.into(),
        span: LifeSpan::FilterChain as i32,
    }
    .encode_to_vec()
}

#[cfg(target_arch = "wasm32")]
mod runtime {
    use proxy_wasm::hostcalls;
    use proxy_wasm::traits::{Context, RootContext, StreamContext};
    use proxy_wasm::types::{Action, ContextType, LogLevel, MetricType, Status};

    use super::{
        POLICY_SNAPSHOT_PROPERTY, REQUESTED_SERVER_NAME_PROPERTY,
        SET_FILTER_STATE_FOREIGN_FUNCTION, encode_cluster_state,
        requested_server_name_from_property,
    };
    use crate::config::RouteConfig;
    use crate::stream::{EngineAction, Host, HostError, StreamEngine, StreamEvent};

    #[derive(Clone)]
    struct Metrics {
        policy_snapshot_failed: u32,
        policy_snapshot_ready: u32,
        policy_snapshot_binding_miss: u32,
        policy_snapshot_pending: u32,
        policy_snapshot_not_ready: u32,
        requested_server_name_failed: u32,
        termination: u32,
        passthrough: u32,
        deny: u32,
        set_cluster_failed: u32,
        close_failed: u32,
    }

    impl Metrics {
        fn define() -> Result<Self, Status> {
            let counter = |name| hostcalls::define_metric(MetricType::Counter, name);
            Ok(Self {
                policy_snapshot_failed: counter("agentio_sni_policy_snapshot_failed_total")?,
                policy_snapshot_ready: counter("agentio_sni_policy_snapshot_ready_total")?,
                policy_snapshot_binding_miss: counter(
                    "agentio_sni_policy_snapshot_binding_miss_total",
                )?,
                policy_snapshot_pending: counter(
                    "agentio_sni_policy_snapshot_pending_references_total",
                )?,
                policy_snapshot_not_ready: counter("agentio_sni_policy_snapshot_not_ready_total")?,
                requested_server_name_failed: counter(
                    "agentio_sni_policy_requested_server_name_failed_total",
                )?,
                termination: counter("agentio_sni_policy_decision_tls_termination_total")?,
                passthrough: counter("agentio_sni_policy_decision_passthrough_total")?,
                deny: counter("agentio_sni_policy_decision_deny_total")?,
                set_cluster_failed: counter("agentio_sni_policy_set_cluster_failed_total")?,
                close_failed: counter("agentio_sni_policy_close_failed_total")?,
            })
        }

        fn increment(&self, event: StreamEvent) {
            use crate::abi::{PolicySnapshotStatus, SniAction};
            let id = match event {
                StreamEvent::PolicySnapshotFailed => Some(self.policy_snapshot_failed),
                StreamEvent::PolicySnapshotStatus(PolicySnapshotStatus::Ready) => {
                    Some(self.policy_snapshot_ready)
                }
                StreamEvent::PolicySnapshotStatus(PolicySnapshotStatus::BindingMiss) => {
                    Some(self.policy_snapshot_binding_miss)
                }
                StreamEvent::PolicySnapshotStatus(PolicySnapshotStatus::PendingReferences) => {
                    Some(self.policy_snapshot_pending)
                }
                StreamEvent::PolicySnapshotStatus(PolicySnapshotStatus::NotReady)
                | StreamEvent::PolicySnapshotStatus(PolicySnapshotStatus::Unspecified) => {
                    Some(self.policy_snapshot_not_ready)
                }
                StreamEvent::RequestedServerNameFailed => Some(self.requested_server_name_failed),
                StreamEvent::Decision(SniAction::TlsTermination) => Some(self.termination),
                StreamEvent::Decision(SniAction::Passthrough) => Some(self.passthrough),
                StreamEvent::Decision(SniAction::Deny)
                | StreamEvent::Decision(SniAction::Unspecified) => Some(self.deny),
                StreamEvent::SetClusterFailed => Some(self.set_cluster_failed),
                StreamEvent::CloseFailed => Some(self.close_failed),
                StreamEvent::NoSni => None,
            };
            if let Some(id) = id {
                let _ = hostcalls::increment_metric(id, 1);
            }
        }
    }

    pub(super) fn register() {
        proxy_wasm::set_log_level(LogLevel::Info);
        proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
            Box::new(SniPolicyRoot {
                metrics: None,
                route_config: None,
            })
        });
    }

    struct SniPolicyRoot {
        metrics: Option<Metrics>,
        route_config: Option<RouteConfig>,
    }

    impl Context for SniPolicyRoot {}

    impl RootContext for SniPolicyRoot {
        fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
            let Some(configuration) = self.get_plugin_configuration() else {
                let _ = hostcalls::log(
                    LogLevel::Error,
                    "SNI policy plugin configuration is missing",
                );
                return false;
            };
            let route_config = match RouteConfig::from_json(&configuration) {
                Ok(config) => config,
                Err(error) => {
                    let _ = hostcalls::log(
                        LogLevel::Error,
                        &format!("invalid SNI policy plugin configuration: {error}"),
                    );
                    return false;
                }
            };
            let Some(metrics) = Metrics::define().ok() else {
                return false;
            };
            self.route_config = Some(route_config);
            self.metrics = Some(metrics);
            true
        }

        fn create_stream_context(&self, _context_id: u32) -> Option<Box<dyn StreamContext>> {
            let metrics = self.metrics.clone()?;
            let route_config = self.route_config.clone()?;
            Some(Box::new(SniPolicyStream {
                engine: StreamEngine::new(route_config),
                host: ProxyHost { metrics },
            }))
        }

        fn get_type(&self) -> Option<ContextType> {
            Some(ContextType::StreamContext)
        }
    }

    struct ProxyHost {
        metrics: Metrics,
    }

    impl Host for ProxyHost {
        fn requested_server_name(&mut self) -> Result<Option<String>, HostError> {
            let value = hostcalls::get_property(REQUESTED_SERVER_NAME_PROPERTY.to_vec())
                .map_err(|_| HostError::RequestedServerNameFailed)?;
            requested_server_name_from_property(value.as_deref())
                .map_err(|_| HostError::RequestedServerNameFailed)
        }

        fn policy_snapshot(&mut self) -> Result<Vec<u8>, HostError> {
            hostcalls::get_property(POLICY_SNAPSHOT_PROPERTY.to_vec())
                .map_err(|_| HostError::PolicySnapshotFailed)?
                .ok_or(HostError::PolicySnapshotFailed)
        }

        fn set_cluster(&mut self, cluster: &str) -> Result<(), HostError> {
            let arguments = encode_cluster_state(cluster);
            hostcalls::call_foreign_function(SET_FILTER_STATE_FOREIGN_FUNCTION, Some(&arguments))
                .map(|_| ())
                .map_err(|_| HostError::SetClusterFailed)
        }

        fn close_downstream(&mut self) -> Result<(), HostError> {
            hostcalls::close_downstream().map_err(|_| HostError::CloseFailed)
        }

        fn record(&mut self, event: StreamEvent) {
            self.metrics.increment(event);
        }
    }

    struct SniPolicyStream {
        engine: StreamEngine,
        host: ProxyHost,
    }

    impl Context for SniPolicyStream {}

    impl StreamContext for SniPolicyStream {
        fn on_new_connection(&mut self) -> Action {
            match self.engine.on_new_connection(&mut self.host) {
                EngineAction::Continue => Action::Continue,
                EngineAction::Pause => Action::Pause,
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub fn register() {
    runtime::register();
}
