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

use crate::abi::{BoundPolicySnapshot, PolicySnapshotStatus, SniAction};
use crate::config::RouteConfig;
use crate::policy::PolicySnapshot;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineAction {
    Continue,
    Pause,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostError {
    RequestedServerNameFailed,
    PolicySnapshotFailed,
    SetClusterFailed,
    CloseFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamEvent {
    RequestedServerNameFailed,
    NoSni,
    PolicySnapshotFailed,
    PolicySnapshotStatus(PolicySnapshotStatus),
    Decision(SniAction),
    SetClusterFailed,
    CloseFailed,
}

pub trait Host {
    fn requested_server_name(&mut self) -> Result<Option<String>, HostError>;
    fn policy_snapshot(&mut self) -> Result<Vec<u8>, HostError>;
    fn set_cluster(&mut self, cluster: &str) -> Result<(), HostError>;
    fn close_downstream(&mut self) -> Result<(), HostError>;
    fn record(&mut self, event: StreamEvent);
}

pub struct StreamEngine {
    route_config: RouteConfig,
}

impl StreamEngine {
    pub fn new(route_config: RouteConfig) -> Self {
        Self { route_config }
    }

    /// Selects the terminal TCP proxy cluster before the TCP proxy filter is
    /// initialized. The TLS inspector has already parsed ClientHello and made
    /// its SNI available as connection.requested_server_name.
    pub fn on_new_connection<H: Host>(&mut self, host: &mut H) -> EngineAction {
        let sni = match host.requested_server_name() {
            Ok(Some(sni)) if !sni.is_empty() => sni,
            Ok(_) => {
                host.record(StreamEvent::NoSni);
                return self.route(host, SniAction::Passthrough);
            }
            Err(_) => {
                host.record(StreamEvent::RequestedServerNameFailed);
                return self.fail_closed(host);
            }
        };

        let Some(snapshot) = self.load_snapshot(host) else {
            return EngineAction::Pause;
        };
        match snapshot.status() {
            PolicySnapshotStatus::Ready => {}
            PolicySnapshotStatus::BindingMiss
            | PolicySnapshotStatus::PendingReferences
            | PolicySnapshotStatus::NotReady
            | PolicySnapshotStatus::Unspecified => return self.fail_closed(host),
        }

        match snapshot.evaluate(&sni) {
            Ok(Some(decision)) => match decision.action {
                SniAction::TlsTermination => self.route(host, SniAction::TlsTermination),
                SniAction::Passthrough => self.route(host, SniAction::Passthrough),
                SniAction::Deny | SniAction::Unspecified => {
                    host.record(StreamEvent::Decision(SniAction::Deny));
                    self.fail_closed(host)
                }
            },
            Ok(None) => self.route(host, SniAction::Passthrough),
            Err(_) => self.fail_closed(host),
        }
    }

    fn load_snapshot<H: Host>(&mut self, host: &mut H) -> Option<PolicySnapshot> {
        let bytes = match host.policy_snapshot() {
            Ok(bytes) => bytes,
            Err(_) => {
                host.record(StreamEvent::PolicySnapshotFailed);
                self.fail_closed(host);
                return None;
            }
        };
        let snapshot = match BoundPolicySnapshot::decode(bytes.as_slice()) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                host.record(StreamEvent::PolicySnapshotFailed);
                self.fail_closed(host);
                return None;
            }
        };
        let snapshot = match PolicySnapshot::try_from(snapshot) {
            Ok(snapshot) => snapshot,
            Err(_) => {
                host.record(StreamEvent::PolicySnapshotFailed);
                self.fail_closed(host);
                return None;
            }
        };
        host.record(StreamEvent::PolicySnapshotStatus(snapshot.status()));
        Some(snapshot)
    }

    fn route<H: Host>(&self, host: &mut H, action: SniAction) -> EngineAction {
        let cluster = match action {
            SniAction::TlsTermination => self.route_config.termination_cluster(),
            SniAction::Passthrough => self.route_config.passthrough_cluster(),
            SniAction::Deny | SniAction::Unspecified => return self.fail_closed(host),
        };
        if host.set_cluster(cluster).is_err() {
            host.record(StreamEvent::SetClusterFailed);
            return self.fail_closed(host);
        }
        host.record(StreamEvent::Decision(action));
        EngineAction::Continue
    }

    fn fail_closed<H: Host>(&self, host: &mut H) -> EngineAction {
        if host.close_downstream().is_err() {
            host.record(StreamEvent::CloseFailed);
        }
        EngineAction::Pause
    }
}
