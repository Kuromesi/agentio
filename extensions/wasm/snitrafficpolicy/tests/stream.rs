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

use agentio_sni_policy_wasm::abi::{
    BoundPolicy, BoundPolicyGroup, BoundPolicySnapshot, PolicySnapshotStatus, SniAction, SniMatch,
    SniRule, SniTrafficPolicy,
};
use agentio_sni_policy_wasm::config::RouteConfig;
use agentio_sni_policy_wasm::policy::SNI_TRAFFIC_POLICY_TYPE_URL;
use agentio_sni_policy_wasm::stream::{EngineAction, Host, HostError, StreamEngine, StreamEvent};
use prost::Message;

const TERMINATION_CLUSTER: &str = "termination-from-control-plane";
const PASSTHROUGH_CLUSTER: &str = "passthrough-from-control-plane";

fn engine() -> StreamEngine {
    StreamEngine::new(
        RouteConfig::new(TERMINATION_CLUSTER.into(), PASSTHROUGH_CLUSTER.into()).unwrap(),
    )
}

#[derive(Default)]
struct FakeHost {
    requested_server_name: Option<String>,
    snapshot: Vec<u8>,
    snapshot_calls: usize,
    clusters: Vec<String>,
    closes: usize,
    fail_requested_server_name: bool,
    fail_snapshot: bool,
    fail_set_cluster: bool,
    fail_close: bool,
    events: Vec<StreamEvent>,
}

impl Host for FakeHost {
    fn requested_server_name(&mut self) -> Result<Option<String>, HostError> {
        if self.fail_requested_server_name {
            Err(HostError::RequestedServerNameFailed)
        } else {
            Ok(self.requested_server_name.clone())
        }
    }

    fn policy_snapshot(&mut self) -> Result<Vec<u8>, HostError> {
        self.snapshot_calls += 1;
        if self.fail_snapshot {
            Err(HostError::PolicySnapshotFailed)
        } else {
            Ok(self.snapshot.clone())
        }
    }

    fn set_cluster(&mut self, cluster: &str) -> Result<(), HostError> {
        if self.fail_set_cluster {
            Err(HostError::SetClusterFailed)
        } else {
            self.clusters.push(cluster.into());
            Ok(())
        }
    }

    fn close_downstream(&mut self) -> Result<(), HostError> {
        self.closes += 1;
        if self.fail_close {
            Err(HostError::CloseFailed)
        } else {
            Ok(())
        }
    }

    fn record(&mut self, event: StreamEvent) {
        self.events.push(event);
    }
}

fn rule(pattern: &str, action: SniAction) -> SniRule {
    SniRule {
        r#match: Some(SniMatch {
            sni: vec![pattern.into()],
        }),
        action: action as i32,
    }
}

fn snapshot(
    status: PolicySnapshotStatus,
    sni_group: Option<(PolicySnapshotStatus, Vec<SniRule>)>,
) -> Vec<u8> {
    BoundPolicySnapshot {
        generation: 7,
        status: status as i32,
        groups: sni_group
            .map(|(group_status, rules)| BoundPolicyGroup {
                type_url: SNI_TRAFFIC_POLICY_TYPE_URL.into(),
                status: group_status as i32,
                policies: if rules.is_empty() {
                    vec![]
                } else {
                    vec![BoundPolicy {
                        resource_name: "sandbox/policy".into(),
                        resource: SniTrafficPolicy { rules }.encode_to_vec(),
                    }]
                },
            })
            .into_iter()
            .collect(),
    }
    .encode_to_vec()
}

fn host_with_rules(rules: Vec<SniRule>) -> FakeHost {
    FakeHost {
        requested_server_name: Some("api.example.com".into()),
        snapshot: snapshot(
            PolicySnapshotStatus::Ready,
            Some((PolicySnapshotStatus::Ready, rules)),
        ),
        ..FakeHost::default()
    }
}

#[test]
fn routes_during_new_connection_before_tcp_proxy_initialization() {
    let mut host = host_with_rules(vec![rule("api.example.com", SniAction::TlsTermination)]);
    let mut engine = engine();

    assert_eq!(engine.on_new_connection(&mut host), EngineAction::Continue);
    assert_eq!(host.snapshot_calls, 1);
    assert_eq!(host.clusters, vec![TERMINATION_CLUSTER]);
}

#[test]
fn maps_actions_and_unmatched_sni() {
    for (action, expected_cluster, expected_action) in [
        (
            SniAction::TlsTermination,
            TERMINATION_CLUSTER,
            EngineAction::Continue,
        ),
        (
            SniAction::Passthrough,
            PASSTHROUGH_CLUSTER,
            EngineAction::Continue,
        ),
        (SniAction::Deny, "", EngineAction::Pause),
    ] {
        let mut host = host_with_rules(vec![rule("api.example.com", action)]);
        let mut engine = engine();
        assert_eq!(engine.on_new_connection(&mut host), expected_action);
        if expected_cluster.is_empty() {
            assert_eq!(host.closes, 1);
        } else {
            assert_eq!(host.clusters, vec![expected_cluster]);
        }
    }

    for rules in [vec![rule("other.example.com", SniAction::Deny)], vec![]] {
        let mut host = host_with_rules(rules);
        let mut engine = engine();
        assert_eq!(engine.on_new_connection(&mut host), EngineAction::Continue);
        assert_eq!(host.clusters, vec![PASSTHROUGH_CLUSTER]);
    }
}

#[test]
fn no_sni_passthrough_does_not_require_policy_snapshot() {
    for requested_server_name in [None, Some(String::new())] {
        let mut host = FakeHost {
            requested_server_name,
            ..FakeHost::default()
        };
        let mut engine = engine();

        assert_eq!(engine.on_new_connection(&mut host), EngineAction::Continue);
        assert_eq!(host.snapshot_calls, 0);
        assert_eq!(host.clusters, vec![PASSTHROUGH_CLUSTER]);
        assert_eq!(host.closes, 0);
        assert!(host.events.contains(&StreamEvent::NoSni));
    }
}

#[test]
fn binding_miss_fails_closed_until_explicit_empty_binding_arrives() {
    let mut host = FakeHost {
        requested_server_name: Some("new-pod.test".into()),
        snapshot: snapshot(PolicySnapshotStatus::BindingMiss, None),
        ..FakeHost::default()
    };
    let mut engine = engine();

    assert_eq!(engine.on_new_connection(&mut host), EngineAction::Pause);
    assert_eq!(host.closes, 1);
    assert!(host.clusters.is_empty());
}

#[test]
fn fails_closed_for_sni_and_policy_snapshot_failures() {
    let cases = [
        FakeHost {
            fail_requested_server_name: true,
            ..FakeHost::default()
        },
        FakeHost {
            requested_server_name: Some("api.example.com".into()),
            ..FakeHost::default()
        },
        FakeHost {
            requested_server_name: Some("api.example.com".into()),
            snapshot: snapshot(PolicySnapshotStatus::NotReady, None),
            ..FakeHost::default()
        },
        FakeHost {
            requested_server_name: Some("api.example.com".into()),
            snapshot: snapshot(
                PolicySnapshotStatus::Ready,
                Some((PolicySnapshotStatus::PendingReferences, vec![])),
            ),
            ..FakeHost::default()
        },
        FakeHost {
            requested_server_name: Some("api.example.com".into()),
            snapshot: vec![0xff, 0xff],
            ..FakeHost::default()
        },
        FakeHost {
            requested_server_name: Some("api.example.com".into()),
            fail_snapshot: true,
            ..FakeHost::default()
        },
    ];
    for mut host in cases {
        let mut engine = engine();
        assert_eq!(engine.on_new_connection(&mut host), EngineAction::Pause);
        assert_eq!(host.closes, 1);
        assert!(host.clusters.is_empty());
    }
}

#[test]
fn fails_closed_for_invalid_sni_and_route_write_failure() {
    let mut invalid_sni_host = host_with_rules(vec![rule("*", SniAction::Passthrough)]);
    invalid_sni_host.requested_server_name = Some("invalid sni".into());
    let mut engine = engine();
    assert_eq!(
        engine.on_new_connection(&mut invalid_sni_host),
        EngineAction::Pause
    );
    assert_eq!(invalid_sni_host.closes, 1);

    let mut route_host = host_with_rules(vec![rule("*", SniAction::Passthrough)]);
    route_host.fail_set_cluster = true;
    let mut engine = engine();
    assert_eq!(
        engine.on_new_connection(&mut route_host),
        EngineAction::Pause
    );
    assert_eq!(route_host.closes, 1);
}

#[test]
fn records_close_failure_without_changing_fail_closed_action() {
    let mut host = FakeHost {
        fail_requested_server_name: true,
        fail_close: true,
        ..FakeHost::default()
    };
    let mut engine = engine();
    assert_eq!(engine.on_new_connection(&mut host), EngineAction::Pause);
    assert_eq!(host.closes, 1);
    assert!(host.events.contains(&StreamEvent::CloseFailed));
}
