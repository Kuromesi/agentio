// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::wire::agentio::security::{TcpAction, TcpMatch, TcpPolicy, TcpRule};
use crate::{
    processor::{Gateway, Processor},
    wire::{
        agentio::{
            sandbox::{Sandbox, sandbox::Attester},
            security::SecurityProfile,
        },
        extproc,
        istio::workload::{Extension, Workload},
        kruise::networking::extensions::v1::{PolicyReference, PolicyResourceReference},
    },
};
use prost::Message;
use prost_types::{Any, Struct, value::Kind};
use std::collections::BTreeMap;

const UID: &str = "Kubernetes//Pod/ns/pod";
const SANDBOX: &str = "kruise:sandbox";

fn policy(action: Option<TcpAction>) -> Any {
    Any {
        type_url: view::SECURITY_PROFILE.into(),
        value: SecurityProfile {
            name: "shared".into(),
            uid: "uid".into(),
            sni_policy: None,
            tcp_policy: Some(TcpPolicy {
                rules: action
                    .into_iter()
                    .map(|action| TcpRule {
                        name: "all".into(),
                        action: action as i32,
                        r#match: vec![TcpMatch {
                            cidrs: vec!["0.0.0.0/0".into()],
                            ports: vec![],
                        }],
                    })
                    .collect(),
            }),
            ..Default::default()
        }
        .encode_to_vec(),
    }
}

fn processor() -> Processor {
    Processor {
        client: Client::new(
            CacheConfig {
                max_entries: 100,
                idle_ttl: Duration::from_secs(60),
            },
            Metrics::new(),
        ),
        cluster_id: "Kubernetes".into(),
        timeout: Duration::from_millis(100),
        enable_sni_traffic_policy: true,
        gateway: Gateway::AgentioEgress,
    }
}

fn workload() -> Workload {
    Workload {
        uid: UID.into(),
        name: "pod".into(),
        namespace: "ns".into(),
        trust_domain: "cluster.local".into(),
        service_account: "default".into(),
        ..Default::default()
    }
}

fn seed(
    client: &Arc<Client>,
    kind: ResourceKind,
    name: &str,
    aliases: &[&str],
    value: impl Message,
) {
    let mut lease = client.acquire(kind, name).unwrap();
    client
        .apply(
            kind,
            &Response {
                type_url: kind.type_url().into(),
                resources: vec![ads::Resource {
                    name: name.into(),
                    aliases: aliases.iter().map(|s| (*s).into()).collect(),
                    resource: Some(Any {
                        type_url: kind.type_url().into(),
                        value: value.encode_to_vec(),
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            },
        )
        .unwrap();
    lease.success = true;
}

fn seed_workload(client: &Arc<Client>, policy: Option<Any>) {
    let w = if let Some(policy) = policy {
        seed(
            client,
            ResourceKind::SecurityProfile,
            "shared",
            &[],
            SecurityProfile::decode(policy.value.as_slice()).unwrap(),
        );
        referenced_workload(&["shared"])
    } else {
        workload()
    };
    seed(client, ResourceKind::Workload, UID, &["/192.0.2.10"], w);
}

fn request(sandbox: &str) -> extproc::ProcessingRequest {
    extproc::ProcessingRequest {
        request_headers: Some(extproc::HttpHeaders {
            headers: Some(extproc::HeaderMap {
                headers: vec![
                    extproc::HeaderValue {
                        key: ":method".into(),
                        value: "CONNECT".into(),
                        ..Default::default()
                    },
                    extproc::HeaderValue {
                        key: ":authority".into(),
                        value: "198.51.100.1:443".into(),
                        ..Default::default()
                    },
                ],
            }),
            ..Default::default()
        }),
        attributes: HashMap::from([(
            "envoy.filters.http.ext_proc".into(),
            Struct {
                fields: BTreeMap::from([
                    (
                        "filter_state['agentio.downstream.ip']".into(),
                        view::string("192.0.2.10"),
                    ),
                    (
                        "filter_state['agentio.peer.principal']".into(),
                        view::string("spiffe://cluster.local/ns/ns/sa/default"),
                    ),
                    (
                        "filter_state['agentio.sandbox.id']".into(),
                        view::string(sandbox),
                    ),
                ]),
            },
        )]),
    }
}

fn metadata(response: extproc::ProcessingResponse) -> Struct {
    assert!(matches!(
        response.response,
        Some(extproc::processing_response::Response::RequestHeaders(_))
    ));
    let mut metadata = response.dynamic_metadata.unwrap();
    let Some(Kind::StructValue(agentio)) = metadata.fields.remove("agentio").unwrap().kind else {
        panic!("missing agentio metadata")
    };
    agentio
}

fn assert_decision(response: extproc::ProcessingResponse, want: &str) {
    assert_eq!(
        metadata(response).fields.get("tcp"),
        Some(&view::object([(
            "original_destination_decision".into(),
            view::string(want)
        )]))
    );
}

#[tokio::test]
async fn deny_is_metadata_not_connect_rejection_and_missing_policy_fails_closed() {
    for enable_sni in [true, false] {
        for action in [Some(TcpAction::Allow), Some(TcpAction::Deny), None] {
            let mut p = processor();
            p.enable_sni_traffic_policy = enable_sni;
            seed_workload(&p.client, action.map(|a| policy(Some(a))));
            let result = p.handle(request("")).await;
            if action.is_none() {
                assert_eq!(result.unwrap_err().code(), tonic::Code::Unavailable);
                continue;
            }
            let fields = metadata(result.unwrap()).fields;
            assert_eq!(fields.contains_key("sni"), enable_sni);
            let want = if action == Some(TcpAction::Allow) {
                "allow"
            } else {
                "deny"
            };
            assert_eq!(
                fields.get("tcp"),
                Some(&view::object([(
                    "original_destination_decision".into(),
                    view::string(want)
                )]))
            );
        }
    }
    assert!(
        ResourceKind::from_type_url("type.googleapis.com/agentio.security.TrafficPolicy").is_none()
    );
}

#[tokio::test]
async fn empty_profile_allows_but_missing_referenced_profile_does_not() {
    let p = processor();
    seed_workload(&p.client, Some(policy(None)));
    assert_decision(p.handle(request("")).await.unwrap(), "allow");
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&["unavailable"]),
    );
    assert_eq!(
        p.handle(request("")).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
}

#[tokio::test]
async fn shared_and_inline_rules_form_one_ordered_chain() {
    for (shared, inline, want) in [
        (Some(TcpAction::Allow), Some(TcpAction::Deny), "allow"),
        (Some(TcpAction::Deny), Some(TcpAction::Allow), "deny"),
        (None, Some(TcpAction::Deny), "deny"),
        (None, None, "allow"),
    ] {
        let p = processor();
        seed_workload(&p.client, Some(policy(shared)));
        seed(
            &p.client,
            ResourceKind::Sandbox,
            SANDBOX,
            &[],
            Sandbox {
                uid: SANDBOX.into(),
                attester: Some(Attester {
                    workload_uid: UID.into(),
                }),
                extensions: vec![policy(inline)],
                ..Default::default()
            },
        );
        assert_decision(p.handle(request(SANDBOX)).await.unwrap(), want);
    }
}

#[tokio::test]
async fn sandbox_without_inline_profile_uses_shared_rules_or_default_allow() {
    for (shared, want) in [
        (Some(TcpAction::Allow), "allow"),
        (Some(TcpAction::Deny), "deny"),
        (None, "allow"),
    ] {
        let p = processor();
        if let Some(action) = shared {
            seed_workload(&p.client, Some(policy(Some(action))));
        } else {
            seed(
                &p.client,
                ResourceKind::Workload,
                UID,
                &["/192.0.2.10"],
                referenced_workload(&[]),
            );
        }
        seed(
            &p.client,
            ResourceKind::Sandbox,
            SANDBOX,
            &[],
            Sandbox {
                uid: SANDBOX.into(),
                attester: Some(Attester {
                    workload_uid: UID.into(),
                }),
                ..Default::default()
            },
        );
        assert_decision(p.handle(request(SANDBOX)).await.unwrap(), want);
    }
}

#[tokio::test]
async fn workload_update_while_waiting_for_sandbox_rebuilds_snapshot() {
    let p = processor();
    seed_workload(&p.client, Some(policy(Some(TcpAction::Allow))));
    let mut pending = Box::pin(p.handle(request(SANDBOX)));
    assert!(futures_util::poll!(&mut pending).is_pending());
    seed_workload(&p.client, Some(policy(Some(TcpAction::Deny))));
    seed(
        &p.client,
        ResourceKind::Sandbox,
        SANDBOX,
        &[],
        Sandbox {
            uid: SANDBOX.into(),
            attester: Some(Attester {
                workload_uid: UID.into(),
            }),
            extensions: vec![policy(None)],
            ..Default::default()
        },
    );
    assert_decision(pending.await.unwrap(), "deny");
}

#[tokio::test]
async fn agentgateway_keeps_identity_only_contract() {
    let mut p = processor();
    p.gateway = Gateway::Agentgateway;
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        workload(),
    );
    let mut req = request("");
    let headers = &mut req
        .request_headers
        .as_mut()
        .unwrap()
        .headers
        .as_mut()
        .unwrap()
        .headers;
    headers[0].value = "GET".into();
    headers[1].value = "api.example.com".into();
    let fields = metadata(p.handle(req).await.unwrap()).fields;
    assert!(fields.contains_key("workload"));
    assert!(!fields.contains_key("sni") && !fields.contains_key("tcp"));
    assert_eq!(
        p.handle(request(SANDBOX)).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
}

fn referenced_workload(names: &[&str]) -> Workload {
    let mut w = workload();
    w.extensions.push(Extension {
        name: "security-profile-reference".into(),
        config: Some(Any {
            type_url: "type.googleapis.com/kruise.networking.extensions.v1.PolicyReference".into(),
            value: PolicyReference {
                type_url: view::SECURITY_PROFILE.into(),
                resources: names
                    .iter()
                    .map(|name| PolicyResourceReference {
                        name: (*name).into(),
                        uid: "uid".into(),
                        extensions: vec![],
                    })
                    .collect(),
            }
            .encode_to_vec(),
        }),
    });
    w
}

fn shared_profile(name: &str, action: Option<TcpAction>) -> SecurityProfile {
    let mut profile = SecurityProfile::decode(policy(action).value.as_slice()).unwrap();
    profile.name = name.into();
    profile
}

#[tokio::test]
async fn shared_profiles_update_without_workload_and_preserve_binding_order() {
    use crate::wire::agentio::security::{
        SniAction, SniMatch, SniPolicy as SniTrafficPolicy, SniRule,
    };
    let p = processor();
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&["second", "first"]),
    );
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "first",
        &[],
        shared_profile("first", Some(TcpAction::Allow)),
    );
    let mut pending = Box::pin(p.handle(request("")));
    assert!(futures_util::poll!(&mut pending).is_pending());
    let mut second = shared_profile("second", Some(TcpAction::Deny));
    second.sni_policy = Some(SniTrafficPolicy {
        rules: vec![SniRule {
            action: SniAction::Deny as i32,
            r#match: Some(SniMatch {
                sni: vec!["blocked.example".into()],
                ports: vec![443],
            }),
        }],
    });
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "second",
        &[],
        second.clone(),
    );
    assert_decision(pending.await.unwrap(), "deny");
    second.tcp_policy = shared_profile("second", None).tcp_policy;
    second.sni_policy.as_mut().unwrap().rules[0].action = SniAction::Passthrough as i32;
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "second",
        &[],
        second.clone(),
    );
    let result = metadata(p.handle(request("")).await.unwrap());
    assert_eq!(
        result.fields["tcp"],
        view::object([(
            "original_destination_decision".into(),
            view::string("allow")
        )])
    );
    assert_eq!(
        result.fields["sni"],
        view::object([(
            "policy".into(),
            view::object([(
                "rules".into(),
                view::list(view::project_rules(&second.sni_policy.unwrap().rules).collect())
            )])
        )])
    );
    p.client
        .apply(
            ResourceKind::SecurityProfile,
            &Response {
                type_url: view::SECURITY_PROFILE.into(),
                removed_resources: vec!["second".into()],
                ..Default::default()
            },
        )
        .unwrap();
    assert!(p.handle(request("")).await.is_err());
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "second",
        &[],
        shared_profile("second", Some(TcpAction::Deny)),
    );
    assert_decision(p.handle(request("")).await.unwrap(), "deny");
    let mut replacement = shared_profile("second", None);
    replacement.uid = "replacement".into();
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "second",
        &[],
        replacement,
    );
    assert_eq!(
        p.handle(request("")).await.unwrap_err().code(),
        tonic::Code::Unavailable
    );
}

#[tokio::test]
async fn empty_binding_allows_and_changed_binding_rebuilds_pending_snapshot() {
    let p = processor();
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&[]),
    );
    assert_decision(p.handle(request("")).await.unwrap(), "allow");
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&["old"]),
    );
    let mut pending = Box::pin(p.handle(request("")));
    assert!(futures_util::poll!(&mut pending).is_pending());
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&["new"]),
    );
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "new",
        &[],
        shared_profile("new", Some(TcpAction::Deny)),
    );
    seed(
        &p.client,
        ResourceKind::SecurityProfile,
        "old",
        &[],
        shared_profile("old", Some(TcpAction::Allow)),
    );
    assert_decision(pending.await.unwrap(), "deny");
}

#[tokio::test]
async fn withdrawn_reference_does_not_reject_the_replacement_binding() {
    let p = processor();
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&["old"]),
    );
    let mut pending = Box::pin(p.handle(request("")));
    assert!(futures_util::poll!(&mut pending).is_pending());
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&[]),
    );
    p.client
        .apply(
            ResourceKind::SecurityProfile,
            &Response {
                type_url: view::SECURITY_PROFILE.into(),
                removed_resources: vec!["old".into()],
                ..Default::default()
            },
        )
        .unwrap();
    assert_decision(pending.await.unwrap(), "allow");
}

#[tokio::test]
async fn profile_source_name_is_independent_of_its_discovery_name() {
    let p = processor();
    let name = "namespaced/ns/shared";
    seed(
        &p.client,
        ResourceKind::Workload,
        UID,
        &["/192.0.2.10"],
        referenced_workload(&[name]),
    );
    let mut profile = shared_profile("shared", None);
    profile.namespace = "ns".into();
    seed(&p.client, ResourceKind::SecurityProfile, name, &[], profile);
    assert_decision(p.handle(request("")).await.unwrap(), "allow");
}
