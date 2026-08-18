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
use agentio_sni_policy_wasm::matcher::matches_sni;
use agentio_sni_policy_wasm::normalize::normalize_sni;
use agentio_sni_policy_wasm::policy::{PolicySnapshot, SNI_TRAFFIC_POLICY_TYPE_URL};
use prost::Message;

fn rule(patterns: &[&str], action: SniAction) -> SniRule {
    SniRule {
        r#match: Some(SniMatch {
            sni: patterns.iter().map(|value| (*value).into()).collect(),
        }),
        action: action as i32,
    }
}

fn policy(resource_name: &str, rules: Vec<SniRule>) -> BoundPolicy {
    BoundPolicy {
        resource_name: resource_name.into(),
        resource: SniTrafficPolicy { rules }.encode_to_vec(),
    }
}

fn snapshot(groups: Vec<BoundPolicyGroup>) -> BoundPolicySnapshot {
    BoundPolicySnapshot {
        generation: 9,
        status: PolicySnapshotStatus::Ready as i32,
        groups,
    }
}

fn sni_group(status: PolicySnapshotStatus, policies: Vec<BoundPolicy>) -> BoundPolicyGroup {
    BoundPolicyGroup {
        type_url: SNI_TRAFFIC_POLICY_TYPE_URL.into(),
        status: status as i32,
        policies,
    }
}

#[test]
fn normalizes_ascii_case_and_one_trailing_dot() {
    assert_eq!(
        normalize_sni("API.Example.COM.").unwrap(),
        "api.example.com"
    );
    assert!(normalize_sni("").is_err());
    assert!(normalize_sni("example.com..").is_err());
    assert!(normalize_sni("täst.example").is_err());
}

#[test]
fn matches_exact_wildcard_and_catch_all_with_label_boundaries() {
    assert!(matches_sni("api.example.com", "api.example.com"));
    assert!(!matches_sni("api.example.com", "other.example.com"));
    assert!(matches_sni("*.example.com", "api.example.com"));
    assert!(matches_sni("*.example.com", "deep.api.example.com"));
    assert!(!matches_sni("*.example.com", "example.com"));
    assert!(!matches_sni("*.example.com", "notexample.com"));
    assert!(matches_sni("*", "anything"));
    assert!(!matches_sni("*", ""));
}

#[test]
fn evaluates_first_rule_of_first_policy_in_binding_order() {
    let snapshot = PolicySnapshot::try_from(snapshot(vec![sni_group(
        PolicySnapshotStatus::Ready,
        vec![
            policy(
                "sandbox/high",
                vec![
                    rule(&["api.example.com"], SniAction::Deny),
                    rule(&["*.example.com"], SniAction::TlsTermination),
                ],
            ),
            policy("sandbox/low", vec![rule(&["*"], SniAction::Passthrough)]),
        ],
    )]))
    .unwrap();

    let exact = snapshot.evaluate("API.Example.COM.").unwrap().unwrap();
    assert_eq!(exact.resource_name, "sandbox/high");
    assert_eq!(exact.rule_index, 0);
    assert_eq!(exact.action, SniAction::Deny);

    let wildcard = snapshot.evaluate("www.example.com").unwrap().unwrap();
    assert_eq!(wildcard.resource_name, "sandbox/high");
    assert_eq!(wildcard.rule_index, 1);
    assert_eq!(wildcard.action, SniAction::TlsTermination);

    let fallback = snapshot.evaluate("outside.test").unwrap().unwrap();
    assert_eq!(fallback.resource_name, "sandbox/low");
    assert_eq!(fallback.action, SniAction::Passthrough);
}

#[test]
fn ignores_unrelated_policy_types_and_accepts_no_sni_group() {
    let snapshot = PolicySnapshot::try_from(snapshot(vec![BoundPolicyGroup {
        type_url: "type.googleapis.com/example.OtherPolicy".into(),
        status: PolicySnapshotStatus::PendingReferences as i32,
        policies: vec![],
    }]))
    .unwrap();
    assert_eq!(snapshot.status(), PolicySnapshotStatus::Ready);
    assert!(snapshot.evaluate("api.example.com").unwrap().is_none());
}

#[test]
fn reports_only_the_sni_group_pending_status() {
    let snapshot = PolicySnapshot::try_from(snapshot(vec![sni_group(
        PolicySnapshotStatus::PendingReferences,
        vec![],
    )]))
    .unwrap();
    assert_eq!(snapshot.status(), PolicySnapshotStatus::PendingReferences);
}

#[test]
fn rejects_unknown_status_action_and_invalid_patterns() {
    let bad_status = BoundPolicySnapshot {
        generation: 1,
        status: 99,
        groups: vec![],
    };
    assert!(PolicySnapshot::try_from(bad_status).is_err());

    let bad_action = snapshot(vec![sni_group(
        PolicySnapshotStatus::Ready,
        vec![policy(
            "sandbox/bad-action",
            vec![SniRule {
                r#match: Some(SniMatch {
                    sni: vec!["api.example.com".into()],
                }),
                action: 99,
            }],
        )],
    )]);
    assert!(PolicySnapshot::try_from(bad_action).is_err());

    let bad_pattern = snapshot(vec![sni_group(
        PolicySnapshotStatus::Ready,
        vec![policy(
            "sandbox/bad-pattern",
            vec![rule(&["*foo.example.com"], SniAction::Deny)],
        )],
    )]);
    assert!(PolicySnapshot::try_from(bad_pattern).is_err());
}
