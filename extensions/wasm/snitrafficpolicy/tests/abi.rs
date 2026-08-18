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
    BoundPolicy, BoundPolicyGroup, BoundPolicySnapshot, PolicySnapshotStatus,
};
use agentio_sni_policy_wasm::policy::SNI_TRAFFIC_POLICY_TYPE_URL;
use prost::Message;

#[test]
fn bound_policy_snapshot_round_trip_preserves_type_and_resource_order() {
    let snapshot = BoundPolicySnapshot {
        generation: 42,
        status: PolicySnapshotStatus::Ready as i32,
        groups: vec![BoundPolicyGroup {
            type_url: SNI_TRAFFIC_POLICY_TYPE_URL.into(),
            status: PolicySnapshotStatus::Ready as i32,
            policies: vec![
                BoundPolicy {
                    resource_name: "sandbox/high".into(),
                    resource: vec![1, 2],
                },
                BoundPolicy {
                    resource_name: "sandbox/low".into(),
                    resource: vec![3, 4],
                },
            ],
        }],
    };

    let decoded = BoundPolicySnapshot::decode(snapshot.encode_to_vec().as_slice()).unwrap();
    assert_eq!(decoded, snapshot);
    assert_eq!(decoded.groups[0].type_url, SNI_TRAFFIC_POLICY_TYPE_URL);
    assert_eq!(decoded.groups[0].policies[0].resource_name, "sandbox/high");
    assert_eq!(decoded.groups[0].policies[1].resource_name, "sandbox/low");
}

#[test]
fn policy_snapshot_status_values_are_distinct() {
    let statuses = [
        PolicySnapshotStatus::Ready,
        PolicySnapshotStatus::BindingMiss,
        PolicySnapshotStatus::PendingReferences,
        PolicySnapshotStatus::NotReady,
    ];
    for (index, status) in statuses.iter().enumerate() {
        assert_eq!(*status as usize, index + 1);
    }
}
