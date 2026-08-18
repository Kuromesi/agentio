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

use prost::Message;

use crate::abi::{BoundPolicySnapshot, PolicySnapshotStatus, SniAction, SniTrafficPolicy};
use crate::matcher::matches_sni;
use crate::normalize::{normalize_pattern, normalize_sni};

pub const SNI_TRAFFIC_POLICY_TYPE_URL: &str =
    "type.googleapis.com/kruise.networking.extensions.v1.SniTrafficPolicy";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyError(String);

impl Display for PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for PolicyError {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Rule {
    patterns: Vec<String>,
    action: SniAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Policy {
    resource_name: String,
    rules: Vec<Rule>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySnapshot {
    generation: u64,
    status: PolicySnapshotStatus,
    policies: Vec<Policy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision<'a> {
    pub resource_name: &'a str,
    pub rule_index: usize,
    pub action: SniAction,
}

impl PolicySnapshot {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn status(&self) -> PolicySnapshotStatus {
        self.status
    }

    pub fn evaluate(&self, sni: &str) -> Result<Option<PolicyDecision<'_>>, PolicyError> {
        let normalized = normalize_sni(sni).map_err(|error| PolicyError(error.to_string()))?;
        for policy in &self.policies {
            for (rule_index, rule) in policy.rules.iter().enumerate() {
                if rule
                    .patterns
                    .iter()
                    .any(|pattern| matches_sni(pattern, &normalized))
                {
                    return Ok(Some(PolicyDecision {
                        resource_name: &policy.resource_name,
                        rule_index,
                        action: rule.action,
                    }));
                }
            }
        }
        Ok(None)
    }
}

impl TryFrom<BoundPolicySnapshot> for PolicySnapshot {
    type Error = PolicyError;

    fn try_from(snapshot: BoundPolicySnapshot) -> Result<Self, Self::Error> {
        let snapshot_status = PolicySnapshotStatus::try_from(snapshot.status).map_err(|_| {
            PolicyError(format!(
                "unknown policy snapshot status {}",
                snapshot.status
            ))
        })?;
        if snapshot_status == PolicySnapshotStatus::Unspecified {
            return Err(PolicyError("policy snapshot status is unspecified".into()));
        }

        if snapshot_status != PolicySnapshotStatus::Ready {
            return Ok(Self {
                generation: snapshot.generation,
                status: snapshot_status,
                policies: vec![],
            });
        }

        let mut sni_group = None;
        for group in snapshot.groups {
            if group.type_url != SNI_TRAFFIC_POLICY_TYPE_URL {
                continue;
            }
            if sni_group.replace(group).is_some() {
                return Err(PolicyError("duplicate SNI traffic policy group".into()));
            }
        }

        let Some(group) = sni_group else {
            return Ok(Self {
                generation: snapshot.generation,
                status: PolicySnapshotStatus::Ready,
                policies: vec![],
            });
        };
        let group_status = PolicySnapshotStatus::try_from(group.status).map_err(|_| {
            PolicyError(format!("unknown SNI policy group status {}", group.status))
        })?;
        if group_status == PolicySnapshotStatus::Unspecified {
            return Err(PolicyError("SNI policy group status is unspecified".into()));
        }
        if group_status != PolicySnapshotStatus::Ready {
            return Ok(Self {
                generation: snapshot.generation,
                status: group_status,
                policies: vec![],
            });
        }

        let mut policies = Vec::with_capacity(group.policies.len());
        for policy in group.policies {
            if policy.resource_name.is_empty() {
                return Err(PolicyError("policy resource name is empty".into()));
            }
            let resource =
                SniTrafficPolicy::decode(policy.resource.as_slice()).map_err(|error| {
                    PolicyError(format!(
                        "SNI policy {} cannot be decoded: {error}",
                        policy.resource_name
                    ))
                })?;
            let mut rules = Vec::with_capacity(resource.rules.len());
            for rule in resource.rules {
                let action = SniAction::try_from(rule.action)
                    .map_err(|_| PolicyError(format!("unknown SNI action {}", rule.action)))?;
                if action == SniAction::Unspecified {
                    return Err(PolicyError("SNI action is unspecified".into()));
                }
                let patterns = rule
                    .r#match
                    .ok_or_else(|| PolicyError("SNI match is missing".into()))?
                    .sni;
                if patterns.is_empty() {
                    return Err(PolicyError("SNI pattern list is empty".into()));
                }
                let patterns = patterns
                    .iter()
                    .map(|pattern| {
                        normalize_pattern(pattern).map_err(|error| PolicyError(error.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                rules.push(Rule { patterns, action });
            }
            policies.push(Policy {
                resource_name: policy.resource_name,
                rules,
            });
        }
        Ok(Self {
            generation: snapshot.generation,
            status: PolicySnapshotStatus::Ready,
            policies,
        })
    }
}
