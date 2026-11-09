// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use tracing::debug;

use crate::{
    discovery::{Client, DemandError},
    identity::certificate_instance,
    view::{ResourceKind, View},
};

#[derive(Clone, Copy)]
pub(super) struct IdentityEvidence<'a> {
    pub certificate: &'a str,
    pub peer_ip: &'a str,
    pub principal: &'a str,
    pub sandbox_id: &'a str,
}

pub(super) struct ResolveRequest<'a> {
    pub identity: IdentityEvidence<'a>,
    pub target: Option<SocketAddr>,
}

pub(super) struct Resolved {
    pub workload: Arc<View>,
    pub sandbox: Option<Arc<View>>,
    pub profiles: Vec<Arc<View>>,
    pub instance: Option<String>,
    pub tcp_decision: Option<bool>,
}

pub(super) struct Resolver<'a> {
    pub client: &'a Arc<Client>,
    pub cluster_id: &'a str,
    pub timeout: Duration,
}

struct RequestSnapshot {
    profiles: Vec<Arc<View>>,
    workload: Arc<View>,
    sandbox: Option<Arc<View>>,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(super) enum ResolveError {
    #[error("TCP policy is unavailable")]
    PolicyUnavailable,
    #[error("deadline exceeded")]
    Timeout,
    #[error("snapshot construction deadline exceeded")]
    Deadline,
    #[error("connection denied")]
    Denied,
    #[error(transparent)]
    Discovery(#[from] DemandError),
}

impl Resolver<'_> {
    pub async fn resolve(&self, request: &ResolveRequest<'_>) -> Result<Resolved, ResolveError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        tokio::time::timeout_at(deadline, async {
            let mut invalidated = self.client.invalidations();
            loop {
                let epoch = *invalidated.borrow_and_update();
                // A clear invalidates all dependencies; retries share the original deadline.
                tokio::select! {
                    biased;
                    _ = invalidated.changed() => continue,
                    result = self.resolve_once(request, deadline) => {
                        if self.client.current_epoch() == epoch {
                            break result;
                        }
                    }
                }
            }
        })
        .await
        .map_err(|_| ResolveError::Timeout)?
    }

    // Construct the complete candidate before emitting metadata or allowing CONNECT.
    async fn snapshot(
        &self,
        lookup: &str,
        instance: Option<&str>,
        principal: &str,
        sandbox_id: &str,
        request_deadline: tokio::time::Instant,
        connection_policy: bool,
    ) -> Result<RequestSnapshot, ResolveError> {
        let mut dependencies = self
            .client
            .dependencies(ResourceKind::SecurityProfile, Some(request_deadline));
        loop {
            if tokio::time::Instant::now() >= request_deadline {
                return Err(ResolveError::Deadline);
            }
            let workload = self
                .client
                .pin(ResourceKind::Workload, lookup, Some(request_deadline));
            let sandbox = async {
                if sandbox_id.is_empty() {
                    return Ok(None);
                }
                self.client
                    .pin(ResourceKind::Sandbox, sandbox_id, Some(request_deadline))
                    .await
                    .map(Some)
            };
            let (workload, sandbox) = tokio::try_join!(workload, sandbox)?;
            let View::Workload(source) = workload.value.as_ref() else {
                unreachable!("typed Workload watch")
            };
            if instance.is_none()
                && (source.host_network
                    || source.principal != principal
                    || source.name.is_empty()
                    || source.namespace.is_empty()
                    || source.uid
                        != format!(
                            "{}//Pod/{}/{}",
                            self.cluster_id, source.namespace, source.name
                        ))
            {
                debug!(reason = "fallback_workload_mismatch", "request denied");
                return Err(ResolveError::Denied);
            }
            if let Some(resource) = &sandbox {
                let View::Sandbox(value) = resource.value.as_ref() else {
                    unreachable!("typed Sandbox watch")
                };
                if value.uid != sandbox_id || value.workload_uid != source.uid {
                    debug!(reason = "sandbox_binding_mismatch", "request denied");
                    return Err(ResolveError::Denied);
                }
            }
            let references = if connection_policy {
                source
                    .profiles
                    .as_deref()
                    .ok_or(ResolveError::PolicyUnavailable)?
            } else {
                &[]
            };
            let names: Vec<_> = references.iter().map(|r| r.name.clone()).collect();
            let profiles = dependencies.resolve(&names).await;
            let mut keys = vec![(ResourceKind::Workload, lookup)];
            if sandbox.is_some() {
                keys.push((ResourceKind::Sandbox, sandbox_id));
            }
            let profile_offset = keys.len();
            keys.extend(
                names
                    .iter()
                    .map(|name| (ResourceKind::SecurityProfile, name.as_str())),
            );
            let captured = self.client.capture(&keys)?;
            if !captured[0]
                .as_ref()
                .is_some_and(|after| Arc::ptr_eq(&workload.value, after))
            {
                continue;
            }
            if let Some(before) = &sandbox
                && !captured[1]
                    .as_ref()
                    .is_some_and(|after| Arc::ptr_eq(&before.value, after))
            {
                continue;
            }
            let profiles = profiles?;
            if profiles.iter().enumerate().any(|(i, before)| {
                !captured[profile_offset + i]
                    .as_ref()
                    .is_some_and(|after| Arc::ptr_eq(before, after))
            }) {
                continue;
            }
            for (reference, profile) in references.iter().zip(&profiles) {
                let View::SecurityProfile(profile) = profile.as_ref() else {
                    unreachable!("typed SecurityProfile watch")
                };
                if !reference.uid.is_empty() && profile.uid != reference.uid {
                    return Err(ResolveError::PolicyUnavailable);
                }
            }
            return Ok(RequestSnapshot {
                profiles,
                workload: workload.value,
                sandbox: sandbox.map(|s| s.value),
            });
        }
    }

    async fn resolve_once(
        &self,
        request: &ResolveRequest<'_>,
        request_deadline: tokio::time::Instant,
    ) -> Result<Resolved, ResolveError> {
        let IdentityEvidence {
            certificate,
            peer_ip,
            principal,
            sandbox_id,
        } = request.identity;
        let target = request.target;
        let instance = match certificate_instance(certificate) {
            Ok(instance) => instance,
            Err(error) => {
                debug!(reason = "invalid_certificate", %error, "request denied");
                return Err(ResolveError::Denied);
            }
        };
        let lookup = if let Some(instance) = instance.as_deref() {
            Cow::Borrowed(instance)
        } else {
            let ip = match peer_ip.parse::<IpAddr>() {
                Ok(ip) if !principal.is_empty() => ip,
                _ => {
                    debug!(reason = "missing_fallback_identity", "request denied");
                    return Err(ResolveError::Denied);
                }
            };
            Cow::Owned(format!("/{}", ip.to_canonical()))
        };
        let RequestSnapshot {
            workload,
            sandbox,
            profiles,
        } = self
            .snapshot(
                &lookup,
                instance.as_deref(),
                principal,
                sandbox_id,
                request_deadline,
                target.is_some(),
            )
            .await?;
        let tcp_decision = if let Some(target) = target {
            let mut decision = None;
            // Evaluate shared profiles before the inline profile.
            for resource in &profiles {
                let View::SecurityProfile(profile) = resource.as_ref() else {
                    unreachable!("typed SecurityProfile watch")
                };
                if decision.is_none() {
                    decision = profile.tcp_policy.matches(target);
                }
            }
            if let Some(sandbox) = &sandbox {
                let View::Sandbox(value) = sandbox.as_ref() else {
                    unreachable!("typed Sandbox watch")
                };
                let profile = value
                    .profile
                    .as_ref()
                    .ok_or(ResolveError::PolicyUnavailable)?;
                if decision.is_none() {
                    decision = profile.tcp_policy.matches(target);
                }
            }
            Some(decision.unwrap_or(true))
        } else {
            None
        };
        Ok(Resolved {
            profiles,
            workload,
            sandbox,
            instance,
            tcp_decision,
        })
    }
}
