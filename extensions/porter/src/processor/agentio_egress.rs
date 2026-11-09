// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::Instant};

use tonic::Status;

use super::{
    ParsedRequest, ResolveRequest, Resolved, allowed, headers, identity, identity_metadata,
};
use crate::{
    metrics::{ConnectResult, Metrics, Protocol},
    view::{self, View},
    wire::extproc,
};

pub(super) fn parse<'a>(
    request_headers: Option<&extproc::HttpHeaders>,
    attributes: Option<&'a prost_types::Struct>,
) -> Result<ParsedRequest<'a>, Status> {
    let headers = headers(request_headers)?;
    let udp = headers.method == "GET" && headers.upgrade.eq_ignore_ascii_case("connect-udp");
    if (headers.method != "CONNECT" && !udp) || headers.authority.is_empty() {
        return Err(Status::invalid_argument(
            "unexpected method or missing request authority",
        ));
    }
    let target = if udp {
        None
    } else {
        let mut target: std::net::SocketAddr = headers
            .authority
            .parse()
            .map_err(|_| Status::invalid_argument("CONNECT target must be numeric IP:port"))?;
        if target.port() == 0 {
            return Err(Status::invalid_argument("invalid CONNECT port"));
        }
        target.set_ip(target.ip().to_canonical());
        Some(target)
    };
    Ok(ParsedRequest {
        resolution: ResolveRequest {
            identity: identity(attributes),
            target,
        },
        protocol: if udp { "udp" } else { "tcp" },
    })
}

pub(super) fn encode(
    resolved: Resolved,
    protocol: &str,
    enable_sni_traffic_policy: bool,
) -> extproc::ProcessingResponse {
    let mut metadata = identity_metadata(resolved.workload.as_ref(), resolved.instance);
    if let Some(sandbox) = &resolved.sandbox {
        let View::Sandbox(sandbox) = sandbox.as_ref() else {
            unreachable!("typed Sandbox watch")
        };
        metadata.insert(
            "sandbox".into(),
            view::object([("id".into(), view::string(&sandbox.uid))]),
        );
    }
    if let Some(allow) = resolved.tcp_decision {
        metadata.insert(
            "tcp".into(),
            view::object([(
                "original_destination_decision".into(),
                view::string(if allow { "allow" } else { "deny" }),
            )]),
        );
    }
    if enable_sni_traffic_policy && protocol == "tcp" {
        let mut rules = Vec::new();
        for profile in &resolved.profiles {
            let View::SecurityProfile(profile) = profile.as_ref() else {
                unreachable!("typed SecurityProfile watch")
            };
            rules.extend(view::project_rules(&profile.rules));
        }
        if let Some(sandbox) = &resolved.sandbox {
            let View::Sandbox(sandbox) = sandbox.as_ref() else {
                unreachable!("typed Sandbox watch")
            };
            if let Some(profile) = &sandbox.profile {
                rules.extend(view::project_rules(&profile.rules));
            }
        }
        let policy = if rules.is_empty() {
            view::object([])
        } else {
            view::object([("rules".into(), view::list(rules))])
        };
        metadata.insert("sni".into(), view::object([("policy".into(), policy)]));
    }
    allowed(metadata)
}

pub(super) struct ConnectMeasurement {
    pub metrics: Arc<Metrics>,
    pub started: Instant,
    pub protocol: &'static str,
    pub result: &'static str,
}

impl Drop for ConnectMeasurement {
    fn drop(&mut self) {
        self.metrics
            .connect_results
            .get_or_create(&ConnectResult {
                protocol: self.protocol,
                result: self.result,
            })
            .inc();
        self.metrics
            .connect
            .get_or_create(&Protocol {
                protocol: self.protocol,
            })
            .observe(self.started.elapsed().as_secs_f64());
    }
}
