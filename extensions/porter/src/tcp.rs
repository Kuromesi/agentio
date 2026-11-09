// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::wire::agentio::security::{TcpAction, TcpPolicy};
use anyhow::{Context, Result, ensure};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct Policy {
    rules: Vec<Rule>,
}
#[derive(Debug)]
struct Rule {
    allow: bool,
    clauses: Vec<Clause>,
}
#[derive(Debug)]
struct Clause {
    networks: Vec<(IpAddr, u8)>,
    ports: Vec<u32>,
}

impl Policy {
    pub fn compile(value: TcpPolicy) -> Result<Self> {
        let mut rules = Vec::new();
        for rule in value.rules {
            let action = TcpAction::try_from(rule.action)?;
            ensure!(action != TcpAction::Unspecified, "unspecified TCP action");
            ensure!(!rule.r#match.is_empty(), "TCP rule requires match");
            let mut clauses = Vec::new();
            for clause in rule.r#match {
                ensure!(
                    clause.ports.iter().all(|p| (1..=65535).contains(p)),
                    "invalid TCP port"
                );
                let mut networks = Vec::new();
                for cidr in clause.cidrs {
                    let (ip, length) = cidr.split_once('/').context("invalid CIDR")?;
                    let ip: IpAddr = ip.parse()?;
                    let length: u8 = length.parse()?;
                    ensure!(
                        length <= if ip.is_ipv4() { 32 } else { 128 },
                        "invalid prefix length"
                    );
                    ensure!(ip.to_canonical() == ip, "IPv4-mapped CIDR is unsupported");
                    networks.push((ip, length));
                }
                clauses.push(Clause {
                    networks,
                    ports: clause.ports,
                });
            }
            rules.push(Rule {
                allow: action == TcpAction::Allow,
                clauses,
            });
        }
        Ok(Self { rules })
    }

    pub fn matches(&self, target: SocketAddr) -> Option<bool> {
        for rule in &self.rules {
            if rule.clauses.iter().any(|clause| {
                (clause.ports.is_empty() || clause.ports.contains(&u32::from(target.port())))
                    && (clause.networks.is_empty()
                        || clause.networks.iter().any(|(ip, length)| {
                            match (*ip, target.ip().to_canonical()) {
                                (IpAddr::V4(a), IpAddr::V4(b)) => {
                                    let mask =
                                        u32::MAX.checked_shl(32 - u32::from(*length)).unwrap_or(0);
                                    u32::from(a) & mask == u32::from(b) & mask
                                }
                                (IpAddr::V6(a), IpAddr::V6(b)) => {
                                    let mask = u128::MAX
                                        .checked_shl(128 - u32::from(*length))
                                        .unwrap_or(0);
                                    u128::from(a) & mask == u128::from(b) & mask
                                }
                                _ => false,
                            }
                        }))
            }) {
                return Some(rule.allow);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::agentio::security::{TcpMatch, TcpRule};
    #[test]
    fn ordered_cidr_and_port_matching_and_default_allow() {
        let rules = vec![
            TcpRule {
                name: "allow".into(),
                action: TcpAction::Allow as i32,
                r#match: vec![TcpMatch {
                    cidrs: vec!["10.1.0.0/16".into()],
                    ports: vec![443],
                }],
            },
            TcpRule {
                name: "deny".into(),
                action: TcpAction::Deny as i32,
                r#match: vec![TcpMatch {
                    cidrs: vec!["10.0.0.0/8".into(), "fc00::/7".into()],
                    ports: vec![],
                }],
            },
        ];
        let policy = Policy::compile(TcpPolicy {
            rules: rules.clone(),
        })
        .unwrap();
        for (target, want) in [
            ("10.1.0.1:443", Some(true)),
            ("10.1.0.1:80", Some(false)),
            ("[fd00::1]:443", Some(false)),
            ("192.0.2.1:443", None),
            ("[::ffff:10.1.0.1]:443", Some(true)),
        ] {
            assert_eq!(policy.matches(target.parse().unwrap()), want, "{target}");
        }
        assert_eq!(
            Policy::compile(TcpPolicy::default())
                .unwrap()
                .matches("192.0.2.1:443".parse().unwrap()),
            None
        );
        for cidr in ["invalid", "10.0.0.0/33", "::ffff:10.0.0.0/120"] {
            let mut bad = rules.clone();
            bad[0].r#match[0].cidrs = vec![cidr.into()];
            assert!(Policy::compile(TcpPolicy { rules: bad }).is_err());
        }
    }
}
