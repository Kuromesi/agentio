// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use envoy_proxy_dynamic_modules_rust_sdk::{EnvoyBuffer, MockEnvoyHttpFilter};

const CONFIG: &str = r#"{
  "rate_limits":[
    {"actions":[{"filter_state":{"key":"sandbox.id","descriptor_key":"sandbox"}}]},
    {"actions":[{"generic_key":{"descriptor_key":"scope","descriptor_value":"gateway"}}]},
    {"actions":[{"filter_state":{"key":"sandbox.id","descriptor_key":"sandbox"}}]}
  ],
  "descriptors":[
    {"entries":[{"key":"sandbox"}],"max_concurrent_streams":2},
    {"entries":[{"key":"scope","value":"gateway"}],"max_concurrent_streams":3},
    {"entries":[{"key":"sandbox","value":"vip"}],"max_concurrent_streams":3}
  ]
}"#;

fn config(name: &str) -> Config {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.budget_name = name.into();
    config
}

fn keys(config: &Config, value: &str) -> Vec<Key> {
    descriptor::resolve(&config.rate_limits, &config.descriptors, |_| {
        Some(value.into())
    })
    .unwrap()
}

#[test]
fn atomic_admission_exact_precedence_and_release() {
    let config = config("atomic-admission");
    let a = keys(&config, "a");
    let b = keys(&config, "b");
    assert_eq!(a.len(), 2); // Repeated matching groups consume one slot.
    assert_eq!(keys(&config, "vip")[0].0, 2);
    let registration = Registration::shared(config).unwrap();
    let mut ledger = registration.ledger.lock().unwrap();
    ledger.acquire(&a).unwrap();
    ledger.acquire(&a).unwrap();
    assert_eq!(ledger.acquire(&a), Err(Rejection::Limit));
    ledger.acquire(&b).unwrap();
    assert_eq!(ledger.acquire(&b), Err(Rejection::Limit));
    assert_eq!(ledger.active[&b[0]], 1); // Rejection by global limit did not take a sandbox slot.
    ledger.release(&a);
    ledger.acquire(&b).unwrap();
    ledger.release(&a);
    ledger.release(&b);
    ledger.release(&b);
    assert!(ledger.active.is_empty());
    assert_eq!(ledger.dynamic_buckets, 0);
}

#[test]
fn capacity_retains_active_keys_and_reclaims_closed_keys() {
    let mut config = config("concurrency-capacity");
    config.max_dynamic_buckets = 1;
    let a = keys(&config, "a");
    let b = keys(&config, "b");
    let registration = Registration::shared(config).unwrap();
    let mut ledger = registration.ledger.lock().unwrap();
    ledger.acquire(&a).unwrap();
    assert_eq!(ledger.acquire(&b), Err(Rejection::Capacity));
    ledger.acquire(&a).unwrap();
    ledger.release(&a);
    ledger.release(&a);
    ledger.acquire(&b).unwrap();
    ledger.release(&b);
}

#[test]
fn concurrent_workers_share_a_strict_limit() {
    let config = config("concurrency-workers");
    let keys = keys(&config, "a");
    let registration = Registration::shared(config).unwrap();
    let workers: Vec<_> = (0..32)
        .map(|_| {
            let registration = registration.clone();
            let keys = keys.clone();
            std::thread::spawn(move || registration.ledger.lock().unwrap().acquire(&keys).is_ok())
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        2
    );
    let mut ledger = registration.ledger.lock().unwrap();
    ledger.release(&keys);
    ledger.release(&keys);
}

#[test]
fn reload_preserves_counts_and_rejected_candidate_restores_limits() {
    let mut config = config("concurrency-reload");
    let keys = keys(&config, "a");
    let original = Registration::shared(config.clone()).unwrap();
    original.ledger.lock().unwrap().acquire(&keys).unwrap();
    config.descriptors[0].max_concurrent_streams = NonZeroU32::new(1).unwrap();
    let candidate = Registration::shared(config.clone()).unwrap();
    assert!(Arc::ptr_eq(&original.ledger, &candidate.ledger));
    assert_eq!(
        candidate.ledger.lock().unwrap().acquire(&keys),
        Err(Rejection::Limit)
    );
    drop(candidate);
    original.ledger.lock().unwrap().acquire(&keys).unwrap();
    config.descriptors[0].max_concurrent_streams = NonZeroU32::new(3).unwrap();
    let raised = Registration::shared(config.clone()).unwrap();
    raised.ledger.lock().unwrap().acquire(&keys).unwrap();
    config.rate_limits[0].actions.clear();
    assert!(Registration::shared(config).is_err());
    let mut ledger = original.ledger.lock().unwrap();
    for _ in 0..3 {
        ledger.release(&keys);
    }
}

#[test]
fn filter_drop_releases_once_and_body_end_does_not_release() {
    let registration = Registration::shared(config("concurrency-lifecycle")).unwrap();
    let mut filter = Filter {
        registration: registration.clone(),
        keys: Vec::new(),
    };
    let mut envoy = MockEnvoyHttpFilter::new();
    envoy
        .expect_get_filter_state_bytes()
        .returning(|_| Some(EnvoyBuffer::new(b"a")));
    assert_eq!(
        filter.on_request_headers(&mut envoy, false),
        Headers::Continue
    );
    filter.on_request_body(&mut envoy, true);
    filter.on_response_headers(&mut envoy, false);
    let keys = filter.keys.clone();
    assert_eq!(registration.ledger.lock().unwrap().active[&keys[0]], 1);
    drop(filter);
    assert!(registration.ledger.lock().unwrap().active.is_empty());

    let mut rejected = Filter {
        registration: registration.clone(),
        keys: Vec::new(),
    };
    let mut missing = MockEnvoyHttpFilter::new();
    missing.expect_get_filter_state_bytes().returning(|_| None);
    let observed = registration.clone();
    missing
        .expect_send_response()
        .times(1)
        .returning(move |status, _, _, detail| {
            assert_eq!(status, 403);
            assert_eq!(detail, Some("concurrency_missing_key"));
            assert!(observed.ledger.try_lock().is_ok());
        });
    assert_eq!(
        rejected.on_request_headers(&mut missing, false),
        Headers::StopIteration
    );
    drop(rejected);
    assert!(registration.ledger.lock().unwrap().active.is_empty());
}

#[test]
fn invalid_limits_and_grouping_are_rejected() {
    for invalid in [
        CONFIG.replace(
            "\"max_concurrent_streams\":2",
            "\"max_concurrent_streams\":0",
        ),
        CONFIG.replace(
            "\"max_concurrent_streams\":2",
            "\"max_concurrent_streams\":4294967296",
        ),
        CONFIG.replace("\"sandbox.id\"", "\"\""),
        CONFIG.replace(
            "\"rate_limits\":",
            "\"max_dynamic_buckets\":0,\"rate_limits\":",
        ),
        CONFIG.replace(
            "\"rate_limits\":",
            "\"buffer_limit_bytes\":1,\"rate_limits\":",
        ),
        "{}".into(),
    ] {
        assert!(Config::parse(invalid.as_bytes()).is_err(), "{invalid}");
    }
}
