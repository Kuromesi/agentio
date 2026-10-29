// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::budget::Ledger;
use super::*;
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyBuffer, MockEnvoyHttpFilter, MockEnvoyHttpFilterScheduler,
};
use std::{sync::Mutex, time::Duration};

const CONFIG: &str = r#"{
  "rate_limits":[{"actions":[
    {"filter_state":{"key":"tenant.id","descriptor_key":"tenant"}},
    {"filter_state":{"key":"sandbox.id","descriptor_key":"sandbox"}}
  ]}],
  "descriptors":[
    {"entries":[{"key":"tenant"},{"key":"sandbox"}],"bandwidth_limit":{"upload_bytes_per_second":100,"download_bytes_per_second":200}},
    {"entries":[{"key":"tenant","value":"vip"},{"key":"sandbox","value":"one"}],"bandwidth_limit":{"download_bytes_per_second":1000}}
  ]
}"#;

fn keys(config: &Config, tenant: &str, sandbox: &str) -> Vec<Key> {
    config
        .resolve(|k| Some(if k == "tenant.id" { tenant } else { sandbox }.into()))
        .unwrap()
}

#[test]
fn descriptors_are_ordered_combined_keys_with_exact_precedence() {
    let config = Config::parse(CONFIG.as_bytes()).unwrap();
    assert_eq!(keys(&config, "vip", "one")[0].0, 1);
    assert_eq!(keys(&config, "vip", "two")[0].0, 0);
    assert_ne!(keys(&config, "a", "one"), keys(&config, "b", "one"));
    assert_ne!(keys(&config, "a", "one"), keys(&config, "a", "two"));
    assert!(config.resolve(|_| None).is_err());
    assert!(config.resolve(|_| Some(String::new())).is_err());
    let mut config = config;
    config.descriptors.remove(0);
    assert!(keys(&config, "a", "one").is_empty());
}

#[test]
fn invalid_configuration_fails_at_the_boundary() {
    for invalid in [
        CONFIG.replace(
            "\"upload_bytes_per_second\":100",
            "\"upload_bytes_per_second\":0",
        ),
        CONFIG.replace("\"key\":\"sandbox\"", "\"key\":\"unknown\""),
        CONFIG.replace("\"sandbox.id\"", "\"\""),
        CONFIG.replace("\"rate_limits\":", "\"typo\":"),
        CONFIG.replace(
            "\"rate_limits\":",
            "\"buffer_limit_bytes\":0,\"rate_limits\":",
        ),
        CONFIG.replace(
            "\"rate_limits\":",
            "\"max_dynamic_buckets\":0,\"rate_limits\":",
        ),
        "{}".into(),
    ] {
        assert!(Config::parse(invalid.as_bytes()).is_err(), "{invalid}");
    }
}

#[test]
fn shared_byte_budget_survives_reconnect_and_is_directional() {
    let config = Config::parse(CONFIG.as_bytes()).unwrap();
    let key = keys(&config, "a", "one");
    let other = keys(&config, "a", "two");
    let mut ledger = Ledger::new(config.clone());
    let now = Instant::now();
    ledger.acquire(&key, now).unwrap();
    ledger.acquire(&key, now).unwrap();
    ledger.acquire(&other, now).unwrap();
    assert_eq!(ledger.charge(&key, 0, 1000, now), None);
    assert_eq!(
        ledger.charge(&key, 0, 1, now),
        Some(now + Duration::from_secs(10))
    );
    assert_eq!(ledger.charge(&key, 1, 200, now), None);
    assert_eq!(ledger.charge(&other, 0, 100, now), None);
    ledger.release(&key, now);
    ledger.release(&key, now);
    ledger.acquire(&key, now).unwrap();
    assert_eq!(
        ledger.charge(&key, 0, 1, now),
        Some(now + Duration::from_secs(10))
    );
    assert_eq!(
        ledger.charge(&key, 0, 100, now + Duration::from_secs(10)),
        None
    );
}

#[test]
fn capacity_retains_live_and_unpaid_buckets() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.max_dynamic_buckets = 1;
    let first = keys(&config, "a", "one");
    let next = keys(&config, "a", "two");
    let exact = keys(&config, "vip", "one");
    let now = Instant::now();
    let mut ledger = Ledger::new(config.clone());
    ledger.acquire(&first, now).unwrap();
    ledger.acquire(&exact, now).unwrap();
    ledger.release(&exact, now);
    assert!(ledger.acquire(&next, now).is_err());
    ledger.acquire(&exact, now).unwrap();
    ledger.charge(&exact, 1, 100, now);
    ledger.release(&exact, now);
    ledger.reap(now + Duration::from_millis(100));
    assert!(
        ledger
            .acquire(&next, now + Duration::from_millis(100))
            .is_err()
    );
    ledger.charge(&first, 0, 100, now);
    ledger.release(&first, now);
    assert!(ledger.acquire(&next, now).is_err());
    ledger.acquire(&next, now + Duration::from_secs(1)).unwrap();
}

#[test]
fn multiple_descriptors_charge_atomically_and_deduplicate() {
    let json = r#"{"rate_limits":[
      {"actions":[{"filter_state":{"key":"tenant.id","descriptor_key":"tenant"}}]},
      {"actions":[{"filter_state":{"key":"sandbox.id","descriptor_key":"sandbox"}}]},
      {"actions":[{"filter_state":{"key":"tenant.id","descriptor_key":"tenant"}}]}
    ],"descriptors":[
      {"entries":[{"key":"tenant"}],"bandwidth_limit":{"upload_bytes_per_second":1000}},
      {"entries":[{"key":"sandbox"}],"bandwidth_limit":{"upload_bytes_per_second":100}}
    ]}"#;
    let config = Config::parse(json.as_bytes()).unwrap();
    let keys = keys(&config, "a", "one");
    assert_eq!(keys.len(), 2);
    let mut ledger = Ledger::new(config.clone());
    let now = Instant::now();
    ledger.acquire(&keys, now).unwrap();
    ledger.charge(&keys, 0, 100, now);
    assert_eq!(
        ledger.charge(&keys, 0, 1000, now + Duration::from_millis(500)),
        Some(now + Duration::from_secs(1))
    );
    assert_eq!(
        ledger.charge(&keys[..1], 0, 1, now + Duration::from_millis(500)),
        None
    );
}

#[test]
fn workers_cannot_multiply_the_budget() {
    let config = Arc::new(Config::parse(CONFIG.as_bytes()).unwrap());
    let keys = keys(&config, "a", "one");
    let now = Instant::now();
    let ledger = Arc::new(Mutex::new(Ledger::new((*config).clone())));
    ledger.lock().unwrap().acquire(&keys, now).unwrap();
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let (keys, ledger) = (keys.clone(), ledger.clone());
            std::thread::spawn(move || ledger.lock().unwrap().charge(&keys, 0, 100, now).is_none())
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

#[test]
fn reload_reuses_budget_and_rejects_conflicting_grouping() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.budget_name = "reload-test".into();
    let first = Budget::shared(config.clone()).unwrap();
    config.buffer_limit_bytes *= 2;
    let second = Budget::shared(config.clone()).unwrap();
    assert!(Arc::ptr_eq(&first.budget, &second.budget));
    config.max_dynamic_buckets += 1;
    assert!(Budget::shared(config.clone()).is_ok());
    config.rate_limits[0].actions.reverse();
    assert!(Budget::shared(config).is_err());
}

#[test]
fn rejected_candidate_restores_previous_rates_without_replacing_buckets() {
    let mut config = Config::parse(CONFIG.as_bytes()).unwrap();
    config.budget_name = "rollback-test".into();
    let first = Budget::shared(config.clone()).unwrap();
    let key = keys(&config, "a", "one");
    let now = Instant::now();
    let mut ledger = first.budget.ledger.lock().unwrap();
    ledger.acquire(&key, now).unwrap();
    ledger.charge(&key, 0, 1000, now);
    drop(ledger);
    config.descriptors[0]
        .bandwidth_limit
        .upload_bytes_per_second = Some(200.try_into().unwrap());
    let candidate = Budget::shared(config).unwrap();
    assert!(Arc::ptr_eq(&first.budget, &candidate.budget));
    assert_eq!(
        first.budget.ledger.lock().unwrap().config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second
            .unwrap()
            .get(),
        200
    );
    drop(candidate);
    let mut ledger = first.budget.ledger.lock().unwrap();
    assert_eq!(
        ledger.config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second
            .unwrap()
            .get(),
        100
    );
    assert!(ledger.charge(&key, 0, 1, Instant::now()).is_some());
    ledger.release(&key, Instant::now());
}

#[test]
fn protojson_rates_accept_uint64_strings_and_reject_zero() {
    let config = CONFIG.replace(
        "\"upload_bytes_per_second\":100",
        "\"upload_bytes_per_second\":\"100\"",
    );
    assert_eq!(
        Config::parse(config.as_bytes()).unwrap().descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second
            .unwrap()
            .get(),
        100
    );
    assert!(Config::parse(config.replace("\"100\"", "\"0\"").as_bytes()).is_err());
}

fn filter() -> Filter {
    let budget = Arc::new(Budget::new(Config::parse(CONFIG.as_bytes()).unwrap()).unwrap());
    let timer = budget.timer.clone();
    Filter {
        budget,
        id: timer.id(),
        timer,
        scheduler: Arc::new(MockEnvoyHttpFilterScheduler::new()),
        buffer_limit: 65536,
        keys: Vec::new(),
        waiting: [None; 2],
    }
}

#[test]
fn callbacks_count_buffered_bytes_once_and_stop_trailers() {
    let mut filter = filter();
    let mut envoy = MockEnvoyHttpFilter::new();
    envoy.expect_get_request_header_value().returning(|_| None);
    envoy
        .expect_get_filter_state_bytes()
        .returning(|_| Some(EnvoyBuffer::new(b"a")));
    envoy
        .expect_set_buffer_limit()
        .withf(|n| *n == 65536)
        .times(1)
        .return_const(());
    assert_eq!(
        filter.on_request_headers(&mut envoy, false),
        Headers::Continue
    );
    // An earlier filter may deliver the filter-manager buffer itself.
    envoy
        .expect_get_received_request_body_size()
        .return_const(10000usize);
    envoy
        .expect_received_buffered_request_body()
        .return_const(true);
    assert_eq!(
        filter.on_request_body(&mut envoy, false),
        RequestBody::Continue
    );
    assert_eq!(
        filter.on_request_body(&mut envoy, true),
        RequestBody::StopIterationAndWatermark
    );
    assert_eq!(
        filter.on_request_trailers(&mut envoy),
        RequestTrailers::StopIteration
    );
    assert_eq!(
        filter.on_response_trailers(&mut envoy),
        ResponseTrailers::Continue
    );
}

#[test]
fn missing_identity_rejects_and_local_response_is_not_charged() {
    let mut filter = filter();
    let mut envoy = MockEnvoyHttpFilter::new();
    envoy.expect_get_request_header_value().returning(|_| None);
    envoy.expect_get_filter_state_bytes().returning(|_| None);
    envoy
        .expect_send_response()
        .withf(|status, _, _, details| *status == 403 && *details == Some("bandwidth_missing_key"))
        .times(1)
        .return_const(());
    assert_eq!(
        filter.on_request_headers(&mut envoy, false),
        Headers::StopIteration
    );
    assert_eq!(
        filter.on_response_body(&mut envoy, true),
        ResponseBody::Continue
    );
}

#[test]
fn retry_headers_are_rejected_before_acquiring_a_budget() {
    for header in ["x-envoy-retry-on", "x-envoy-retry-grpc-on"] {
        let mut filter = filter();
        let mut envoy = MockEnvoyHttpFilter::new();
        envoy
            .expect_get_request_header_value()
            .returning(move |key| (key == header).then(|| EnvoyBuffer::new(b"unavailable")));
        envoy
            .expect_send_response()
            .withf(|status, _, _, details| {
                *status == 400 && *details == Some("bandwidth_retry_unsupported")
            })
            .times(1)
            .return_const(());
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            Headers::StopIteration
        );
        assert!(filter.keys.is_empty());
    }
}

#[test]
fn scheduled_resume_returns_before_touching_the_other_direction() {
    let mut filter = filter();
    let now = Instant::now();
    let keys = keys(&filter.budget.ledger.lock().unwrap().config, "a", "one");
    filter
        .budget
        .ledger
        .lock()
        .unwrap()
        .acquire(&keys, now)
        .unwrap();
    filter.keys = keys;
    // Future deadlines keep the real timer from racing this manually delivered event.
    filter.waiting = [Some(now + Duration::from_secs(60)); 2];

    let mut request = MockEnvoyHttpFilter::new();
    request
        .expect_get_buffered_request_body_size()
        .times(1)
        .return_const(100usize);
    request.expect_continue_decoding().times(1).return_const(());
    // No further Envoy calls are allowed: continue_decoding may have destroyed the filter.
    filter.on_scheduled(&mut request, 0);
    assert!(filter.waiting[0].is_none());
    assert!(filter.waiting[1].is_some());
    assert!(
        filter
            .budget
            .ledger
            .lock()
            .unwrap()
            .waiters
            .contains_key(&filter.id)
    );

    // If the stream survived, its next scheduled event must still resume the response.
    let mut response = MockEnvoyHttpFilter::new();
    response
        .expect_get_buffered_response_body_size()
        .times(1)
        .return_const(200usize);
    response
        .expect_continue_encoding()
        .times(1)
        .return_const(());
    filter.on_scheduled(&mut response, 0);
    assert_eq!(filter.waiting, [None; 2]);
    assert!(
        !filter
            .budget
            .ledger
            .lock()
            .unwrap()
            .waiters
            .contains_key(&filter.id)
    );
}
