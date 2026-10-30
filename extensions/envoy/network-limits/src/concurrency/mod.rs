// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::descriptor::{self, Entry, Key, MatchDescriptor, RateLimit};
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, HttpFilter, HttpFilterConfig,
    abi::envoy_dynamic_module_type_on_http_filter_request_headers_status as Headers,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroU32,
    sync::{Arc, Mutex, OnceLock},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default = "descriptor::default_budget_name")]
    budget_name: String,
    rate_limits: Vec<RateLimit>,
    descriptors: Vec<Descriptor>,
    #[serde(default = "descriptor::default_capacity")]
    max_dynamic_buckets: usize,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    entries: Vec<Entry>,
    max_concurrent_streams: NonZeroU32,
}

impl MatchDescriptor for Descriptor {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

impl Config {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let config: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if config.budget_name.is_empty() || config.max_dynamic_buckets == 0 {
            return Err("budget_name and capacity must be nonempty/positive".into());
        }
        descriptor::validate_groups(&config.rate_limits, &config.descriptors)?;
        Ok(config)
    }
}

struct Ledger {
    config: Config,
    active: HashMap<Key, u32>,
    dynamic_buckets: usize,
    registrations: BTreeMap<u64, Config>,
    next_registration: u64,
}

#[derive(Debug, PartialEq)]
enum Rejection {
    Limit,
    Capacity,
}

impl Ledger {
    fn acquire(&mut self, keys: &[Key]) -> Result<(), Rejection> {
        let mut new_dynamic = 0;
        for key in keys {
            let descriptor = &self.config.descriptors[key.0];
            if self.active.get(key).copied().unwrap_or(0) >= descriptor.max_concurrent_streams.get()
            {
                return Err(Rejection::Limit);
            }
            if descriptor.dynamic() && !self.active.contains_key(key) {
                new_dynamic += 1;
            }
        }
        // A capacity decrease must not prevent admission to existing counters.
        if new_dynamic > 0 && self.dynamic_buckets + new_dynamic > self.config.max_dynamic_buckets {
            return Err(Rejection::Capacity);
        }
        for key in keys {
            *self.active.entry(key.clone()).or_default() += 1;
        }
        self.dynamic_buckets += new_dynamic;
        Ok(())
    }

    fn release(&mut self, keys: &[Key]) {
        for key in keys {
            let count = self.active.get_mut(key).unwrap();
            *count -= 1;
            if *count == 0 {
                self.active.remove(key);
                if self.config.descriptors[key.0].dynamic() {
                    self.dynamic_buckets -= 1;
                }
            }
        }
    }
}

struct Registration {
    ledger: Arc<Mutex<Ledger>>,
    id: u64,
}

impl Registration {
    fn shared(config: Config) -> Result<Arc<Self>, String> {
        static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<Mutex<Ledger>>>>> = OnceLock::new();
        let mut registry = REGISTRY.get_or_init(Mutex::default).lock().unwrap();
        registry.retain(|_, ledger| Arc::strong_count(ledger) > 1);
        let ledger = registry
            .entry(config.budget_name.clone())
            .or_insert_with(|| {
                Arc::new(Mutex::new(Ledger {
                    config: config.clone(),
                    active: HashMap::new(),
                    dynamic_buckets: 0,
                    registrations: BTreeMap::new(),
                    next_registration: 0,
                }))
            })
            .clone();
        let mut state = ledger.lock().unwrap();
        if !descriptor::same_layout(
            &config.rate_limits,
            &config.descriptors,
            &state.config.rate_limits,
            &state.config.descriptors,
        ) {
            return Err("concurrency grouping is still in use; drain it before changing actions or descriptor entries".into());
        }
        state.next_registration += 1;
        let id = state.next_registration;
        state.registrations.insert(id, config.clone());
        state.config = config;
        drop(state);
        Ok(Arc::new(Self { ledger, id }))
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut ledger = self.ledger.lock().unwrap();
        ledger.registrations.remove(&self.id);
        if let Some((_, config)) = ledger.registrations.last_key_value() {
            ledger.config = config.clone();
        }
    }
}

pub struct FilterConfig {
    registration: Arc<Registration>,
}

impl FilterConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self {
            registration: Registration::shared(Config::parse(bytes)?)?,
        })
    }
}

impl<E: EnvoyHttpFilter> HttpFilterConfig<E> for FilterConfig {
    fn new_http_filter(&self, _: &mut E) -> Box<dyn HttpFilter<E>> {
        Box::new(Filter {
            registration: self.registration.clone(),
            keys: Vec::new(),
        })
    }
}

struct Filter {
    registration: Arc<Registration>,
    keys: Vec<Key>,
}

impl<E: EnvoyHttpFilter> HttpFilter<E> for Filter {
    fn on_request_headers(&mut self, envoy: &mut E, _: bool) -> Headers {
        let result = {
            let mut ledger = self.registration.ledger.lock().unwrap();
            match descriptor::resolve(
                &ledger.config.rate_limits,
                &ledger.config.descriptors,
                |key| {
                    envoy
                        .get_filter_state_bytes(key.as_bytes())
                        .and_then(|value| {
                            std::str::from_utf8(value.as_slice())
                                .ok()
                                .map(str::to_owned)
                        })
                },
            ) {
                Err(()) => Err((403, "concurrency_missing_key")),
                Ok(keys) => match ledger.acquire(&keys) {
                    Ok(()) => {
                        self.keys = keys;
                        Ok(())
                    }
                    Err(Rejection::Limit) => Err((429, "concurrency_limit_exceeded")),
                    Err(Rejection::Capacity) => Err((503, "concurrency_capacity")),
                },
            }
        };
        if let Err((status, detail)) = result {
            // Local replies can synchronously destroy the filter; release the lock first.
            envoy.send_response(status, &[], Some(detail.as_bytes()), Some(detail));
            return Headers::StopIteration;
        }
        Headers::Continue
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        self.registration.ledger.lock().unwrap().release(&self.keys);
    }
}

#[cfg(test)]
mod tests;
