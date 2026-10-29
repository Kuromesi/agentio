// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use super::config::Config;
use crate::descriptor::Key;
use envoy_proxy_dynamic_modules_rust_sdk::EnvoyHttpFilterScheduler;
use std::{
    collections::{BTreeMap, HashMap},
    num::NonZeroU64,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

pub struct Ledger {
    pub config: Config,
    buckets: HashMap<Key, Bucket>,
    registrations: BTreeMap<u64, Config>,
    next_registration: u64,
    pub waiters: HashMap<u64, Arc<dyn EnvoyHttpFilterScheduler>>,
}

struct Bucket {
    users: usize,
    ready: [Instant; 2],
    debt_rates: [Option<NonZeroU64>; 2],
}

pub struct Budget {
    pub ledger: Mutex<Ledger>,
}

// The newest live Envoy configuration supplies rates. Dropping a rejected
// candidate restores the preceding configuration without replacing its buckets.
pub struct Registration {
    pub budget: Arc<Budget>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut ledger = self.budget.ledger.lock().unwrap();
        ledger.registrations.remove(&self.id);
        if let Some((_, config)) = ledger.registrations.last_key_value() {
            let config = config.clone();
            ledger.update(config, Instant::now());
        }
    }
}

impl Budget {
    pub fn shared(config: Config) -> Result<Registration, String> {
        static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<Budget>>>> = OnceLock::new();
        let mut registry = REGISTRY.get_or_init(Mutex::default).lock().unwrap();
        let now = Instant::now();
        registry.retain(|_, budget| {
            Arc::strong_count(budget) > 1 || !budget.ledger.lock().unwrap().idle(now)
        });
        let budget = registry
            .entry(config.budget_name.clone())
            .or_insert_with(|| {
                Arc::new(Self {
                    ledger: Mutex::new(Ledger::new(config.clone())),
                })
            })
            .clone();
        let mut ledger = budget.ledger.lock().unwrap();
        if !ledger.config.same_layout(&config) {
            return Err("bandwidth grouping is still in use; drain it before changing actions or descriptor entries".into());
        }
        ledger.next_registration += 1;
        let id = ledger.next_registration;
        ledger.registrations.insert(id, config.clone());
        ledger.update(config, now);
        drop(ledger);
        Ok(Registration { budget, id })
    }
}

impl Ledger {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            buckets: HashMap::new(),
            registrations: BTreeMap::new(),
            next_registration: 0,
            waiters: HashMap::new(),
        }
    }

    fn idle(&self, now: Instant) -> bool {
        self.buckets
            .values()
            .all(|b| b.users == 0 && b.ready.iter().all(|t| *t <= now))
    }

    fn update(&mut self, config: Config, now: Instant) {
        let changed = self.config.descriptors != config.descriptors;
        if changed {
            for (key, bucket) in &mut self.buckets {
                let new = &config.descriptors[key.0].bandwidth_limit;
                for (direction, new) in [new.upload_bytes_per_second, new.download_bytes_per_second]
                    .into_iter()
                    .enumerate()
                {
                    // Preserve existing debt while unlimited, including across candidate rollback.
                    let old = bucket.debt_rates[direction];
                    if new.is_some() && old != new {
                        let remaining = bucket.ready[direction].saturating_duration_since(now);
                        let delay = match (old, new) {
                            (Some(old), Some(new)) => {
                                let nanos = (remaining.as_nanos() * old.get() as u128)
                                    .div_ceil(new.get() as u128);
                                Duration::new(
                                    (nanos / 1_000_000_000) as u64,
                                    (nanos % 1_000_000_000) as u32,
                                )
                            }
                            _ => Duration::ZERO,
                        };
                        bucket.ready[direction] = now + delay;
                        bucket.debt_rates[direction] = new;
                    }
                }
            }
        }
        self.config = config;
        if changed {
            // Drop removes waiters under this lock, quiescing posts before worker teardown.
            for scheduler in self.waiters.values() {
                scheduler.commit(0);
            }
        }
    }

    pub fn acquire(&mut self, keys: &[Key], now: Instant) -> Result<(), ()> {
        let needed = keys
            .iter()
            .filter(|k| self.config.descriptors[k.0].dynamic() && !self.buckets.contains_key(*k))
            .count();
        if needed > 0 {
            // Retain unpaid debt after the last stream closes: reconnecting must not refill a bucket.
            self.buckets
                .retain(|_, b| b.users > 0 || b.ready.iter().any(|t| *t > now));
            let needed = keys
                .iter()
                .filter(|k| {
                    self.config.descriptors[k.0].dynamic() && !self.buckets.contains_key(*k)
                })
                .count();
            let dynamic = self
                .buckets
                .keys()
                .filter(|k| self.config.descriptors[k.0].dynamic())
                .count();
            if dynamic + needed > self.config.max_dynamic_buckets {
                return Err(());
            }
        }
        for key in keys {
            self.buckets
                .entry(key.clone())
                .or_insert(Bucket {
                    users: 0,
                    ready: [now; 2],
                    debt_rates: [None; 2],
                })
                .users += 1;
        }
        Ok(())
    }

    pub fn release(&mut self, keys: &[Key]) {
        for key in keys {
            self.buckets.get_mut(key).unwrap().users -= 1;
        }
    }

    pub fn charge(
        &mut self,
        keys: &[Key],
        direction: usize,
        bytes: usize,
        now: Instant,
    ) -> Option<Instant> {
        if bytes == 0 {
            return None;
        }
        let rate = |key: &Key| {
            let limit = &self.config.descriptors[key.0].bandwidth_limit;
            if direction == 0 {
                limit.upload_bytes_per_second
            } else {
                limit.download_bytes_per_second
            }
        };
        let due = keys
            .iter()
            .filter(|k| rate(k).is_some())
            .map(|k| self.buckets[k].ready[direction])
            .max();
        if let Some(due) = due.filter(|t| *t > now) {
            return Some(due);
        }
        // Check all budgets before charging any; a tenant and its sandbox must commit together.
        // shortcut: pacing permits one callback-sized burst; strict burst caps need partial injection.
        for key in keys {
            if let Some(rate) = rate(key) {
                let bucket = self.buckets.get_mut(key).unwrap();
                bucket.debt_rates[direction] = Some(rate);
                let bytes = bytes as u64;
                let rate = rate.get();
                let delay = Duration::from_secs(bytes / rate)
                    + Duration::from_nanos(
                        ((bytes % rate) as u128 * 1_000_000_000).div_ceil(rate as u128) as u64,
                    );
                bucket.ready[direction] = now + delay;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_proxy_dynamic_modules_rust_sdk::MockEnvoyHttpFilterScheduler;

    #[test]
    fn rate_updates_preserve_unpaid_bytes_and_wake_waiters() {
        let mut config = Config::parse(br#"{"rate_limits":[{"actions":[{"filter_state":{"key":"id","descriptor_key":"id"}}]}],
            "descriptors":[{"entries":[{"key":"id"}],"bandwidth_limit":{"upload_bytes_per_second":100,"download_bytes_per_second":200}}]}"#).unwrap();
        let keys = config.resolve(|_| Some("a".into())).unwrap();
        let mut ledger = Ledger::new(config.clone());
        let now = Instant::now();
        ledger.acquire(&keys, now).unwrap();
        ledger.charge(&keys, 0, 1000, now);
        ledger.charge(&keys, 1, 2000, now);
        let mut scheduler = MockEnvoyHttpFilterScheduler::new();
        scheduler.expect_commit().times(4).return_const(());
        ledger.waiters.insert(1, Arc::new(scheduler));

        config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second = Some(200.try_into().unwrap());
        ledger.update(config.clone(), now + Duration::from_secs(2));
        assert_eq!(
            ledger.charge(&keys, 0, 1, now + Duration::from_secs(2)),
            Some(now + Duration::from_secs(6))
        );
        assert_eq!(
            ledger.charge(&keys, 1, 1, now + Duration::from_secs(2)),
            Some(now + Duration::from_secs(10))
        );
        config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second = Some(50.try_into().unwrap());
        ledger.update(config.clone(), now + Duration::from_secs(3));
        assert_eq!(
            ledger.charge(&keys, 0, 1, now + Duration::from_secs(3)),
            Some(now + Duration::from_secs(15))
        );
        config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second = None;
        ledger.update(config.clone(), now + Duration::from_secs(4));
        assert_eq!(
            ledger.charge(&keys, 0, 100, now + Duration::from_secs(4)),
            None
        );
        config.descriptors[0]
            .bandwidth_limit
            .upload_bytes_per_second = Some(50.try_into().unwrap());
        ledger.update(config, now + Duration::from_secs(5));
        assert_eq!(
            ledger.charge(&keys, 0, 1, now + Duration::from_secs(5)),
            Some(now + Duration::from_secs(15))
        );
    }
}
