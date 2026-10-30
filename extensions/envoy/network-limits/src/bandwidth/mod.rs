// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

mod budget;
mod config;
mod timer;

use crate::descriptor::Key;
use budget::{Budget, Registration};
use config::Config;
use envoy_proxy_dynamic_modules_rust_sdk::{
    EnvoyHttpFilter, EnvoyHttpFilterScheduler, HttpFilter, HttpFilterConfig,
    abi::{
        envoy_dynamic_module_type_on_http_filter_request_body_status as RequestBody,
        envoy_dynamic_module_type_on_http_filter_request_headers_status as Headers,
        envoy_dynamic_module_type_on_http_filter_request_trailers_status as RequestTrailers,
        envoy_dynamic_module_type_on_http_filter_response_body_status as ResponseBody,
        envoy_dynamic_module_type_on_http_filter_response_trailers_status as ResponseTrailers,
    },
};
use std::{sync::Arc, time::Instant};
use timer::Timer;

pub struct FilterConfig {
    registration: Registration,
    timer: Arc<Timer>,
    buffer_limit: u32,
}

impl FilterConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let config = Config::parse(bytes)?;
        let buffer_limit = config.buffer_limit_bytes;
        let registration = Budget::shared(config)?;
        let timer = registration.budget.timer.clone();
        Ok(Self {
            registration,
            timer,
            buffer_limit,
        })
    }
}

impl<E: EnvoyHttpFilter> HttpFilterConfig<E> for FilterConfig {
    fn new_http_filter(&self, envoy: &mut E) -> Box<dyn HttpFilter<E>> {
        Box::new(Filter {
            budget: self.registration.budget.clone(),
            timer: self.timer.clone(),
            id: self.timer.id(),
            scheduler: Arc::new(envoy.new_scheduler()),
            buffer_limit: self.buffer_limit,
            keys: Vec::new(),
            waiting: [None; 2],
        })
    }
}

struct Filter {
    budget: Arc<Budget>,
    timer: Arc<Timer>,
    id: u64,
    scheduler: Arc<dyn EnvoyHttpFilterScheduler>,
    buffer_limit: u32,
    keys: Vec<Key>,
    waiting: [Option<Instant>; 2],
}

impl Filter {
    fn charge(&mut self, direction: usize, bytes: usize) -> bool {
        let mut ledger = self.budget.ledger.lock().unwrap();
        self.waiting[direction] = ledger.charge(&self.keys, direction, bytes, Instant::now());
        if self.waiting.iter().any(Option::is_some) {
            ledger.waiters.insert(self.id, self.scheduler.clone());
        } else {
            ledger.waiters.remove(&self.id);
        }
        drop(ledger);
        self.arm();
        self.waiting[direction].is_none()
    }

    fn arm(&self) {
        if let Some(due) = self.waiting.iter().flatten().min() {
            self.timer.schedule(self.id, *due, self.scheduler.clone());
        } else {
            self.timer.cancel(self.id);
        }
    }
}

impl<E: EnvoyHttpFilter> HttpFilter<E> for Filter {
    fn on_request_headers(&mut self, envoy: &mut E, _: bool) -> Headers {
        // Retry replay buffers share the filter-manager buffer used for pacing.
        if ["x-envoy-retry-on", "x-envoy-retry-grpc-on"]
            .iter()
            .any(|header| envoy.get_request_header_value(header).is_some())
        {
            envoy.send_response(
                400,
                &[],
                Some(b"bandwidth shaping does not support router retries"),
                Some("bandwidth_retry_unsupported"),
            );
            return Headers::StopIteration;
        }
        let keys = self.budget.ledger.lock().unwrap().config.resolve(|key| {
            envoy
                .get_filter_state_bytes(key.as_bytes())
                .and_then(|value| {
                    std::str::from_utf8(value.as_slice())
                        .ok()
                        .map(str::to_owned)
                })
        });
        let Ok(keys) = keys else {
            envoy.send_response(
                403,
                &[],
                Some(b"bandwidth descriptor value missing or invalid"),
                Some("bandwidth_missing_key"),
            );
            return Headers::StopIteration;
        };
        if self
            .budget
            .ledger
            .lock()
            .unwrap()
            .acquire(&keys, Instant::now())
            .is_err()
        {
            envoy.send_response(
                503,
                &[],
                Some(b"bandwidth bucket capacity exhausted"),
                Some("bandwidth_capacity"),
            );
            return Headers::StopIteration;
        }
        self.keys = keys;
        if !self.keys.is_empty() {
            envoy.set_buffer_limit(self.buffer_limit as u64);
        }
        Headers::Continue
    }

    fn on_request_body(&mut self, envoy: &mut E, _: bool) -> RequestBody {
        if self.keys.is_empty() {
            return RequestBody::Continue;
        }
        let mut bytes = envoy.get_received_request_body_size();
        if !envoy.received_buffered_request_body() {
            bytes += envoy.get_buffered_request_body_size();
        }
        if self.charge(0, bytes) {
            RequestBody::Continue
        } else {
            RequestBody::StopIterationAndWatermark
        }
    }

    fn on_response_body(&mut self, envoy: &mut E, _: bool) -> ResponseBody {
        if self.keys.is_empty() {
            return ResponseBody::Continue;
        }
        let mut bytes = envoy.get_received_response_body_size();
        if !envoy.received_buffered_response_body() {
            bytes += envoy.get_buffered_response_body_size();
        }
        if self.charge(1, bytes) {
            ResponseBody::Continue
        } else {
            ResponseBody::StopIterationAndWatermark
        }
    }

    fn on_request_trailers(&mut self, _: &mut E) -> RequestTrailers {
        if self.waiting[0].is_some() {
            RequestTrailers::StopIteration
        } else {
            RequestTrailers::Continue
        }
    }

    fn on_response_trailers(&mut self, _: &mut E) -> ResponseTrailers {
        if self.waiting[1].is_some() {
            ResponseTrailers::StopIteration
        } else {
            ResponseTrailers::Continue
        }
    }

    fn on_scheduled(&mut self, envoy: &mut E, _: u64) {
        if self.waiting[0].is_some() && self.charge(0, envoy.get_buffered_request_body_size()) {
            // Resuming can synchronously destroy this filter. charge() already armed the other direction.
            envoy.continue_decoding();
            return;
        }
        if self.waiting[1].is_some() && self.charge(1, envoy.get_buffered_response_body_size()) {
            envoy.continue_encoding();
        }
    }
}

impl Drop for Filter {
    fn drop(&mut self) {
        self.timer.cancel(self.id);
        let mut ledger = self.budget.ledger.lock().unwrap();
        ledger.waiters.remove(&self.id);
        let due = ledger.release(&self.keys, Instant::now());
        drop(ledger);
        self.budget.reap_at(due);
    }
}

#[cfg(test)]
mod tests;
