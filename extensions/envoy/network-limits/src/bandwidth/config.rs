// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

use crate::descriptor::{
    Entry, MatchDescriptor, RateLimit, default_budget_name, default_capacity, resolve, same_layout,
    validate_groups,
};
use serde::{Deserialize, Deserializer, de::Error};
use std::num::NonZeroU64;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_budget_name")]
    pub budget_name: String,
    pub rate_limits: Vec<RateLimit>,
    pub descriptors: Vec<Descriptor>,
    #[serde(default = "default_capacity")]
    pub max_dynamic_buckets: usize,
    #[serde(default = "default_buffer_limit")]
    pub buffer_limit_bytes: u32,
}

fn default_buffer_limit() -> u32 {
    65536
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub entries: Vec<Entry>,
    pub bandwidth_limit: BandwidthLimit,
}

impl Descriptor {
    pub fn dynamic(&self) -> bool {
        self.entries.iter().any(|e| e.value.is_empty())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BandwidthLimit {
    #[serde(default, deserialize_with = "byte_rate")]
    pub upload_bytes_per_second: Option<NonZeroU64>,
    #[serde(default, deserialize_with = "byte_rate")]
    pub download_bytes_per_second: Option<NonZeroU64>,
}

// ProtoJSON encodes uint64 as strings; standalone module configurations may use numbers.
fn byte_rate<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<NonZeroU64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Rate {
        Number(NonZeroU64),
        String(String),
    }
    let rate = match Rate::deserialize(deserializer)? {
        Rate::Number(rate) => rate,
        Rate::String(rate) => rate.parse().map_err(D::Error::custom)?,
    };
    Ok(Some(rate))
}

impl Config {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let config: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if config.budget_name.is_empty()
            || config.rate_limits.is_empty()
            || config.descriptors.is_empty()
            || config.max_dynamic_buckets == 0
            || config.buffer_limit_bytes == 0
        {
            return Err("budget_name, rate_limits, descriptors, capacity and buffer limit must be nonempty/positive".into());
        }
        validate_groups(&config.rate_limits, &config.descriptors)?;
        for descriptor in &config.descriptors {
            if descriptor.bandwidth_limit.upload_bytes_per_second.is_none()
                && descriptor
                    .bandwidth_limit
                    .download_bytes_per_second
                    .is_none()
            {
                return Err("each descriptor needs at least one bandwidth limit".into());
            }
        }
        Ok(config)
    }

    pub fn same_layout(&self, other: &Self) -> bool {
        same_layout(
            &self.rate_limits,
            &self.descriptors,
            &other.rate_limits,
            &other.descriptors,
        )
    }

    pub fn resolve(
        &self,
        get: impl FnMut(&str) -> Option<String>,
    ) -> Result<Vec<(usize, Vec<String>)>, ()> {
        resolve(&self.rate_limits, &self.descriptors, get)
    }
}

impl MatchDescriptor for Descriptor {
    fn entries(&self) -> &[Entry] {
        &self.entries
    }
}
