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

use serde::Deserialize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteConfig {
    termination_cluster: String,
    passthrough_cluster: String,
}

#[derive(Deserialize)]
struct RawRouteConfig {
    termination_cluster: String,
    passthrough_cluster: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError(String);

impl Display for ConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ConfigError {}

impl RouteConfig {
    pub fn new(
        termination_cluster: String,
        passthrough_cluster: String,
    ) -> Result<Self, ConfigError> {
        if termination_cluster.trim().is_empty() {
            return Err(ConfigError("termination_cluster is empty".into()));
        }
        if passthrough_cluster.trim().is_empty() {
            return Err(ConfigError("passthrough_cluster is empty".into()));
        }
        Ok(Self {
            termination_cluster,
            passthrough_cluster,
        })
    }

    pub fn from_json(value: &[u8]) -> Result<Self, ConfigError> {
        let config: RawRouteConfig = serde_json::from_slice(value)
            .map_err(|error| ConfigError(format!("decode plugin configuration: {error}")))?;
        Self::new(config.termination_cluster, config.passthrough_cluster)
    }

    pub fn termination_cluster(&self) -> &str {
        &self.termination_cluster
    }

    pub fn passthrough_cluster(&self) -> &str {
        &self.passthrough_cluster
    }
}
