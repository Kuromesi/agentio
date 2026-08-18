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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizeError(&'static str);

impl Display for NormalizeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for NormalizeError {}

pub fn normalize_sni(value: &str) -> Result<String, NormalizeError> {
    normalize_dns_name(value, false)
}

pub(crate) fn normalize_pattern(value: &str) -> Result<String, NormalizeError> {
    if value == "*" {
        return Ok(value.into());
    }
    if let Some(suffix) = value.strip_prefix("*.") {
        let suffix = normalize_dns_name(suffix, false)?;
        return Ok(format!("*.{suffix}"));
    }
    if value.contains('*') {
        return Err(NormalizeError(
            "wildcard must be the complete leftmost label",
        ));
    }
    normalize_dns_name(value, false)
}

fn normalize_dns_name(value: &str, allow_empty: bool) -> Result<String, NormalizeError> {
    if !value.is_ascii() {
        return Err(NormalizeError("SNI must contain ASCII characters only"));
    }
    let mut normalized = value.to_ascii_lowercase();
    if normalized.ends_with('.') {
        normalized.pop();
    }
    if normalized.is_empty() {
        return if allow_empty {
            Ok(normalized)
        } else {
            Err(NormalizeError("SNI is empty"))
        };
    }
    if normalized.ends_with('.') {
        return Err(NormalizeError("SNI has more than one trailing dot"));
    }
    if normalized.len() > 253 {
        return Err(NormalizeError("SNI exceeds 253 bytes"));
    }
    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(NormalizeError("SNI contains an empty or overlong label"));
        }
        let bytes = label.as_bytes();
        if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
            return Err(NormalizeError(
                "SNI label must start and end with an alphanumeric character",
            ));
        }
        if bytes
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-')
        {
            return Err(NormalizeError("SNI label contains an invalid character"));
        }
    }
    Ok(normalized)
}
