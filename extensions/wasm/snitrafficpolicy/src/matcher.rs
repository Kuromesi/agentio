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

pub fn matches_sni(pattern: &str, normalized_sni: &str) -> bool {
    if normalized_sni.is_empty() {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return normalized_sni.len() > suffix.len()
            && normalized_sni.ends_with(suffix)
            && normalized_sni.as_bytes()[normalized_sni.len() - suffix.len() - 1] == b'.';
    }
    pattern == normalized_sni
}
