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

use agentio_multi_tenant_egress_poc::{request_scope, RequestScope};

const UDP_PATH: &str = "/.well-known/masque/udp/udp-echo.udp-hbone-poc.svc.cluster.local/9000/";

#[test]
fn explicit_trigger_scopes_an_http_request() {
    assert_eq!(
        request_scope(Some("1"), Some("GET"), None, None, Some("/"), UDP_PATH),
        RequestScope::Http
    );
}

#[test]
fn exact_connect_udp_shape_is_scoped_without_a_client_tenant_header() {
    assert_eq!(
        request_scope(
            None,
            Some("GET"),
            Some("connect-udp"),
            Some("?1"),
            Some(UDP_PATH),
            UDP_PATH,
        ),
        RequestScope::ConnectUdp
    );
}

#[test]
fn similar_udp_requests_remain_unscoped() {
    for (method, upgrade, capsule, path) in [
        ("POST", "connect-udp", "?1", UDP_PATH),
        ("GET", "websocket", "?1", UDP_PATH),
        ("GET", "connect-udp", "?0", UDP_PATH),
        (
            "GET",
            "connect-udp",
            "?1",
            "/.well-known/masque/udp/other.example/9000/",
        ),
    ] {
        assert_eq!(
            request_scope(
                None,
                Some(method),
                Some(upgrade),
                Some(capsule),
                Some(path),
                UDP_PATH,
            ),
            RequestScope::Unscoped,
            "unexpected scope for {method} {upgrade} {capsule} {path}"
        );
    }
}
