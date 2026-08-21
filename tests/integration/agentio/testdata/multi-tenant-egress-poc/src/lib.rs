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

pub mod config;
pub mod render;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestScope {
    Unscoped,
    Http,
    ConnectUdp,
}

pub fn request_scope(
    http_trigger: Option<&str>,
    method: Option<&str>,
    upgrade: Option<&str>,
    capsule_protocol: Option<&str>,
    path: Option<&str>,
    udp_path: &str,
) -> RequestScope {
    if http_trigger == Some("1") {
        return RequestScope::Http;
    }
    if method == Some("GET")
        && upgrade == Some("connect-udp")
        && capsule_protocol == Some("?1")
        && path == Some(udp_path)
    {
        return RequestScope::ConnectUdp;
    }
    RequestScope::Unscoped
}

#[cfg(target_arch = "wasm32")]
mod plugin {
    use std::rc::Rc;

    use proxy_wasm::hostcalls;
    use proxy_wasm::traits::{Context, HttpContext, RootContext};
    use proxy_wasm::types::{Action, ContextType, LogLevel};

    use crate::config::PluginConfig;
    use crate::{request_scope, RequestScope};

    const INTERNAL_ROUTE_HEADER: &str = "x-agentio-poc-route";
    const HTTP_TRIGGER_HEADER: &str = "x-agentio-poc-tenant";

    struct TenantRouterRoot {
        config: Option<Rc<PluginConfig>>,
    }

    impl Context for TenantRouterRoot {}

    impl RootContext for TenantRouterRoot {
        fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
            let Some(configuration) = self.get_plugin_configuration() else {
                log(LogLevel::Error, "configuration=<missing> decision=reject");
                return false;
            };
            let config: PluginConfig = match serde_json::from_slice(&configuration) {
                Ok(config) => config,
                Err(error) => {
                    log(
                        LogLevel::Error,
                        &format!("configuration=<invalid:{error}> decision=reject"),
                    );
                    return false;
                }
            };
            if config.udp_path.is_empty() || config.bindings.is_empty() {
                log(LogLevel::Error, "configuration=<empty> decision=reject");
                return false;
            }
            self.config = Some(Rc::new(config));
            true
        }

        fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
            Some(Box::new(TenantRouterHttp {
                config: self.config.clone()?,
            }))
        }

        fn get_type(&self) -> Option<ContextType> {
            Some(ContextType::HttpContext)
        }
    }

    struct TenantRouterHttp {
        config: Rc<PluginConfig>,
    }

    impl Context for TenantRouterHttp {}

    impl HttpContext for TenantRouterHttp {
        fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
            let spoofed_route = self
                .get_http_request_header(INTERNAL_ROUTE_HEADER)
                .is_some();
            self.set_http_request_header(INTERNAL_ROUTE_HEADER, None);

            let trigger = self.get_http_request_header(HTTP_TRIGGER_HEADER);
            let method = self.get_http_request_header(":method");
            let upgrade = self.get_http_request_header("upgrade");
            let capsule_protocol = self.get_http_request_header("capsule-protocol");
            let path = self.get_http_request_header(":path");
            let scope = request_scope(
                trigger.as_deref(),
                method.as_deref(),
                upgrade.as_deref(),
                capsule_protocol.as_deref(),
                path.as_deref(),
                &self.config.udp_path,
            );

            if scope == RequestScope::Unscoped {
                if spoofed_route && self.clear_route_cache().is_err() {
                    return self.reject(
                        500,
                        "clear-route-cache-failed",
                        b"failed to clear route cache\n",
                    );
                }
                return Action::Continue;
            }
            self.set_http_request_header(HTTP_TRIGGER_HEADER, None);

            let namespace =
                match read_utf8_property(vec!["filter_state", "downstream_peer", "namespace"]) {
                    Ok(value) => value,
                    Err(reason) => {
                        log(
                            LogLevel::Warn,
                            &format!("namespace=<unknown:{reason}> name=<unknown> decision=deny"),
                        );
                        return self.reject(403, "unknown-tenant", b"unknown tenant identity\n");
                    }
                };
            let name = match read_utf8_property(vec!["filter_state", "downstream_peer", "name"]) {
                Ok(value) => value,
                Err(reason) => {
                    log(
                        LogLevel::Warn,
                        &format!("namespace={namespace} name=<unknown:{reason}> decision=deny"),
                    );
                    return self.reject(403, "unknown-tenant", b"unknown tenant identity\n");
                }
            };

            let Some(route_key) = self.config.route_for(&namespace, &name) else {
                log(
                    LogLevel::Warn,
                    &format!("namespace={namespace} name={name} decision=deny"),
                );
                return self.reject(403, "unknown-tenant", b"unknown tenant identity\n");
            };
            let route_key = route_key.to_owned();
            self.set_http_request_header(INTERNAL_ROUTE_HEADER, Some(&route_key));
            if self.clear_route_cache().is_err() {
                self.set_http_request_header(INTERNAL_ROUTE_HEADER, None);
                return self.reject(
                    500,
                    "clear-route-cache-failed",
                    b"failed to clear route cache\n",
                );
            }

            log(
                LogLevel::Warn,
                &format!("namespace={namespace} name={name} route={route_key} scope={scope:?}"),
            );
            Action::Continue
        }
    }

    impl TenantRouterHttp {
        fn clear_route_cache(&self) -> Result<(), proxy_wasm::types::Status> {
            self.call_foreign_function("clear_route_cache", None)
                .map(|_| ())
        }

        fn reject(&self, status: u32, result: &str, body: &[u8]) -> Action {
            self.send_http_response(
                status,
                vec![
                    ("content-type", "text/plain"),
                    ("x-agentio-poc-result", result),
                ],
                Some(body),
            );
            Action::Pause
        }
    }

    fn read_utf8_property(path: Vec<&str>) -> Result<String, &'static str> {
        match hostcalls::get_property(path) {
            Ok(Some(value)) => String::from_utf8(value).map_err(|_| "non-utf8"),
            Ok(None) => Err("missing"),
            Err(_) => Err("read-error"),
        }
    }

    fn log(level: LogLevel, message: &str) {
        let _ = hostcalls::log(level, &format!("POC_TENANT_ROUTER {message}"));
    }

    proxy_wasm::main!({
        proxy_wasm::set_log_level(LogLevel::Warn);
        proxy_wasm::set_root_context(|_| Box::new(TenantRouterRoot { config: None }));
    });
}
