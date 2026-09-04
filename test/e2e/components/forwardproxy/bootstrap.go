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
// The fixed bootstrap provides HTTP/1 cleartext and TLS CONNECT listeners
// without Pilot or Envoy Go API dependencies. Its local HTTPS target lets a
// non-mesh explicit proxy enter an ordinary Pod's dedicated ztunnel.

package forwardproxy

// DefaultImage is the framework-owned Envoy image used by the forward-proxy
// fixture. Tests may override it when validating another Envoy build.
const DefaultImage = "docker.io/envoyproxy/envoy@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4"

const bootstrap = `admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9902
static_resources:
  listeners:
  - name: http_forward_proxy_3128
    address:
      socket_address:
        address: "::"
        port_value: 3128
        ipv4_compat: true
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: http_forward_proxy
          codec_type: HTTP1
          http_protocol_options: {}
          access_log:
          - name: envoy.access_loggers.file
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: /dev/stdout
              log_format:
                text_format_source:
                  inline_string: |
                    [%START_TIME%] http_forward_proxy_3128 "%PROTOCOL% %REQ(:METHOD)% %REQ(:AUTHORITY)%" %RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS% %CONNECTION_TERMINATION_DETAILS% "%UPSTREAM_TRANSPORT_FAILURE_REASON%" "%UPSTREAM_HOST%" %UPSTREAM_CLUSTER% %UPSTREAM_LOCAL_ADDRESS% %DOWNSTREAM_REMOTE_ADDRESS%
          http_filters:
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
              dns_cache_config:
                name: dynamic_forward_proxy_cache_config
                typed_dns_resolver_config:
                  name: envoy.network.dns_resolver.cares
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig
                    resolvers:
                    - socket_address:
                        address: 8.8.8.8
                        port_value: 53
                        ipv4_compat: true
                    dns_resolver_options:
                      use_tcp_for_dns_lookups: true
                      no_default_search_domain: true
                    use_resolvers_as_fallback: true
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: default
            virtual_hosts:
            - name: http_forward_proxy
              domains: ["*"]
              routes:
              - match:
                  connect_matcher: {}
                route:
                  cluster: dynamic_forward_proxy_cluster
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config: {}
    stat_prefix: http_forward_proxy_3128
  - name: http_forward_proxy_4128
    address:
      socket_address:
        address: "::"
        port_value: 4128
        ipv4_compat: true
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: http_forward_proxy
          codec_type: HTTP1
          http_protocol_options: {}
          access_log:
          - name: envoy.access_loggers.file
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
              path: /dev/stdout
              log_format:
                text_format_source:
                  inline_string: |
                    [%START_TIME%] http_forward_proxy_4128 "%PROTOCOL% %REQ(:METHOD)% %REQ(:AUTHORITY)%" %RESPONSE_CODE% %RESPONSE_FLAGS% %RESPONSE_CODE_DETAILS% %CONNECTION_TERMINATION_DETAILS% "%UPSTREAM_TRANSPORT_FAILURE_REASON%" "%UPSTREAM_HOST%" %UPSTREAM_CLUSTER% %UPSTREAM_LOCAL_ADDRESS% %DOWNSTREAM_REMOTE_ADDRESS%
          http_filters:
          - name: envoy.filters.http.dynamic_forward_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig
              dns_cache_config:
                name: dynamic_forward_proxy_cache_config
                typed_dns_resolver_config:
                  name: envoy.network.dns_resolver.cares
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig
                    resolvers:
                    - socket_address:
                        address: 8.8.8.8
                        port_value: 53
                        ipv4_compat: true
                    dns_resolver_options:
                      use_tcp_for_dns_lookups: true
                      no_default_search_domain: true
                    use_resolvers_as_fallback: true
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: default
            virtual_hosts:
            - name: http_forward_proxy
              domains: ["*"]
              routes:
              - match:
                  connect_matcher: {}
                route:
                  cluster: dynamic_forward_proxy_cluster
                  upgrade_configs:
                  - upgrade_type: CONNECT
                    connect_config: {}
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: /etc/envoy/external-forward-proxy-cert.pem
              private_key:
                filename: /etc/envoy/external-forward-proxy-key.pem
    stat_prefix: http_forward_proxy_4128
  - name: https_target_8443
    address:
      socket_address:
        address: "::"
        port_value: 8443
        ipv4_compat: true
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: https_target
          codec_type: HTTP1
          route_config:
            name: https_target
            virtual_hosts:
            - name: https_target
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                direct_response:
                  status: 200
                  body:
                    inline_string: "connect target\n"
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates:
            - certificate_chain:
                filename: /etc/envoy/external-forward-proxy-cert.pem
              private_key:
                filename: /etc/envoy/external-forward-proxy-key.pem
  clusters:
  - name: dynamic_forward_proxy_cluster
    lb_policy: CLUSTER_PROVIDED
    cluster_type:
      name: envoy.clusters.dynamic_forward_proxy
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig
        dns_cache_config:
          name: dynamic_forward_proxy_cache_config
          typed_dns_resolver_config:
            name: envoy.network.dns_resolver.cares
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig
              resolvers:
              - socket_address:
                  address: 8.8.8.8
                  port_value: 53
                  ipv4_compat: true
              dns_resolver_options:
                use_tcp_for_dns_lookups: true
                no_default_search_domain: true
              use_resolvers_as_fallback: true
`

// Bootstrap returns the complete Envoy v3 bootstrap for the fixed forward
// CONNECT fixture. It contains no user-supplied values or template expansion.
func Bootstrap() string {
	return bootstrap
}
