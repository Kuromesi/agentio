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

package forwardproxy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBootstrapRendersFixedConnectProxy(t *testing.T) {
	// A missing listener, CONNECT route, dynamic-forward-proxy config, or TLS
	// certificate path must make this behavior test fail.
	var bootstrap map[string]any
	if err := yaml.Unmarshal([]byte(Bootstrap()), &bootstrap); err != nil {
		t.Fatalf("parse bootstrap: %v", err)
	}

	adminPort := nested(bootstrap, "admin", "address", "socket_address", "port_value")
	if adminPort != 9902 {
		t.Fatalf("admin port = %#v, want 9902", adminPort)
	}

	listeners := maps(nested(bootstrap, "static_resources", "listeners"))
	if len(listeners) != 3 {
		t.Fatalf("listeners = %d, want 3", len(listeners))
	}
	for _, want := range []struct {
		port int
		tls  bool
	}{
		{port: 3128},
		{port: 4128, tls: true},
	} {
		listener := listenerAtPort(t, listeners, want.port)
		chain := maps(nested(listener, "filter_chains"))
		if len(chain) != 1 {
			t.Fatalf("listener %d filter chains = %d, want 1", want.port, len(chain))
		}
		transportSocket := nested(chain[0], "transport_socket")
		if want.tls {
			if nested(transportSocket, "name") != "envoy.transport_sockets.tls" {
				t.Fatalf("listener %d transport socket = %#v, want TLS", want.port, transportSocket)
			}
			if nested(transportSocket, "typed_config", "common_tls_context", "tls_certificates", "0", "certificate_chain", "filename") != "/etc/envoy/external-forward-proxy-cert.pem" ||
				nested(transportSocket, "typed_config", "common_tls_context", "tls_certificates", "0", "private_key", "filename") != "/etc/envoy/external-forward-proxy-key.pem" {
				t.Fatalf("listener %d TLS certificate files = %#v", want.port, transportSocket)
			}
		} else if transportSocket != nil {
			t.Fatalf("listener %d transport socket = %#v, want none", want.port, transportSocket)
		}
		assertConnectRouteAndDynamicForwardProxy(t, chain[0])
	}

	target := listenerAtPort(t, listeners, 8443)
	targetChains := maps(nested(target, "filter_chains"))
	if len(targetChains) != 1 || nested(targetChains[0], "transport_socket", "name") != "envoy.transport_sockets.tls" {
		t.Fatalf("HTTPS target filter chain = %#v", targetChains)
	}
	targetFilters := maps(nested(targetChains[0], "filters"))
	if len(targetFilters) != 1 || nested(targetFilters[0], "name") != "envoy.filters.network.http_connection_manager" ||
		nested(targetFilters[0], "typed_config", "route_config", "virtual_hosts", "0", "routes", "0", "direct_response", "status") != 200 ||
		nested(targetFilters[0], "typed_config", "http_filters", "0", "typed_config", "@type") != "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router" {
		t.Fatalf("HTTPS target HCM = %#v", targetFilters)
	}

	clusters := maps(nested(bootstrap, "static_resources", "clusters"))
	if len(clusters) != 1 || nested(clusters[0], "name") != "dynamic_forward_proxy_cluster" ||
		nested(clusters[0], "cluster_type", "name") != "envoy.clusters.dynamic_forward_proxy" {
		t.Fatalf("dynamic forward proxy cluster = %#v", clusters)
	}
	if strings.Contains(Bootstrap(), "{{") || strings.Contains(Bootstrap(), "}}") {
		t.Fatal("bootstrap contains template placeholders")
	}
}

func listenerAtPort(t *testing.T, listeners []map[string]any, want int) map[string]any {
	t.Helper()
	for _, listener := range listeners {
		if nested(listener, "address", "socket_address", "port_value") == want {
			return listener
		}
	}
	t.Fatalf("listener at port %d not found", want)
	return nil
}

func assertConnectRouteAndDynamicForwardProxy(t *testing.T, chain map[string]any) {
	t.Helper()
	filters := maps(nested(chain, "filters"))
	if len(filters) != 1 || nested(filters[0], "name") != "envoy.filters.network.http_connection_manager" {
		t.Fatalf("network filters = %#v", filters)
	}
	hcm := mapValue(nested(filters[0], "typed_config"))
	httpFilters := maps(nested(hcm, "http_filters"))
	if len(httpFilters) != 2 || nested(httpFilters[0], "name") != "envoy.filters.http.dynamic_forward_proxy" ||
		nested(httpFilters[1], "name") != "envoy.filters.http.router" ||
		nested(httpFilters[1], "typed_config", "@type") != "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router" {
		t.Fatalf("HTTP filters = %#v", httpFilters)
	}
	route := mapValue(nested(hcm, "route_config", "virtual_hosts", "0", "routes", "0"))
	if nested(route, "match", "connect_matcher") == nil ||
		nested(route, "route", "cluster") != "dynamic_forward_proxy_cluster" ||
		nested(route, "route", "upgrade_configs", "0", "upgrade_type") != "CONNECT" ||
		nested(route, "route", "upgrade_configs", "0", "connect_config") == nil {
		t.Fatalf("CONNECT route = %#v", route)
	}
}

func nested(value any, path ...string) any {
	for _, element := range path {
		switch typed := value.(type) {
		case map[string]any:
			value = typed[element]
		case []any:
			if element != "0" || len(typed) == 0 {
				return nil
			}
			value = typed[0]
		default:
			return nil
		}
	}
	return value
}

func maps(value any) []map[string]any {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		result = append(result, mapValue(item))
	}
	return result
}

func mapValue(value any) map[string]any {
	mapped, _ := value.(map[string]any)
	return mapped
}
