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

package networking

import (
	"testing"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	setstatehttpv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/set_filter_state/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/model"
)

func testGateway(config *configv1.EgressGateway) model.Gateway {
	if config == nil {
		config = &configv1.EgressGateway{}
	}
	return model.Gateway{
		Namespace: "agentio-system",
		Name:      "egress",
		Config:    config,
	}
}

func assertStaticEndpointState(t *testing.T, typedConfig map[string]*anypb.Any, wantAddress string) {
	t.Helper()
	value := typedConfig["agentio.static_endpoint_filter_state"]
	if value == nil {
		t.Fatal("static endpoint set-filter-state config not found")
	}
	config := &setstatehttpv3.Config{}
	if err := value.UnmarshalTo(config); err != nil {
		t.Fatalf("decode static endpoint set-filter-state: %v", err)
	}
	values := config.GetOnRequestHeaders()
	if got, want := len(values), 2; got != want {
		t.Fatalf("static endpoint state values = %d, want %d", got, want)
	}
	if got := values[0].GetObjectKey(); got != "envoy.upstream.dynamic_host" {
		t.Fatalf("static host state key = %q", got)
	}
	if got := values[0].GetFormatString().GetTextFormatSource().GetInlineString(); got != wantAddress {
		t.Fatalf("static host state value = %q, want %q", got, wantAddress)
	}
	if !values[0].GetReadOnly() {
		t.Fatal("static host state must be read-only")
	}
	if got := values[1].GetObjectKey(); got != "envoy.upstream.dynamic_port" {
		t.Fatalf("static port state key = %q", got)
	}
	if got, want := values[1].GetFormatString().GetTextFormatSource().GetInlineString(),
		"%FILTER_STATE(envoy.filters.listener.original_dst.local_ip:FIELD:port)%"; got != want {
		t.Fatalf("static port state value = %q, want %q", got, want)
	}
	if !values[1].GetReadOnly() || !values[1].GetSkipIfEmpty() {
		t.Fatal("static port state must be read-only and skip empty values")
	}
}

func messagesOf[T proto.Message](t *testing.T, resources []model.Resource, typeURL string, newMessage func() T) map[string]T {
	t.Helper()
	result := map[string]T{}
	for _, resource := range resources {
		if resource.Key.TypeURL != typeURL {
			continue
		}
		message := newMessage()
		if err := resource.Value.UnmarshalTo(message); err != nil {
			t.Fatalf("unmarshal %s: %v", resource.Key.Name, err)
		}
		result[resource.XDSName] = message
	}
	return result
}

func findHCM(t *testing.T, listener *listenerv3.Listener) *hcmv3.HttpConnectionManager {
	t.Helper()
	for _, chain := range listener.GetFilterChains() {
		for _, filter := range chain.GetFilters() {
			if filter.GetName() != "envoy.filters.network.http_connection_manager" {
				continue
			}
			cfg := &hcmv3.HttpConnectionManager{}
			if err := filter.GetTypedConfig().UnmarshalTo(cfg); err != nil {
				t.Fatalf("unmarshal HCM: %v", err)
			}
			return cfg
		}
	}
	t.Fatal("HCM not found")
	return nil
}

func findFilterChain(t *testing.T, listener *listenerv3.Listener, name string) *listenerv3.FilterChain {
	t.Helper()
	for _, chain := range listener.GetFilterChains() {
		if chain.GetName() == name {
			return chain
		}
	}
	t.Fatalf("filter chain %q not found", name)
	return nil
}

func networkFilterNames(chain *listenerv3.FilterChain) []string {
	result := make([]string, 0, len(chain.GetFilters()))
	for _, filter := range chain.GetFilters() {
		result = append(result, filter.GetName())
	}
	return result
}

func hasHTTPFilter(hcm *hcmv3.HttpConnectionManager, name string) bool {
	for _, filter := range hcm.GetHttpFilters() {
		if filter.GetName() == name {
			return true
		}
	}
	return false
}

func httpFilterNames(hcm *hcmv3.HttpConnectionManager) []string {
	result := make([]string, 0, len(hcm.GetHttpFilters()))
	for _, filter := range hcm.GetHttpFilters() {
		result = append(result, filter.GetName())
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
