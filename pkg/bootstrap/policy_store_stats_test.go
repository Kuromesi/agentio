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

package bootstrap

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	"istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/model"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/test/env"
)

// renderPolicyBindingBootstrap renders the shipped bootstrap template with the
// gateway policy store extension enabled.
func renderPolicyBindingBootstrap(t *testing.T) string {
	t.Helper()
	proxyConfig := model.NodeMetaProxyConfig(v1alpha1.ProxyConfig{
		DiscoveryAddress: "agentiod.istio-system.svc:15012",
		ProxyMetadata:    map[string]string{},
	})
	node := &model.Node{
		ID:       "router~10.0.0.1~gateway.istio-system~istio-system.svc.cluster.local",
		Locality: &core.Locality{},
		Metadata: &model.BootstrapNodeMetadata{NodeMetadata: model.NodeMetadata{
			ProxyConfig:            &proxyConfig,
			PolicyBindingDiscovery: ptr.Of(model.StringBool(true)),
		}},
		RawMetadata: map[string]any{},
	}
	var buf bytes.Buffer
	template := filepath.Join(env.IstioSrc, "tools/packaging/common/envoy_bootstrap.json")
	if err := New(Config{Node: node}).WriteTo(template, &buf); err != nil {
		t.Fatalf("render bootstrap: %v", err)
	}
	return buf.String()
}

// The stats matcher uses an inclusion list, so all native policy scopes must be
// admitted explicitly. policy_store drives readiness, while sni_traffic_policy exposes
// matcher failure reasons and fail-open admissions.
func TestPolicyStatsPrefixesAreRendered(t *testing.T) {
	rendered := renderPolicyBindingBootstrap(t)

	var parsed map[string]any
	if err := json.Unmarshal([]byte(rendered), &parsed); err != nil {
		t.Fatalf("rendered bootstrap is not valid JSON: %v", err)
	}

	if !strings.Contains(rendered, `"prefix": "policy_store"`) {
		t.Error(`rendered bootstrap is missing the stats inclusion prefix "policy_store"`)
	}
	if !strings.Contains(rendered, `"prefix": "sni_traffic_policy"`) {
		t.Error(`rendered bootstrap is missing the stats inclusion prefix "sni_traffic_policy"`)
	}
	if strings.Contains(rendered, "agentio.gateway_policy_store") {
		t.Error(`rendered bootstrap still carries the stale prefix "agentio.gateway_policy_store", ` +
			"which matches no stat created by the extension")
	}
}

// The bootstrap extension is resolved by its typed-config type URL, so a stale
// name is not fatal -- but it is misleading, and the registered factory name is
// the one a reader will grep for.
func TestPolicyStoreExtensionNameMatchesFactory(t *testing.T) {
	rendered := renderPolicyBindingBootstrap(t)
	if !strings.Contains(rendered, `"name": "kruise.bootstrap.policy_store"`) {
		t.Error(`rendered bootstrap does not use the registered factory name "kruise.bootstrap.policy_store"`)
	}
	if !strings.Contains(rendered, `"policy_deletion_grace_period": "15s"`) {
		t.Error("rendered bootstrap does not use the default fifteen-second policy deletion grace period")
	}
}
