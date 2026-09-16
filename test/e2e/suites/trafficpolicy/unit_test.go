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

package trafficpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
)

func TestSetupOrder(t *testing.T) {
	digest := "registry.example/test@sha256:" + strings.Repeat("b", 64)
	setups := suiteSetupGraph(agentiocomponent.Config{
		Namespace:         "agentio-system",
		AgentiodImage:     digest,
		ZtunnelImage:      digest,
		ProxyInitImage:    digest,
		GatewayImage:      digest,
		EPEImage:          digest,
		ExtProcImage:      digest,
		ForwardProxyImage: digest,
	})
	names := make([]string, len(setups))
	for index := range setups {
		names[index] = setups[index].name
	}
	want := []string{
		"agentio", "agentio-baseline", "traffic-policy-namespace", "traffic-policy-client",
		"traffic-policy-server", "traffic-policy-another-server", "traffic-policy-workload-target",
		"fixture-readiness",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("setup order = %v, want %v", names, want)
	}
}

func TestTrafficPolicyBuilderTargetsSourceAndCIDR(t *testing.T) {
	policy := trafficPolicy("policy", "sandbox", map[string]string{"app": "client"}, "reject", "10.0.0.8/32")
	if policy.GetAPIVersion() != "agents.kruise.io/v1alpha1" || policy.GetKind() != "TrafficPolicy" {
		t.Fatalf("type metadata = %s %s", policy.GetAPIVersion(), policy.GetKind())
	}
	if policy.GetNamespace() != "sandbox" || policy.GetName() != "policy" {
		t.Fatalf("metadata = %s/%s", policy.GetNamespace(), policy.GetName())
	}
	priority, _, err := unstructured.NestedInt64(policy.Object, "spec", "priority")
	if err != nil || priority != 100 {
		t.Fatalf("priority = %d, err = %v", priority, err)
	}
	selector, _, err := unstructured.NestedStringMap(policy.Object, "spec", "selector", "matchLabels")
	if err != nil || !reflect.DeepEqual(selector, map[string]string{"app": "client"}) {
		t.Fatalf("selector = %#v, err = %v", selector, err)
	}
	rules, _, err := unstructured.NestedSlice(policy.Object, "spec", "egress", "rules")
	if err != nil || len(rules) != 2 {
		t.Fatalf("rules = %#v, err = %v", rules, err)
	}
	rule := rules[0].(map[string]any)
	if rule["action"] != "reject" {
		t.Fatalf("action = %v", rule["action"])
	}
	peers := rule["to"].([]any)
	if peers[0].(map[string]any)["cidr"] != "10.0.0.8/32" {
		t.Fatalf("peers = %#v", peers)
	}
}

func TestDataplaneEchoConfigIsProfileNeutral(t *testing.T) {
	config := dataplaneEchoConfig("client", "sandbox")
	if config.Name != "client" || config.Namespace != "sandbox" {
		t.Fatalf("echo identity = %s/%s", config.Namespace, config.Name)
	}
	if !reflect.DeepEqual(config.Labels, map[string]string{"app": "client"}) {
		t.Fatalf("echo labels = %#v", config.Labels)
	}
	if len(config.PodAnnotations) != 0 {
		t.Fatalf("echo annotations contain dataplane enrollment: %#v", config.PodAnnotations)
	}
}

func TestTrafficPolicyKeepsNonTargetEgressAvailable(t *testing.T) {
	policy := trafficPolicy("lifecycle", "sandbox", map[string]string{"app": "client"}, "reject", "10.0.0.1/32")
	rules := policy.Object["spec"].(map[string]any)["egress"].(map[string]any)["rules"].([]any)
	wantFallback := map[string]any{
		"action": "allow",
		"to": []any{
			map[string]any{"cidr": "0.0.0.0/0"},
		},
	}
	if len(rules) != 2 || !reflect.DeepEqual(rules[1], wantFallback) {
		t.Fatalf("egress rules = %#v, want target rule followed by %#v", rules, wantFallback)
	}
}

func TestWaitForPolicyStateObservesAppearanceAndRemoval(t *testing.T) {
	tests := []struct {
		name    string
		present bool
		dumps   []string
	}{
		{name: "appears", present: true, dumps: []string{nativePolicyDump(false, false), nativePolicyDump(true, true)}},
		{name: "disappears", present: false, dumps: []string{nativePolicyDump(true, true), nativePolicyDump(false, true)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := waitForPolicyState(ctx, "tp-target", test.present, func(context.Context) (string, error) {
				index := calls
				if index >= len(test.dumps) {
					index = len(test.dumps) - 1
				}
				calls++
				return test.dumps[index], nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatalf("dump calls = %d, want 2", calls)
			}
		})
	}
}

func TestWaitForPolicyStateReturnsRecentDumpError(t *testing.T) {
	want := errors.New("admin unavailable")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := waitForPolicyState(ctx, "tp-target", true, func(context.Context) (string, error) {
		return "", want
	})
	if !errors.Is(err, want) {
		t.Fatalf("waitForPolicyState() error = %v", err)
	}
}

func nativePolicyDump(bound, cached bool) string {
	refs := []string{}
	policies := []map[string]any{}
	if bound {
		refs = append(refs, "namespaces/test/trafficPolicies/tp-target")
	}
	if cached {
		policies = append(policies, map[string]any{"name": "namespaces/test/trafficPolicies/tp-target", "egress": map[string]any{"rules": []any{}}})
	}
	body, _ := json.Marshal(map[string]any{
		"workload":        map[string]any{"uid": "client-uid", "namespace": "test"},
		"sandboxes":       []any{map[string]any{"workloadUid": "client-uid", "trafficPolicyRefs": refs}},
		"trafficPolicies": policies,
	})
	return string(body)
}

func legacyPolicyDump(complete bool) string {
	aggregate := fmt.Sprintf("sandbox-%x", sha256.Sum256([]byte("client-uid")))
	policies := []any{map[string]any{"namespace": "test", "name": aggregate + "-egress", "priority": -1}}
	if complete {
		policies = append(policies, map[string]any{"namespace": "test", "name": aggregate + "-ingress", "priority": -1})
	}
	body, _ := json.Marshal(map[string]any{
		"workload": map[string]any{"uid": "client-uid", "namespace": "test", "authorizationPolicies": []string{"test/" + aggregate + "-egress", "test/" + aggregate + "-ingress"}},
		"policies": policies,
	})
	return string(body)
}

func TestInspectPolicyDumpRequiresBindingAndBody(t *testing.T) {
	for _, tc := range []struct {
		name, dump                 string
		found, aggregated, wantErr bool
	}{
		{name: "native binding and body", dump: nativePolicyDump(true, true), found: true},
		{name: "cached but unbound", dump: nativePolicyDump(false, true)},
		{name: "missing referenced body", dump: nativePolicyDump(true, false), wantErr: true},
		{name: "exact policy name", dump: strings.ReplaceAll(nativePolicyDump(true, true), "tp-target", "tp-target-extra")},
		{name: "different workload", dump: strings.Replace(nativePolicyDump(true, true), `"workloadUid":"client-uid"`, `"workloadUid":"other-uid"`, 1), wantErr: true},
		{name: "legacy aggregates are opaque", dump: legacyPolicyDump(true), aggregated: true},
		{name: "incomplete legacy aggregates", dump: legacyPolicyDump(false), wantErr: true},
		{name: "invalid JSON", dump: `broken`, wantErr: true},
		{name: "missing workload", dump: `{}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := inspectPolicyDump(tc.dump, "tp-target")
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v, want error=%v", err, tc.wantErr)
			}
			if err == nil && (got.found != tc.found || got.aggregated != tc.aggregated) {
				t.Fatalf("view=%+v", got)
			}
			if (got.found || got.aggregated) && got.body == "" {
				t.Fatal("policy bodies are missing")
			}
		})
	}
}

func TestWaitForPolicyStateReportsLegacyIdentityLimitation(t *testing.T) {
	for _, present := range []bool{true, false} {
		err := waitForPolicyState(context.Background(), "tp-target", present, func(context.Context) (string, error) { return legacyPolicyDump(true), nil })
		if !errors.Is(err, errAggregatedPolicyIdentity) {
			t.Fatalf("error=%v, want explicit identity limitation", err)
		}
	}
}
