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

package debug

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	configv1 "github.com/openkruise/agentio/api/config/v1"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

var configDebugTestTime = time.Date(2026, time.September, 1, 4, 5, 6, 0, time.FixedZone("CST", 8*60*60))

func TestConfigDebugSnapshotIncludesEffectiveKindsInStableOrder(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)

	got, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{})
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{
		"AgentioConfig//effective",
		"EnvoyFilter/demo/patch-a",
		"Gateway/agentio-system/egress",
		"GlobalSecurityProfile//global-security",
		"GlobalTrafficPolicy//global-traffic",
		"SecurityProfile/demo/security",
		"Telemetry/demo/telemetry",
		"TrafficPolicy/demo/traffic",
	}
	gotOrder := make([]string, 0, len(got.Items))
	for _, item := range got.Items {
		gotOrder = append(gotOrder, item.Kind+"/"+item.Metadata.Namespace+"/"+item.Metadata.Name)
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("item order = %v, want %v", gotOrder, wantOrder)
	}
	if !got.GeneratedAt.Equal(time.Date(2026, time.August, 31, 20, 5, 6, 0, time.UTC)) || got.GeneratedAt.Location() != time.UTC {
		t.Fatalf("generatedAt = %v, want the supplied instant normalized to UTC", got.GeneratedAt)
	}
	if !got.Synced {
		t.Fatal("snapshot reports synced=false after every input and compiler synced")
	}
	wantCounts := map[string]int{
		"AgentioConfig":         1,
		"EnvoyFilter":           1,
		"Gateway":               1,
		"GlobalSecurityProfile": 1,
		"GlobalTrafficPolicy":   1,
		"SecurityProfile":       1,
		"Telemetry":             1,
		"TrafficPolicy":         1,
	}
	if !reflect.DeepEqual(got.CountsByKind, wantCounts) {
		t.Fatalf("countsByKind = %v, want %v", got.CountsByKind, wantCounts)
	}
}

func TestConfigDebugSnapshotUsesSourceToBreakItemSortTies(t *testing.T) {
	fixture := newConfigDebugFixture(t, func(sources Sources, stop <-chan struct{}) Sources {
		original := sources.GatewayPatches.List()[0]
		later := original.Clone()
		later.Source = "z-source"
		earlier := original.Clone()
		earlier.Source = "a-source"
		sources.GatewayPatches = krt.NewStaticCollection[model.GatewayPatch](nil,
			[]model.GatewayPatch{later, earlier}, krt.WithStop(stop))
		return sources
	}, true)
	var later, earlier model.GatewayPatch
	for _, patch := range fixture.sources.GatewayPatches.List() {
		if patch.Source == "z-source" {
			later = patch
		} else if patch.Source == "a-source" {
			earlier = patch
		}
	}
	fixture.sources.GatewayPatches = orderedConfigDebugGatewayPatches{
		Collection: fixture.sources.GatewayPatches,
		values:     []model.GatewayPatch{later, earlier},
	}

	got, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{
		Kind: "EnvoyFilter",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantSources := []string{"a-source", "z-source"}
	gotSources := []string{got.Items[0].Metadata.Source, got.Items[1].Metadata.Source}
	if !reflect.DeepEqual(gotSources, wantSources) {
		t.Fatalf("source tie-break order = %v, want %v", gotSources, wantSources)
	}
}

func TestConfigDebugSnapshotFiltersAndCountsPostFilterItems(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)

	got, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{
		Kind:      "TrafficPolicy",
		Namespace: "demo",
		Name:      "traffic",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Kind != "TrafficPolicy" || got.Items[0].Metadata.Name != "traffic" {
		t.Fatalf("filtered items = %#v, want demo/traffic only", got.Items)
	}
	wantCounts := map[string]int{"TrafficPolicy": 1}
	if !reflect.DeepEqual(got.CountsByKind, wantCounts) {
		t.Fatalf("filtered countsByKind = %v, want %v", got.CountsByKind, wantCounts)
	}

	global, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{
		Kind:      "GlobalTrafficPolicy",
		Namespace: "demo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(global.Items) != 0 || len(global.CountsByKind) != 0 {
		t.Fatalf("global policy matched namespace filter: %#v", global)
	}
}

func TestConfigDebugSnapshotUsesInjectedFinalSource(t *testing.T) {
	fixture := newConfigDebugFixture(t, func(sources Sources, stop <-chan struct{}) Sources {
		replacement := krt.NewStaticCollection[model.TrafficPolicy](nil, []model.TrafficPolicy{{
			Name: "injected", Namespace: "external", Spec: validConfigDebugTrafficPolicySpec(),
		}}, krt.WithStop(stop))
		sources.TrafficPolicies = replacement
		return sources
	}, true)

	got, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{
		Kind: "TrafficPolicy",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Metadata.Namespace != "external" || got.Items[0].Metadata.Name != "injected" {
		t.Fatalf("injected TrafficPolicy items = %#v, want external/injected only", got.Items)
	}
}

func TestConfigDebugSnapshotReportsCompilerFailures(t *testing.T) {
	fixture := newConfigDebugFixture(t, func(sources Sources, stop <-chan struct{}) Sources {
		sources.TrafficPolicies = krt.NewStaticCollection[model.TrafficPolicy](nil, []model.TrafficPolicy{{
			Name: "broken-traffic", Namespace: "demo", SandboxUID: "sandbox-a",
			Spec: agentsv1alpha1.TrafficPolicySpec{
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{
					agentsv1alpha1.LabelSandboxID: "sandbox-b",
				}},
				Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
					Action: agentsv1alpha1.RuleActionAllow,
					To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
				}}},
			},
		}}, krt.WithStop(stop))
		sources.SecurityProfiles = krt.NewStaticCollection[model.SecurityProfile](nil, []model.SecurityProfile{{
			Name: "broken-security", Namespace: "demo",
			Spec: agentsv1alpha1.SecurityProfileSpec{
				Selector: metav1.LabelSelector{},
				Rules: []agentsv1alpha1.SecurityRule{{
					Name:  "bad-domain",
					Match: []agentsv1alpha1.RuleMatch{{Domains: []string{"*foo.example.com"}}},
				}},
			},
		}}, krt.WithStop(stop))
		return sources
	}, true)
	waitForConfigDebugCondition(t, func() bool { return len(fixture.compiler.Failures()) == 2 })

	got, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{
		Kind: "Gateway",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{
		"SecurityProfile/namespaced/demo/broken-security",
		"TrafficPolicy/namespaced/demo/broken-traffic",
	}
	gotKeys := make([]string, 0, len(got.Failures))
	for _, failure := range got.Failures {
		gotKeys = append(gotKeys, failure.Key)
		if failure.Message == "" {
			t.Fatalf("failure %q has an empty message", failure.Key)
		}
	}
	if !reflect.DeepEqual(gotKeys, wantKeys) {
		t.Fatalf("failure keys = %v, want sorted unfiltered failures %v", gotKeys, wantKeys)
	}
}

func TestConfigDebugSnapshotRemovesRecoveredCompilerFailures(t *testing.T) {
	var policies krt.StaticCollection[model.TrafficPolicy]
	fixture := newConfigDebugFixture(t, func(sources Sources, stop <-chan struct{}) Sources {
		policies = krt.NewStaticCollection[model.TrafficPolicy](nil, []model.TrafficPolicy{{
			Name: "recovering", Namespace: "demo", SandboxUID: "sandbox-a",
			Spec: agentsv1alpha1.TrafficPolicySpec{
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{
					agentsv1alpha1.LabelSandboxID: "sandbox-b",
				}},
				Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
					Action: agentsv1alpha1.RuleActionAllow,
					To:     []agentsv1alpha1.TrafficPolicyPeer{{CIDR: "10.0.0.0/24"}},
				}}},
			},
		}}, krt.WithStop(stop))
		sources.TrafficPolicies = policies
		return sources
	}, true)
	waitForConfigDebugCondition(t, func() bool {
		_, found := fixture.compiler.Failures()["TrafficPolicy/namespaced/demo/recovering"]
		return found
	})
	before, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Failures) != 1 {
		t.Fatalf("failures before recovery = %v, want one", before.Failures)
	}

	policies.UpdateObject(model.TrafficPolicy{
		Name: "recovering", Namespace: "demo", Spec: validConfigDebugTrafficPolicySpec(),
	})
	waitForConfigDebugCondition(t, func() bool { return len(fixture.compiler.Failures()) == 0 })
	after, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Failures) != 0 {
		t.Fatalf("failures after recovery = %v, want empty", after.Failures)
	}
}

func TestConfigDebugSnapshotReportsUnsyncedInput(t *testing.T) {
	fixture := newConfigDebugFixture(t, func(sources Sources, stop <-chan struct{}) Sources {
		sources.Telemetry = krt.NewStaticCollection[model.Telemetry](neverConfigDebugSynced{}, sources.Telemetry.List(), krt.WithStop(stop))
		return sources
	}, false)

	got, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Synced {
		t.Fatal("snapshot reports synced=true while an in-scope source is unsynced")
	}
}

func TestConfigDebugSnapshotExcludesTelemetryProviderOverrides(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)

	got, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "TelemetryProviderOverrides") || strings.Contains(string(encoded), "provider-override-marker") {
		t.Fatalf("snapshot exposed TelemetryProviderOverrides: %s", encoded)
	}
}

func TestConfigDebugSnapshotEncodesEmptyCollectionsAsObjectsAndArrays(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	got, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{
		Kind: "TrafficPolicy", Name: "missing",
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"countsByKind":{}`, `"items":[]`, `"failures":[]`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("empty snapshot %s does not contain %s", encoded, want)
		}
	}
}

func TestConfigDebugSnapshotDoesNotMutateSources(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)
	beforePatch := fixture.sources.GatewayPatches.List()[0].Clone()
	beforeTelemetry := fixture.sources.Telemetry.List()[0].Clone()
	beforeConfig := proto.Clone(fixture.sources.AgentioConfig.List()[0].Value)

	if _, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{}); err != nil {
		t.Fatal(err)
	}
	afterPatch := fixture.sources.GatewayPatches.List()[0]
	afterTelemetry := fixture.sources.Telemetry.List()[0]
	afterConfig := fixture.sources.AgentioConfig.List()[0].Value
	if !beforePatch.Equals(afterPatch) {
		t.Fatalf("GatewayPatch mutated: before=%#v after=%#v", beforePatch, afterPatch)
	}
	if !beforeTelemetry.Equals(afterTelemetry) {
		t.Fatalf("Telemetry mutated: before=%#v after=%#v", beforeTelemetry, afterTelemetry)
	}
	if !proto.Equal(beforeConfig, afterConfig) {
		t.Fatalf("AgentioConfig mutated: before=%v after=%v", beforeConfig, afterConfig)
	}
}

func TestConfigDebugSnapshotSupportsConcurrentSourceUpdates(t *testing.T) {
	var policies krt.StaticCollection[model.TrafficPolicy]
	fixture := newConfigDebugFixture(t, func(sources Sources, stop <-chan struct{}) Sources {
		policies = krt.NewStaticCollection[model.TrafficPolicy](nil, []model.TrafficPolicy{{
			Name: "changing", Namespace: "demo", Spec: validConfigDebugTrafficPolicySpec(),
		}}, krt.WithStop(stop))
		sources.TrafficPolicies = policies
		return sources
	}, true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := range 200 {
			spec := validConfigDebugTrafficPolicySpec()
			spec.Priority = int32(index)
			policies.UpdateObject(model.TrafficPolicy{Name: "changing", Namespace: "demo", Spec: spec})
		}
	}()
	for range 200 {
		snapshot, err := configDebugSnapshotAt(time.Now(), fixture.sources, fixture.compiler, configDebugFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := json.Marshal(snapshot); err != nil {
			t.Fatal(err)
		}
	}
	<-done
}

func TestConfigDebugSnapshotUsesProtoJSON(t *testing.T) {
	fixture := newConfigDebugFixture(t, nil, true)

	got, err := configDebugSnapshotAt(configDebugTestTime, fixture.sources, fixture.compiler, configDebugFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var agentio, envoyFilter string
	for _, item := range got.Items {
		switch item.Kind {
		case "AgentioConfig":
			agentio = string(item.Spec)
		case "EnvoyFilter":
			envoyFilter = string(item.Spec)
		}
	}
	if !strings.Contains(agentio, `"sandboxIgnoredLabels":["drop-me"]`) || strings.Contains(agentio, "sandbox_ignored_labels") {
		t.Fatalf("AgentioConfig is not proto JSON: %s", agentio)
	}
	if !strings.Contains(envoyFilter, `"connectTimeout":"3s"`) || strings.Contains(envoyFilter, "connect_timeout") {
		t.Fatalf("EnvoyFilter patch value is not nested proto JSON: %s", envoyFilter)
	}
}

func TestConfigDebugAgentioConfigPreservesRateLimitDescriptorValues(t *testing.T) {
	item, err := configDebugAgentioConfig(model.AgentioConfiguration{
		Value: &configv1.AgentioConfig{
			EgressGateways: []*configv1.EgressGateway{{
				ConnectRateLimit: &configv1.LocalRateLimitSettings{
					Descriptors: []*configv1.RateLimitDescriptor{{
						Entries: []*configv1.RateLimitEntry{{Key: "source_ip", Value: "203.0.113.10"}},
					}},
				},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(item.Spec), `"key":"source_ip","value":"203.0.113.10"`) {
		t.Fatalf("rate limit descriptor value was changed: %s", item.Spec)
	}
}

func TestConfigDebugSerializationRedactsSensitiveValues(t *testing.T) {
	tlsCertificate, err := marshalConfigDebugProto(&tlsv3.TlsCertificate{
		CertificateChain: &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: "certificate-material"}},
		PrivateKey:       &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: []byte("private-key-material")}},
		Password:         &corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: "private-key-password"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	header, err := marshalConfigDebugProto(&corev3.HeaderValue{Key: "x-backend-token", Value: "header-credential"})
	if err != nil {
		t.Fatal(err)
	}
	headerAny, err := anypb.New(&corev3.HeaderValue{Key: "x-nested-token", Value: "nested-header-credential"})
	if err != nil {
		t.Fatal(err)
	}
	nestedHeader, err := marshalConfigDebugProto(&corev3.TypedExtensionConfig{Name: "header", TypedConfig: headerAny})
	if err != nil {
		t.Fatal(err)
	}
	dataSourceAny, err := anypb.New(&corev3.DataSource{Specifier: &corev3.DataSource_InlineString{InlineString: "nested-data-source-credential"}})
	if err != nil {
		t.Fatal(err)
	}
	nestedDataSource, err := marshalConfigDebugProto(&corev3.TypedExtensionConfig{Name: "data-source", TypedConfig: dataSourceAny})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := configDebugSecurityProfile(model.SecurityProfile{
		Name:      "sensitive",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{},
			Inputs: []agentsv1alpha1.SecurityProfileInput{{
				Name: "request-data",
				Inline: map[string]string{
					"accessKeySecret": "policy-credential",
					"sharedSecret":    "second-policy-credential",
					"backendAuth":     "third-policy-credential",
					"region":          "cn-hangzhou",
				},
			}},
			Rules: []agentsv1alpha1.SecurityRule{{
				Name: "set-header",
				Actions: agentsv1alpha1.SecurityRuleActions{
					HeaderManipulation: &agentsv1alpha1.HeaderManipulationAction{
						Set: []agentsv1alpha1.HeaderValue{{Name: "x-backend-token", Value: "profile-header-credential"}},
					},
				},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	combined := string(tlsCertificate) + string(header) + string(nestedHeader) + string(nestedDataSource) + string(profile.Spec)
	for _, secret := range []string{
		"certificate-material",
		"private-key-material",
		"cHJpdmF0ZS1rZXktbWF0ZXJpYWw=",
		"private-key-password",
		"header-credential",
		"nested-header-credential",
		"nested-data-source-credential",
		"profile-header-credential",
		"policy-credential",
		"second-policy-credential",
		"third-policy-credential",
		"cn-hangzhou",
	} {
		if strings.Contains(combined, secret) {
			t.Fatalf("debug serialization exposed %q: %s", secret, combined)
		}
	}
	if strings.Count(combined, "[REDACTED]") < 4 {
		t.Fatalf("sensitive values were not visibly redacted: %s", combined)
	}
}

func TestConfigDebugSecurityProfileRedactsAuditHeadersWithoutMutatingSource(t *testing.T) {
	profile := model.SecurityProfile{
		Name:      "audit-headers",
		Namespace: "demo",
		Spec: agentsv1alpha1.SecurityProfileSpec{
			Selector: metav1.LabelSelector{},
			Audit: []agentsv1alpha1.AuditAction{{
				Name: "profile-audit",
				Webhook: &agentsv1alpha1.AuditWebhook{URL: "https://audit.example.com", Request: &agentsv1alpha1.AuditRequest{
					Headers: []agentsv1alpha1.AuditHeader{{Name: "Authorization", Value: "Bearer profile-audit-credential"}},
				}},
			}},
			Rules: []agentsv1alpha1.SecurityRule{{
				Name: "rule-audit",
				Actions: agentsv1alpha1.SecurityRuleActions{Audit: []agentsv1alpha1.AuditAction{{
					Name: "rule-audit",
					Webhook: &agentsv1alpha1.AuditWebhook{URL: "https://audit.example.com", Request: &agentsv1alpha1.AuditRequest{
						Headers: []agentsv1alpha1.AuditHeader{{Name: "x-audit-token", Value: "rule-audit-credential"}},
					}},
				}}},
			}},
		},
	}

	item, err := configDebugSecurityProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{"profile-audit-credential", "rule-audit-credential"} {
		if strings.Contains(string(item.Spec), credential) {
			t.Fatalf("audit header credential %q exposed: %s", credential, item.Spec)
		}
	}
	if got := profile.Spec.Audit[0].Webhook.Request.Headers[0].Value; got != "Bearer profile-audit-credential" {
		t.Fatalf("profile audit source header mutated: %q", got)
	}
	if got := profile.Spec.Rules[0].Actions.Audit[0].Webhook.Request.Headers[0].Value; got != "rule-audit-credential" {
		t.Fatalf("rule audit source header mutated: %q", got)
	}
}

func TestConfigDebugRedactionPreservesCredentialReferenceShape(t *testing.T) {
	got, err := redactConfigDebugJSON([]byte(`{
		"credentialRef": {
			"secret": {"name": "backend-credentials", "namespace": "demo"},
			"credentialProvider": {"name": "vault"}
		}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		CredentialRef struct {
			Secret struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"secret"`
			CredentialProvider struct {
				Name string `json:"name"`
			} `json:"credentialProvider"`
		} `json:"credentialRef"`
	}
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("redaction changed credential reference shape: %v: %s", err, got)
	}
	if decoded.CredentialRef.Secret.Name != "backend-credentials" || decoded.CredentialRef.Secret.Namespace != "demo" ||
		decoded.CredentialRef.CredentialProvider.Name != "vault" {
		t.Fatalf("credential references changed by redaction: %s", got)
	}
}

func TestConfigDebugPatchSupportsEverySealedTarget(t *testing.T) {
	for _, test := range []struct {
		name   string
		target model.PatchTarget
		want   string
	}{
		{name: "cluster", target: model.ClusterPatch{Value: &clusterv3.Cluster{}}, want: "cluster"},
		{name: "listener", target: model.ListenerPatch{Value: &listenerv3.Listener{}}, want: "listener"},
		{name: "listener filter", target: model.ListenerFilterPatch{Value: &listenerv3.ListenerFilter{}}, want: "listenerFilter"},
		{name: "filter chain", target: model.FilterChainPatch{Value: &listenerv3.FilterChain{}}, want: "filterChain"},
		{name: "network filter", target: model.NetworkFilterPatch{Value: &listenerv3.Filter{}}, want: "networkFilter"},
		{name: "HTTP filter", target: model.HTTPFilterPatch{Value: &hcmv3.HttpFilter{}}, want: "httpFilter"},
		{name: "route configuration", target: model.RouteConfigurationPatch{Value: &routev3.RouteConfiguration{}}, want: "routeConfiguration"},
		{name: "virtual host", target: model.VirtualHostPatch{Value: &routev3.VirtualHost{}}, want: "virtualHost"},
		{name: "HTTP route", target: model.HTTPRoutePatch{Value: &routev3.Route{}}, want: "httpRoute"},
		{name: "extension configuration", target: model.ExtensionConfigurationPatch{Value: &corev3.TypedExtensionConfig{}}, want: "extensionConfiguration"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := configDebugPatch(model.EnvoyPatch{Operation: model.PatchAdd, Target: test.target})
			if err != nil {
				t.Fatal(err)
			}
			if got.Target != test.want || got.Operation != "ADD" || string(got.Value) != "{}" {
				t.Fatalf("adapted patch = %#v, want target=%q operation=ADD value={}", got, test.want)
			}
		})
	}

	unknown, err := configDebugPatch(model.EnvoyPatch{
		Operation: model.PatchOperation(255),
		Target: model.HTTPRoutePatch{
			Match: &model.RouteConfigurationMatch{VirtualHost: &model.VirtualHostMatch{
				Route: &model.RouteMatch{Action: model.RouteAction(255)},
			}},
			Value: &routev3.Route{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	match, err := json.Marshal(unknown.Match)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Operation != "UNKNOWN(255)" || !strings.Contains(string(match), `"action":"UNKNOWN(255)"`) {
		t.Fatalf("unknown enum adaptation = %#v match=%s", unknown, match)
	}
}

type configDebugFixture struct {
	sources  Sources
	compiler *compiler.Compiler
}

type configDebugSourceMutation func(Sources, <-chan struct{}) Sources

func newConfigDebugFixture(t *testing.T, mutate configDebugSourceMutation, wait bool) configDebugFixture {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	sources := populatedConfigDebugSources(t, stop)
	if mutate != nil {
		sources = mutate(sources, stop)
	}
	options := []krt.CollectionOption{krt.WithStop(stop)}
	resourceCompiler, err := compiler.New(compiler.Inputs{
		ClusterID:          "cluster",
		RootNamespace:      "agentio-system",
		Sandboxes:          krt.NewStaticCollection[model.Sandbox](nil, nil, options...),
		Workloads:          krt.NewStaticCollection[model.Workload](nil, nil, options...),
		Pods:               krt.NewStaticCollection[*corev1.Pod](nil, nil, krt.WithStop(stop)),
		KubernetesServices: krt.NewStaticCollection[*corev1.Service](nil, nil, krt.WithStop(stop)),
		EndpointSlices:     krt.NewStaticCollection[*discoveryv1.EndpointSlice](nil, nil, krt.WithStop(stop)),
		Services:           krt.NewStaticCollection[model.Service](nil, nil, options...),
		Endpoints:          krt.NewStaticCollection[model.Endpoint](nil, nil, options...),
		Gateways:           sources.Gateways,
		TrafficPolicies:    sources.TrafficPolicies,
		SecurityProfiles:   sources.SecurityProfiles,
		GatewayPatches:     sources.GatewayPatches,
		Telemetry:          sources.Telemetry,
		TelemetryProviderOverrides: krt.NewStatic(&model.TelemetryProviderOverrides{
			Providers: []model.TelemetryProvider{{Name: "provider-override-marker", Prometheus: true}},
		}, true, options...),
		AgentioConfig:    sources.AgentioConfig,
		DiscoveryAddress: "agentiod.agentio-system.svc:15012",
		TrustDomain:      "cluster.local",
	}, krt.NewOptionsBuilder(stop, "config-debug-test", nil))
	if err != nil {
		t.Fatal(err)
	}
	if wait && !resourceCompiler.WaitUntilSynced(stop) {
		t.Fatal("compiler did not sync")
	}
	return configDebugFixture{sources: sources, compiler: resourceCompiler}
}

func populatedConfigDebugSources(t *testing.T, stop <-chan struct{}) Sources {
	t.Helper()
	sources := Sources{}
	options := []krt.CollectionOption{krt.WithStop(stop)}
	sources.AgentioConfig = krt.NewStaticCollection[model.AgentioConfiguration](nil, []model.AgentioConfiguration{{
		ResourceVersion: "config-rv",
		Value: &configv1.AgentioConfig{
			SandboxIgnoredLabels: []string{"drop-me"},
		},
	}}, options...)
	sources.TrafficPolicies = krt.NewStaticCollection[model.TrafficPolicy](nil, []model.TrafficPolicy{
		{Name: "traffic", Namespace: "demo", CreationTime: configDebugTestTime, Spec: validConfigDebugTrafficPolicySpec()},
		{Name: "global-traffic", Global: true, CreationTime: configDebugTestTime, Spec: validConfigDebugTrafficPolicySpec()},
	}, options...)
	sources.SecurityProfiles = krt.NewStaticCollection[model.SecurityProfile](nil, []model.SecurityProfile{
		{Name: "security", Namespace: "demo", CreationTime: configDebugTestTime},
		{Name: "global-security", Global: true, CreationTime: configDebugTestTime},
	}, options...)
	sources.Gateways = krt.NewStaticCollection[model.Gateway](nil, []model.Gateway{{
		Namespace: "agentio-system",
		Name:      "egress",
		Source:    model.GatewaySourceGatewayAPI,
		Config:    &configv1.EgressGateway{},
	}}, options...)
	patch, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace:       "demo",
		Name:            "patch-a",
		Source:          "configmap/demo-patches",
		ResourceVersion: "patch-rv",
		CreationTime:    configDebugTestTime,
	}, 10, []string{"agentio-system/egress"}, []model.EnvoyPatch{{
		Operation: model.PatchAdd,
		Target: model.ClusterPatch{
			Match: &model.ClusterMatch{Name: "outbound"},
			Value: &clusterv3.Cluster{Name: "debug-cluster", ConnectTimeout: durationpb.New(3 * time.Second)},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	sources.GatewayPatches = krt.NewStaticCollection[model.GatewayPatch](nil, []model.GatewayPatch{patch}, options...)
	telemetry, err := model.NewTelemetry(model.TelemetryMetadata{
		Namespace:       "demo",
		Name:            "telemetry",
		Source:          "configmap/demo-telemetry",
		ResourceVersion: "telemetry-rv",
		CreationTime:    configDebugTestTime,
	}, []string{"demo/egress"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sources.Telemetry = krt.NewStaticCollection[model.Telemetry](nil, []model.Telemetry{telemetry}, options...)
	return sources
}

func validConfigDebugTrafficPolicySpec() agentsv1alpha1.TrafficPolicySpec {
	return agentsv1alpha1.TrafficPolicySpec{
		Selector: metav1.LabelSelector{},
		Egress: &agentsv1alpha1.TrafficPolicyDirection{Rules: []agentsv1alpha1.TrafficPolicyRule{{
			Action: agentsv1alpha1.RuleActionAllow,
		}}},
	}
}

func waitForConfigDebugCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type neverConfigDebugSynced struct{}

func (neverConfigDebugSynced) HasSynced() bool { return false }

func (neverConfigDebugSynced) WaitUntilSynced(<-chan struct{}) bool { return false }

type orderedConfigDebugGatewayPatches struct {
	krt.Collection[model.GatewayPatch]
	values []model.GatewayPatch
}

func (c orderedConfigDebugGatewayPatches) List() []model.GatewayPatch {
	return append([]model.GatewayPatch(nil), c.values...)
}
