// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"
	"k8s.io/kubectl/pkg/util/fieldpath"

	"istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/bootstrap/option"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/model"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test"
	testenv "istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/version"
)

func TestParseDownwardApi(t *testing.T) {
	cases := []struct {
		name string
		m    map[string]string
	}{
		{
			"empty",
			map[string]string{},
		},
		{
			"single",
			map[string]string{"foo": "bar"},
		},
		{
			"multi",
			map[string]string{
				"app":               "istio-ingressgateway",
				"chart":             "gateways",
				"heritage":          "Tiller",
				"istio":             "ingressgateway",
				"pod-template-hash": "54756dbcf9",
			},
		},
		{
			"multi line",
			map[string]string{
				"config": `foo: bar
other: setting`,
				"istio": "ingressgateway",
			},
		},
		{
			"weird values",
			map[string]string{
				"foo": `a1_-.as1`,
				"bar": `a=b`,
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// Using the function kubernetes actually uses to write this, we do a round trip of
			// map -> file -> map and ensure the input and output are the same
			got, err := ParseDownwardAPI(fieldpath.FormatMap(tt.m))
			if !reflect.DeepEqual(got, tt.m) {
				t.Fatalf("expected %v, got %v with err: %v", tt.m, got, err)
			}
		})
	}
}

func TestGetNodeMetaData(t *testing.T) {
	inputOwner := "test"
	inputWorkloadName := "workload"

	expectOwner := "test"
	expectWorkloadName := "workload"
	expectExitOnZeroActiveConnections := model.StringBool(true)

	t.Setenv(IstioMetaPrefix+"OWNER", inputOwner)
	t.Setenv(IstioMetaPrefix+"WORKLOAD_NAME", inputWorkloadName)

	dir, _ := os.Getwd()
	defer os.Chdir(dir)
	// prepare a pod label file
	tempDir := t.TempDir()
	os.Chdir(tempDir)
	os.MkdirAll("./etc/istio/pod/", os.ModePerm)
	os.WriteFile(constants.PodInfoLabelsPath, []byte(`istio-locality="region.zone.subzone"`), 0o600)

	node, err := GetNodeMetaData(MetadataOptions{
		ID:                          "test",
		Envs:                        os.Environ(),
		ExitOnZeroActiveConnections: true,
	})

	g := NewWithT(t)
	g.Expect(err).Should(BeNil())
	g.Expect(node.Metadata.Owner).To(Equal(expectOwner))
	g.Expect(node.Metadata.WorkloadName).To(Equal(expectWorkloadName))
	g.Expect(node.Metadata.ExitOnZeroActiveConnections).To(Equal(expectExitOnZeroActiveConnections))
	g.Expect(node.RawMetadata["OWNER"]).To(Equal(expectOwner))
	g.Expect(node.RawMetadata["WORKLOAD_NAME"]).To(Equal(expectWorkloadName))
	g.Expect(node.Metadata.Labels[model.LocalityLabel]).To(Equal("region/zone/subzone"))
}

func TestSetIstioVersion(t *testing.T) {
	test.SetForTest(t, &version.Info.Version, "binary")

	testCases := []struct {
		name            string
		meta            *model.BootstrapNodeMetadata
		binaryVersion   string
		expectedVersion string
	}{
		{
			name:            "if IstioVersion is not specified, set it from binary version",
			meta:            &model.BootstrapNodeMetadata{},
			expectedVersion: "binary",
		},
		{
			name: "if IstioVersion is specified, don't set it from binary version",
			meta: &model.BootstrapNodeMetadata{
				NodeMetadata: model.NodeMetadata{
					IstioVersion: "metadata-version",
				},
			},
			expectedVersion: "metadata-version",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ret := SetIstioVersion(tc.meta)
			if ret.IstioVersion != tc.expectedVersion {
				t.Fatalf("SetIstioVersion: expected '%s', got '%s'", tc.expectedVersion, ret.IstioVersion)
			}
		})
	}
}

func TestGetStatOptions(t *testing.T) {
	cases := []struct {
		name            string
		metadataOptions MetadataOptions
		// TODO(ramaraochavali): Add validation for prefix and tags also.
		wantInclusionSuffixes []string
	}{
		{
			name: "with exit on zero connections enabled",
			metadataOptions: MetadataOptions{
				ID:                          "test",
				Envs:                        os.Environ(),
				ProxyConfig:                 &v1alpha1.ProxyConfig{},
				ExitOnZeroActiveConnections: true,
			},
			wantInclusionSuffixes: []string{"rbac.allowed", "rbac.denied", "shadow_allowed", "shadow_denied", "downstream_cx_active"},
		},
		{
			name: "with exit on zero connections disabled",
			metadataOptions: MetadataOptions{
				ID:                          "test",
				Envs:                        os.Environ(),
				ProxyConfig:                 &v1alpha1.ProxyConfig{},
				ExitOnZeroActiveConnections: false,
			},
			wantInclusionSuffixes: []string{"rbac.allowed", "rbac.denied", "shadow_allowed", "shadow_denied"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(tt *testing.T) {
			node, _ := GetNodeMetaData(tc.metadataOptions)
			options := getStatsOptions(node.Metadata)
			templateParams, _ := option.NewTemplateParams(options...)
			inclusionSuffixes := templateParams["inclusionSuffix"]
			if !reflect.DeepEqual(inclusionSuffixes, tc.wantInclusionSuffixes) {
				tt.Errorf("unexpected inclusion suffixes. want: %v, got: %v", tc.wantInclusionSuffixes, inclusionSuffixes)
			}
		})
	}
}

func TestRequiredEnvoyStatsMatcherInclusionRegexes(t *testing.T) {
	ok, _ := regexp.MatchString(requiredEnvoyStatsMatcherInclusionRegexes, "vhost.default.local:18000.route.routev1.upstream_rq_200")
	if !ok {
		t.Fatal("requiredEnvoyStatsMatcherInclusionRegexes doesn't match the route's stat_prefix")
	}
}

func TestPolicyRuntimeBootstrapOption(t *testing.T) {
	proxyConfig := model.NodeMetaProxyConfig(v1alpha1.ProxyConfig{
		DiscoveryAddress: "agentiod.istio-system.svc:15012",
		ProxyMetadata:    map[string]string{},
	})
	node := &model.Node{
		ID:       "router~10.0.0.1~gateway.istio-system~istio-system.svc.cluster.local",
		Locality: &core.Locality{},
		Metadata: &model.BootstrapNodeMetadata{NodeMetadata: model.NodeMetadata{
			ProxyConfig:               &proxyConfig,
			MetadataDiscovery:         ptr.Of(model.StringBool(true)),
			PolicyRuntimeCapabilities: []string{"sni_traffic_policy"},
		}},
		RawMetadata: map[string]any{},
	}
	bootstrapConfig := Config{
		Node: node,
		PolicyStoreReferenceResolutionGracePeriod: 17 * time.Second,
	}
	params, err := bootstrapConfig.toTemplateParams()
	if err != nil {
		t.Fatal(err)
	}
	if enabled, ok := params["policy_store"].(bool); !ok || !enabled {
		t.Fatalf("policy_store template option = %#v, want true", params["policy_store"])
	}

	var rendered bytes.Buffer
	templatePath := filepath.Join(testenv.IstioSrc, "tools/packaging/common/envoy_bootstrap.json")
	if err := New(bootstrapConfig).WriteTo(templatePath, &rendered); err != nil {
		t.Fatalf("render bootstrap template: %v", err)
	}
	if !strings.Contains(rendered.String(), `"name": "kruise.bootstrap.policy_store"`) {
		t.Fatalf("rendered bootstrap does not contain kruise policy store extension: %s", rendered.String())
	}
	if !strings.Contains(rendered.String(),
		`"type_url": "type.googleapis.com/kruise.networking.policy_runtime.v1alpha1.PolicyStoreConfig"`) {
		t.Fatalf("rendered bootstrap does not use the policy runtime config TypeURL: %s", rendered.String())
	}
	if strings.Contains(rendered.String(), "kruise.networking.gateway_policy") {
		t.Fatalf("rendered bootstrap still uses the gateway-scoped policy package: %s", rendered.String())
	}
	if !strings.Contains(rendered.String(), `"reference_resolution_grace_period": "17s"`) {
		t.Fatalf("rendered bootstrap does not contain the configured reference resolution grace period: %s", rendered.String())
	}
}

// TestPolicyStoreReferenceResolutionGracePeriodIsProtoDuration renders the grace period for
// durations whose Go string form is not a legal google.protobuf.Duration and
// asserts Envoy's JSON parser would accept what we emit. time.Duration.String()
// produces "1m0s"/"500ms", which the Duration JSON mapping rejects, so a bootstrap
// built that way never loads and the proxy crash-loops.
func TestPolicyStoreReferenceResolutionGracePeriodIsProtoDuration(t *testing.T) {
	templatePath := filepath.Join(testenv.IstioSrc, "tools/packaging/common/envoy_bootstrap.json")
	for _, configured := range []time.Duration{
		15 * time.Second,
		17 * time.Second,
		time.Minute,
		90 * time.Second,
		time.Hour,
		500 * time.Millisecond,
		2*time.Minute + 500*time.Millisecond,
		// Zero falls back to defaultPolicyStoreReferenceResolutionGracePeriod rather than
		// being skipped, which would render an empty and equally invalid value.
		0,
	} {
		t.Run(configured.String(), func(t *testing.T) {
			proxyConfig := model.NodeMetaProxyConfig(v1alpha1.ProxyConfig{
				DiscoveryAddress: "agentiod.istio-system.svc:15012",
				ProxyMetadata:    map[string]string{},
			})
			bootstrapConfig := Config{
				Node: &model.Node{
					ID:       "router~10.0.0.1~gateway.istio-system~istio-system.svc.cluster.local",
					Locality: &core.Locality{},
					Metadata: &model.BootstrapNodeMetadata{NodeMetadata: model.NodeMetadata{
						ProxyConfig:               &proxyConfig,
						MetadataDiscovery:         ptr.Of(model.StringBool(true)),
						PolicyRuntimeCapabilities: []string{"sni_traffic_policy"},
					}},
					RawMetadata: map[string]any{},
				},
				PolicyStoreReferenceResolutionGracePeriod: configured,
			}
			var rendered bytes.Buffer
			if err := New(bootstrapConfig).WriteTo(templatePath, &rendered); err != nil {
				t.Fatalf("render bootstrap template: %v", err)
			}
			// Parsing the whole document also proves the template still emits valid
			// JSON, which a bad duration would not break on its own.
			got := referenceResolutionGracePeriodFromBootstrap(t, rendered.Bytes())

			var parsed durationpb.Duration
			if err := protojson.Unmarshal([]byte(strconv.Quote(got)), &parsed); err != nil {
				t.Fatalf("reference_resolution_grace_period %q is not a valid google.protobuf.Duration: %v", got, err)
			}
			want := configured
			if want <= 0 {
				want = defaultPolicyStoreReferenceResolutionGracePeriod
			}
			if parsed.AsDuration() != want {
				t.Fatalf("reference_resolution_grace_period %q = %v, want %v", got, parsed.AsDuration(), want)
			}
		})
	}
}

// referenceResolutionGracePeriodFromBootstrap digs the grace period out of the rendered
// bootstrap so the test asserts on what Envoy actually reads, not on a substring.
func referenceResolutionGracePeriodFromBootstrap(t *testing.T, rendered []byte) string {
	t.Helper()
	var doc struct {
		BootstrapExtensions []struct {
			Name        string `json:"name"`
			TypedConfig struct {
				Value struct {
					ReferenceResolutionGracePeriod string `json:"reference_resolution_grace_period"`
				} `json:"value"`
			} `json:"typed_config"`
		} `json:"bootstrap_extensions"`
	}
	if err := json.Unmarshal(rendered, &doc); err != nil {
		t.Fatalf("rendered bootstrap is not valid JSON: %v\n%s", err, rendered)
	}
	for _, extension := range doc.BootstrapExtensions {
		if extension.Name == "kruise.bootstrap.policy_store" {
			return extension.TypedConfig.Value.ReferenceResolutionGracePeriod
		}
	}
	t.Fatalf("rendered bootstrap has no kruise.bootstrap.policy_store extension:\n%s", rendered)
	return ""
}

func TestPolicyRuntimeCapabilitiesNodeMetadata(t *testing.T) {
	proxyConfig := &v1alpha1.ProxyConfig{ProxyMetadata: map[string]string{}}
	want := []string{
		"sni_traffic_policy",
		"other_policy",
	}
	node, err := GetNodeMetaData(MetadataOptions{
		ProxyConfig:               proxyConfig,
		PolicyRuntimeCapabilities: want,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(node.Metadata.PolicyRuntimeCapabilities, want) {
		t.Fatalf("POLICY_RUNTIME_CAPABILITIES = %v, want %v", node.Metadata.PolicyRuntimeCapabilities, want)
	}
}
