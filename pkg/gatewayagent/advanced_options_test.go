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

package gatewayagent

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
)

func configuredBootstrap(t *testing.T) Config {
	t.Helper()
	c := testConfig(t)
	raw := `{
 "statsEvictionInterval":"30s",
 "statsMatcher":{"inclusionPrefixes":["http.{pod_ip}_","cluster.telemetry"],"inclusionSuffixes":["upstream_rq_total"],"inclusionRegexps":["http.*"]},
 "extraStatTags":["team"],"histogramBuckets":{"http.":[1,5,10]},
 "runtimeValues":{"envoy.reloadable_features.http_reject_path_with_fragment":true},
 "maxDownstreamConnections":1000,"adminPort":16000,"statusPort":16020,"envoyStatusPort":16021,"prometheusPort":16090,
 "metricsLocalhostOnly":true,"statusProxyProtocol":true,"instanceIPs":["10.0.0.1","2001:db8::1"],
 "locality":{"region":"test","zone":"a"},
 "telemetryClusters":[{"name":"telemetry","type":"STATIC","connect_timeout":"1s","http2_protocol_options":{},"load_assignment":{"cluster_name":"telemetry","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":4317}}}}]}]}}],
 "statsSinks":[{"name":"envoy.stat_sinks.statsd","typed_config":{"@type":"type.googleapis.com/envoy.config.metrics.v3.StatsdSink","address":{"socket_address":{"address":"127.0.0.1","port_value":8125,"protocol":"UDP"}}}}],
 "tracing":{"http":{"name":"envoy.tracers.zipkin","typed_config":{"@type":"type.googleapis.com/envoy.config.trace.v3.ZipkinConfig","collector_cluster":"telemetry","collector_endpoint":"/api/v2/spans","collector_endpoint_version":"HTTP_JSON"}}},
 "loadStatsConfig":{"api_type":"GRPC","transport_api_version":"V3","grpc_services":[{"envoy_grpc":{"cluster_name":"telemetry"}}]},
 "outlierEventLog":"/tmp/gateway-outlier-test.log"
 }`
	if err := json.Unmarshal([]byte(raw), &c.AdvancedOptions); err != nil {
		t.Fatal(err)
	}
	c.applyCredentialPaths()
	return c
}

func TestConfiguredBootstrap(t *testing.T) {
	c := configuredBootstrap(t)
	b, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if !b.GetClusterManager().GetEnableDeferredClusterCreation() {
		t.Fatal("telemetry configuration disabled deferred cluster creation")
	}
	if b.GetStatsEvictionInterval().AsDuration() != 30*time.Second || b.Node.Locality.Zone != "a" ||
		len(b.StatsSinks) != 1 ||
		len(b.StaticResources.Clusters) != 4 {
		t.Fatal("missing configured native resource")
	}
	if len(b.StaticResources.Listeners[0].AdditionalAddresses) != 1 ||
		len(b.StaticResources.Listeners[0].ListenerFilters) != 1 ||
		!b.StaticResources.Listeners[0].BypassOverloadManager {
		t.Fatal("listener options not applied")
	}
	if b.StaticResources.Listeners[1].Address.GetSocketAddress().Address != "127.0.0.1" ||
		b.Admin.Address.GetSocketAddress().PortSpecifier == nil {
		t.Fatal("listener address/port ignored")
	}
	content, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"downstream_cx_active", "histogram_bucket_settings", "global_downstream_max_connections", "outlier_detection", "load_stats_config", "team", "http.10.0.0.1_"} {
		if !strings.Contains(string(content), required) {
			t.Fatalf("missing %s", required)
		}
	}
}

// The pinned binary must accept configured resources, not just defaults.
func TestEnvoyConfiguredBootstrap(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	c := configuredBootstrap(t)
	b, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	content, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), binary, "--mode", "validate", "-c", path, "--concurrency", "1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("configured bootstrap: %v\n%s", err, output)
	}
}

func TestAdvancedOptionValidation(t *testing.T) {
	for _, raw := range []string{`{"statsEvictionInterval":"11s"}`, `{"statsEvictionInterval":"0s"}`, `{"adminPort":15020}`, `{"policyStore":true}`, `{"rsaKeySize":1024}`, `{"eccCurve":"typo"}`, `{"rotationGraceRatio":1}`, `{"rotationJitter":0.6}`, `{"xdsHeaders":{"authorization":"forged"}}`, `{"instanceIPs":["not-ip"]}`} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("AGENTIO_GATEWAY_CONFIG", raw)
			if _, err := LoadConfig(nil, io.Discard); err == nil {
				t.Fatal("accepted invalid options")
			}
		})
	}
}

func TestWorkloadKeyOptions(t *testing.T) {
	for _, curve := range []string{"", "P256", "P384"} {
		for _, pkcs8 := range []bool{false, true} {
			c := testConfig(t)
			c.ECCCurve = curve
			c.PKCS8 = pkcs8
			_, encoded, err := generateWorkloadKey(c)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(encoded)
			if block == nil {
				t.Fatal("invalid PEM")
			}
			if pkcs8 {
				_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			} else if curve != "" {
				_, err = x509.ParseECPrivateKey(block.Bytes)
			} else {
				_, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
