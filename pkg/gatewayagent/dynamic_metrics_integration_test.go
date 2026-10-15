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
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"google.golang.org/protobuf/encoding/protojson"
)

//go:embed testdata/dynamic-metrics.json
var dynamicMetricsFixture []byte

func TestCommunityEnvoyDynamicMetrics(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_ENVOY_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_ENVOY_BINARY")
	}
	module := os.Getenv("AGENTIO_TEST_METRICS_MODULE")
	if module == "" {
		module = "/usr/local/lib/libagentio_gateway_metrics.so"
	}
	if _, err := os.Stat(module); err != nil {
		t.Fatal(err)
	}
	c := testConfig(t)
	c.IP = "127.0.0.1"
	c.Proxy.AdminPort = int32(freePort(t))
	metricsPort, statusPort, businessPort := freePort(t), freePort(t), freePort(t)
	c.PrometheusPort, c.EnvoyStatusPort = metricsPort, statusPort
	agent := httptest.NewServer(proxyMetrics(c))
	defer agent.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(agent.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	agentPort, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	c.StatusPort = agentPort
	bootstrap, err := bootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	data, err := protojson.Marshal(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	var config, fixture map[string]any
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(dynamicMetricsFixture, &fixture); err != nil {
		t.Fatal(err)
	}
	delete(config, "dynamicResources")
	resources := config["staticResources"].(map[string]any)
	listener := fixture["static_resources"].(map[string]any)["listeners"].([]any)[0].(map[string]any)
	listener["address"].(map[string]any)["socket_address"].(map[string]any)["port_value"] = businessPort
	hcm := listener["filter_chains"].([]any)[0].(map[string]any)["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
	arrived := make(chan struct{})
	slow := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(arrived)
			<-r.Context().Done()
		}),
	)
	defer slow.Close()
	_, slowPort, err := net.SplitHostPort(strings.TrimPrefix(slow.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	var cluster map[string]any
	if err := json.Unmarshal(
		[]byte(
			fmt.Sprintf(
				`{"name":"slow","connect_timeout":"1s","type":"STATIC","load_assignment":{"cluster_name":"slow","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":%s}}}}]}]}}`,
				slowPort,
			),
		),
		&cluster,
	); err != nil {
		t.Fatal(err)
	}
	resources["clusters"] = append(resources["clusters"].([]any), cluster)
	virtualHost := hcm["route_config"].(map[string]any)["virtual_hosts"].([]any)[0].(map[string]any)
	virtualHost["routes"] = append(
		[]any{map[string]any{"match": map[string]any{"path": "/abort"}, "route": map[string]any{"cluster": "slow"}}},
		virtualHost["routes"].([]any)...)
	accessLog := hcm["access_log"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
	accessLog["dynamic_module_config"].(map[string]any)["module"].(map[string]any)["local"].(map[string]any)["filename"] = module
	resources["listeners"] = append(resources["listeners"].([]any), listener)
	config["stats_flush_on_admin"] = true
	delete(config, "statsFlushInterval")
	data, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "envoy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	command := exec.CommandContext(
		ctx,
		binary,
		"-c",
		path,
		"--concurrency",
		"2",
		"--disable-hot-restart",
		"--log-level",
		"warning",
	)
	command.Stdout, command.Stderr = &logs, &logs
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		var exitError *exec.ExitError
		if err := command.Wait(); err != nil && !errors.As(err, &exitError) {
			t.Error(err)
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/ready", c.Proxy.AdminPort))
		if err == nil {
			closeResource(response.Body)
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Envoy did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	codes := []int{200, 201, 204, 302, 403, 404, 418, 429, 500, 503, 504}
	// Do not follow redirects: each response is one downstream request.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, code := range codes {
		for range 3 {
			response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/%d", businessPort, code))
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, response.Body)
			closeResource(response.Body)
			if err != nil || response.StatusCode != code {
				t.Fatalf("status %d: response %d, error %v", code, response.StatusCode, err)
			}
		}
	}

	connection, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", businessPort))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(connection, "GET /abort HTTP/1.1\r\nHost: test\r\n\r\n"); err != nil {
		closeResource(connection)
		t.Fatal(err)
	}
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		closeResource(connection)
		t.Fatal("upstream never received abort request")
	}
	closeResource(connection)
	// Both externally supported scrape paths must expose the same metric contract.
	for _, url := range []string{agent.URL + "/stats/prometheus", fmt.Sprintf("http://127.0.0.1:%d/stats/prometheus", metricsPort)} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			response, err := client.Get(url)
			if err != nil {
				t.Fatal(err)
			}
			parser := expfmt.NewTextParser(model.UTF8Validation)
			families, err := parser.TextToMetricFamilies(response.Body)
			closeResource(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			counts := map[string]float64{}
			for _, metric := range families["istio_requests_total"].GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "response_code" {
						counts[label.GetValue()] = metric.GetCounter().GetValue()
					}
				}
			}
			duration := families["istio_request_duration_milliseconds"]
			if duration == nil || len(duration.Metric) != 1 {
				t.Fatal("missing aggregate duration histogram")
			}
			histogram := duration.Metric[0].GetHistogram()
			// Admin-triggered histogram merging finishes asynchronously on worker threads.
			if histogram.GetSampleCount() != uint64(len(codes)*3+1) || counts["0"] != 1 {
				if time.Now().After(deadline) {
					t.Fatalf("histogram count %d, aborted count %v", histogram.GetSampleCount(), counts["0"])
				}
				time.Sleep(20 * time.Millisecond)
				continue
			}
			for _, code := range codes {
				if counts[strconv.Itoa(code)] != 3 {
					t.Fatalf("%s: code %d count %v", url, code, counts[strconv.Itoa(code)])
				}
			}
			wantBuckets := []float64{
				0.5,
				1,
				5,
				10,
				25,
				50,
				100,
				250,
				500,
				1000,
				2500,
				5000,
				10000,
				30000,
				60000,
				300000,
				600000,
				1800000,
				3600000,
				math.Inf(1),
			}
			if len(histogram.Bucket) != len(wantBuckets) {
				t.Fatalf("buckets = %v", histogram.Bucket)
			}
			for i, bucket := range histogram.Bucket {
				if bucket.GetUpperBound() != wantBuckets[i] {
					t.Fatalf("bucket %d = %v", i, bucket)
				}
			}
			for name := range families {
				if strings.HasPrefix(name, "envoy_agentio_gateway_istio_") {
					t.Fatalf("untranslated metric %s", name)
				}
			}
			break
		}
	}
}
