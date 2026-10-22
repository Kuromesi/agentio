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

package epe

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// This checks the shared deployed fixture contract. TestEPEHTTPCallout covers
// SecurityProfile distribution and the Envoy/EPE data path.
func TestHTTPCalloutFixture(t *testing.T) {
	rig.RequireLive(t)
	environment, scope := rig.BeginScenario(t)
	namespace := resolvedAgentioConfig.Namespace
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	e2econfig.New(scope).Eval(namespace, map[string]any{
		"Image": resolvedAgentioConfig.ExtProcImage,
	}, httpCalloutFixtureYAML).ApplyOrFail(t, kube.CreateOnly)
	if _, err := environment.Kube.WaitReadyPods(ctx, namespace, "app=httpcallout", 1); err != nil {
		t.Fatal(err)
	}
	endpoint := "http://httpcallout." + namespace + ".svc.cluster.local:8080"
	request := func(t *testing.T, path, payload string, status int) string {
		t.Helper()
		args := []string{"curl", "--silent", "--show-error", "--max-time", "10", "--noproxy", "*",
			"--write-out", "\n%{http_code}", endpoint + path}
		if payload != "" {
			args = append(args, "--header", "Content-Type: application/json", "--data-binary", payload)
		}
		out, stderr, err := trafficFixture.Client.Exec(ctx, args)
		if err != nil {
			t.Fatalf("request %s: %v: %s", path, err, stderr)
		}
		suffix := "\n" + strconv.Itoa(status)
		if !strings.HasSuffix(out, suffix) {
			t.Fatalf("%s: want HTTP %d, got %.300s", path, status, out)
		}
		return strings.TrimSuffix(out, suffix)
	}
	// Pod readiness can precede Service routing convergence at the caller.
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		out, stderr, err := trafficFixture.Client.Exec(ctx, []string{
			"curl", "--silent", "--show-error", "--max-time", "5", "--noproxy", "*",
			"--write-out", "%{http_code}", endpoint + "/healthz",
		})
		if err != nil {
			return fmt.Errorf("wait for callout Service: %w: %s", err, stderr)
		}
		if out != "200" {
			return fmt.Errorf("callout health response = %q, want HTTP 200 with an empty body", out)
		}
		return nil
	})
	for _, phase := range []string{"request", "response"} {
		for _, mode := range []string{"continue", "mutate", "respond", "status", "malformed", "oversize", "delay"} {
			t.Run(phase+"/"+mode, func(t *testing.T) {
				payload := `{"version":"0.1","phase":"request","request":{"method":"POST","body":"original"}}`
				if phase == "response" {
					payload = `{"version":"0.1","phase":"response","request":{"method":"POST"},"response":{"statusCode":200,"body":"original"}}`
				}
				path, status := "/"+mode, 200
				if mode == "delay" {
					path += "?duration=1ms"
				}
				if mode == "status" {
					status = 503
				}
				body := request(t, path, payload, status)
				switch mode {
				case "status":
					if body != "injected failure\n" {
						t.Fatalf("unexpected failure: %q", body)
					}
					return
				case "malformed":
					if json.Valid([]byte(body)) {
						t.Fatal("expected invalid decision JSON")
					}
					return
				case "oversize":
					if len(body) <= 1<<20 {
						t.Fatalf("response size = %d", len(body))
					}
					return
				}
				want := `{"version":"0.1"}`
				if mode == "mutate" {
					want = fmt.Sprintf(
						`{"version":"0.1",%q:{"headers":[{"operation":"set","name":"x-callout-verdict","value":"clean"}],"body":"changed by callout"}}`,
						phase,
					)
				}
				if mode == "respond" {
					want = `{"version":"0.1","action":"respond","response":{"statusCode":403,"body":"blocked by callout"}}`
				}
				var actual, expected any
				if err := json.Unmarshal([]byte(body), &actual); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(want), &expected); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(actual, expected) {
					t.Fatalf("decision = %s, want %s", body, want)
				}
			})
		}
	}
	request(t, "/continue", `{}`, 400)
	var stats struct {
		Calls    int64
		Active   int64
		Canceled int64
	}
	if err := json.Unmarshal([]byte(request(t, "/stats", "", 200)), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.Calls != 14 || stats.Active != 0 || stats.Canceled != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

const httpCalloutFixtureYAML = `
apiVersion: v1
kind: Service
metadata:
  name: httpcallout
spec:
  selector: {app: httpcallout}
  ports: [{name: http, port: 8080, targetPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata:
  name: httpcallout
  labels: {app: httpcallout, agentio.kruise.io/dataplane-mode: none}
spec:
  containers:
  - name: callout
    image: {{ .Image }}
    args: ["-http-callout-port=8080"]
    readinessProbe:
      httpGet: {path: /healthz, port: 8080}
      periodSeconds: 1
    resources:
      requests: {cpu: 10m, memory: 32Mi}
      limits: {cpu: 500m, memory: 128Mi}
`
