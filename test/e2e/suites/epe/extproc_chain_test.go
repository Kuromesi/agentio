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
//
// The chart-owned sandboxExtProc block is applied explicitly because the suite
// keeps its shared primary ConfigMap at the PASSTHROUGH-only baseline.

package epe

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// TestAdditionalExtProcChain exercises ConfigMap -> compiler -> xDS -> Envoy,
// with real EPE identity/policy processing and two independently named processors.
func TestAdditionalExtProcChain(t *testing.T) {
	environment, scope := rig.BeginScenario(t)
	ns := resolvedAgentioConfig.Namespace
	ctx, cancel := e2e.Context(t, 6*time.Minute)
	defer cancel()
	for _, name := range []string{"a", "b", "c"} {
		e2econfig.New(scope).
			Eval(ns, map[string]any{"Name": name, "Image": resolvedAgentioConfig.ExtProcImage}, chainFixtureYAML).
			ApplyOrFail(t, kube.CreateOnly)
		if _, err := environment.Kube.WaitReadyPods(ctx, ns, "app=chain-"+name, 1); err != nil {
			t.Fatal(err)
		}
	}
	e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"Client": trafficFixture.Client.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata: {name: extproc-chain}
spec:
  selector:
    matchLabels: {app: {{ .Client }}}
  rules:
  - name: chain
    match:
    - domains: ["*"]
      paths: [{type: Exact, value: /extproc-chain}]
    actions:
      headerManipulation:
        set: [{name: x-chain-request, value: epe}]
`).ApplyOrFail(t, kube.CreateOnly)
	apply := func(t *testing.T, order []string, replacement, disabled bool) {
		providers := []string{}
		for _, name := range order {
			service := name
			if replacement && name == "a" {
				service = "c"
			}
			providers = append(
				providers,
				fmt.Sprintf(
					`{name: %s, service: chain-%s.%s.svc.cluster.local, port: 9002, response: {headerMode: SEND}}`,
					name,
					service,
					ns,
				),
			)
		}
		override := ""
		if disabled {
			override = "extProc: {}"
		}
		rig.ApplyConfig(
			t,
			scope,
			map[string]any{
				"Namespace": ns,
				"EPE":       epeName,
				"Providers": "[" + strings.Join(providers, ",") + "]",
				"Override":  override,
			},
			`
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: {{ .EPE }}.{{ .Namespace }}.svc.cluster.local
      port: 9002
      messageTimeout: 5s
    additionalExtProcs: {{ .Providers }}
    egressGateways:
    - namespace: {{ .Namespace }}
      name: egress-gateway
      {{ .Override }}
    egressPolicies:
    - gateway: {service: egress-gateway.{{ .Namespace }}.svc.cluster.local}
      policy: GATEWAY
`,
		)
	}
	const payload = "body-delivered-on-demand"
	request := func(selected string) (http.Header, http.Header, error) {
		stdout, stderr, err := trafficFixture.Client.Exec(
			ctx,
			[]string{
				"curl",
				"--silent",
				"--show-error",
				"--max-time",
				"10",
				"--noproxy",
				"*",
				"--include",
				"--header",
				"x-extproc-body: " + selected,
				"--data-binary",
				payload,
				"http://" + trafficFixture.Server.Address() + "/extproc-chain",
			},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("curl: %w: %s", err, stderr)
		}
		response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(stdout)), nil)
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if closeErr != nil {
			return nil, nil, closeErr
		}
		if response.StatusCode != 200 {
			return nil, nil, fmt.Errorf("status %d: %s", response.StatusCode, body)
		}
		headers := http.Header{}
		for line := range strings.SplitSeq(string(body), "\n") {
			if value, ok := strings.CutPrefix(line, "RequestHeader="); ok {
				if k, v, ok := strings.Cut(value, ":"); ok {
					headers.Add(k, v)
				}
			}
		}
		return headers, response.Header, nil
	}
	verify := func(t *testing.T, wantRequest, wantResponse string) http.Header {
		var response http.Header
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			requestHeaders, responseHeaders, err := request("")
			if err != nil {
				return err
			}
			if requestHeaders.Get("X-Chain-Request") != wantRequest ||
				responseHeaders.Get("X-Chain-Response") != wantResponse {
				return fmt.Errorf(
					"chain request=%q response=%q, want %q / %q",
					requestHeaders.Get("X-Chain-Request"),
					responseHeaders.Get("X-Chain-Response"),
					wantRequest,
					wantResponse,
				)
			}
			response = responseHeaders
			return nil
		})
		t.Logf("request order=%q response order=%q", wantRequest, wantResponse)
		return response
	}
	podsBefore := func() map[string]string {
		pods, err := environment.Kube.ReadyPods(ctx, ns, "")
		if err != nil {
			t.Fatal(err)
		}
		result := map[string]string{}
		for _, pod := range pods {
			result[pod.Name] = string(pod.UID)
			for _, c := range pod.Status.ContainerStatuses {
				result[pod.Name+"/"+c.Name] = fmt.Sprint(c.RestartCount)
			}
		}
		return result
	}
	before := podsBefore()
	apply(t, []string{"a", "b"}, false, false)
	headers := verify(t, "epe,a,b", ",b,a")
	for _, name := range []string{"a", "b"} {
		if headers.Get("X-Chain-Body-Count-"+name) != "0" {
			t.Fatalf("unsolicited body at %s: %v", name, headers)
		}
	}
	t.Log("headers-only: both body counters are zero despite a nonempty POST body")
	// No retries: each selected processor must receive exactly one complete body.
	for _, selected := range []string{"a", "b", "a,b"} {
		h, r, err := request(selected)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"a", "b"} {
			want := ""
			if strings.Contains(selected, name) {
				want = payload
			}
			if h.Get("X-Chain-Body-"+name) != want {
				t.Fatalf("selected=%s processor=%s body=%q want=%q", selected, name, h.Get("X-Chain-Body-"+name), want)
			}
		}
		t.Logf(
			"selected=%s body counters a=%s b=%s",
			selected,
			r.Get("X-Chain-Body-Count-a"),
			r.Get("X-Chain-Body-Count-b"),
		)
	}
	headers = verify(t, "epe,a,b", ",b,a")
	for _, name := range []string{"a", "b"} {
		if headers.Get("X-Chain-Body-Count-"+name) != "2" {
			t.Fatalf("body count at %s: %v", name, headers)
		}
	}
	for _, tc := range []struct {
		name        string
		order       []string
		replacement bool
		disabled    bool
		request     string
		response    string
	}{
		{"reorder", []string{"b", "a"}, false, false, "epe,b,a", ",a,b"},
		{"endpoint-update", []string{"b", "a"}, true, false, "epe,b,c", ",c,b"},
		{"remove", []string{"a"}, true, false, "epe,c", ",c"},
		{"clear", nil, false, false, "epe", ""},
		{"restore", []string{"a", "b"}, false, false, "epe,a,b", ",b,a"},
		{"disable-gateway", []string{"a", "b"}, false, true, "", ""},
		{"restore-gateway", []string{"a", "b"}, false, false, "epe,a,b", ",b,a"},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			apply(t, tc.order, tc.replacement, tc.disabled)
			verify(t, tc.request, tc.response)
		}) {
			return
		}
	}
	if after := podsBefore(); !reflect.DeepEqual(before, after) {
		t.Fatalf("configuration update restarted/replaced Pods: before=%v after=%v", before, after)
	}
	t.Log("all ConfigMap hot updates took effect without Pod replacement or container restart")
}

const chainFixtureYAML = `
apiVersion: v1
kind: Service
metadata: {name: chain-{{ .Name }}}
spec:
  selector: {app: chain-{{ .Name }}}
  ports: [{name: grpc, port: 9002, targetPort: 9002}]
---
apiVersion: v1
kind: Pod
metadata:
  name: chain-{{ .Name }}
  labels: {app: chain-{{ .Name }}, agentio.kruise.io/dataplane-mode: none}
spec:
  containers:
  - name: ext-proc
    image: {{ .Image }}
    env: [{name: CHAIN_NAME, value: "{{ .Name }}"}]
    readinessProbe:
      tcpSocket: {port: 9002}
      periodSeconds: 1
`
