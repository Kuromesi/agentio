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

package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/openkruise/agentio/pkg/kube"
)

func TestAgentioKubernetesAPILimits(t *testing.T) {
	const helper = "AGENTIO_KUBERNETES_RATE_HELPER"
	if mode := os.Getenv(helper); mode != "" {
		wantQPS, wantBurst := float32(80), 160
		if mode == "override" {
			wantQPS, wantBurst = 41.5, 83
		}
		path := filepath.Join(t.TempDir(), "kubeconfig")
		data := []byte(`apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: test
  context:
    cluster: test
    user: test
current-context: test
users:
- name: test
  user: {}
`)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		config, err := kubernetesRESTConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		if config.Host != "https://127.0.0.1:6443" || config.QPS != wantQPS || config.Burst != wantBurst {
			t.Fatalf("REST config host=%q QPS=%v burst=%v, want kubeconfig host and %v/%v", config.Host, config.QPS, config.Burst, wantQPS, wantBurst)
		}
		client, err := kube.NewClient(config)
		if err != nil {
			t.Fatal(err)
		}
		limiter := client.Kube().CoreV1().RESTClient().GetRateLimiter()
		if limiter == nil || limiter.QPS() != wantQPS {
			t.Fatalf("Kubernetes client limiter = %v, want QPS %v", limiter, wantQPS)
		}
		return
	}
	for _, mode := range []string{"default", "override"} {
		t.Run(mode, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=^TestAgentioKubernetesAPILimits$")
			command.Env = append(environmentWithout(os.Environ(),
				"AGENTIO_KUBERNETES_API_QPS", "AGENTIO_KUBERNETES_API_BURST", helper), helper+"="+mode)
			if mode == "override" {
				command.Env = append(command.Env, "AGENTIO_KUBERNETES_API_QPS=41.5", "AGENTIO_KUBERNETES_API_BURST=83")
			}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("subprocess failed: %v\n%s", err, output)
			}
		})
	}
}
