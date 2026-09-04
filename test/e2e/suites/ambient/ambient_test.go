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

package ambient

import (
	"context"
	"os"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
)

func TestAmbientComponentsReady(t *testing.T) {
	if os.Getenv("AGENTIO_E2E") != "1" {
		t.Skip("set AGENTIO_E2E=1 to run the live ambient product test")
	}
	environment := suite.Environment(t)
	waitContext, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, component := range []struct {
		name, selector string
	}{
		{name: "agentiod", selector: "app.kubernetes.io/name=agentiod"},
		{name: "CNI", selector: "app.kubernetes.io/name=agentio-cni"},
		{name: "ztunnel", selector: "app.kubernetes.io/name=ztunnel"},
	} {
		if _, err := environment.Kube.WaitReadyPods(waitContext, resolvedAgentioConfig.Namespace, component.selector, 1); err != nil {
			t.Fatalf("wait for %s: %v", component.name, err)
		}
	}
}

func TestAmbientDataplane(t *testing.T) {
	if os.Getenv("AGENTIO_E2E") != "1" {
		t.Skip("set AGENTIO_E2E=1 to run the live ambient product test")
	}
	environment := suite.Environment(t)
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()

	for _, instance := range []struct {
		name string
		pods []string
	}{
		{name: "client", pods: ambientClient.Pods()},
		{name: "server", pods: ambientServer.Pods()},
	} {
		for _, podName := range instance.pods {
			pod, err := environment.Cluster.Kube.CoreV1().Pods(ambientNamespace.Name()).Get(ctx, podName, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get ambient %s Pod %s: %v", instance.name, podName, err)
			}
			if got := pod.Annotations["ambient.istio.io/redirection"]; got != "enabled" {
				t.Fatalf("ambient %s Pod %s redirection annotation = %q, want enabled", instance.name, podName, got)
			}
		}
	}

	options := ambientServer.CallOptionsOrFail(t, "http")
	options.Check = check.OK()
	if _, err := ambientClient.Call(ctx, options); err != nil {
		t.Fatalf("ambient client-to-server request: %v", err)
	}
}
