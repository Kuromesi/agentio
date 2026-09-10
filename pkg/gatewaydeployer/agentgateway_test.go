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

package gatewaydeployer

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

func agentgatewayFixture() (*gatewayv1.Gateway, *corev1.ConfigMap) {
	gw := egressGatewayFixture("agentgateway", "demo")
	gw.Spec.GatewayClassName = "agentio-agentgateway"
	gw.Spec.Infrastructure = &gatewayv1.GatewayInfrastructure{ParametersRef: &gatewayv1.LocalParametersReference{Group: "", Kind: "ConfigMap", Name: "agentgateway-config"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "agentgateway-config", Namespace: "demo"}, Data: map[string]string{agentgatewayConfigKey: "binds: []\n"}}
	return gw, cm
}

func agentgatewayRenderer(t *testing.T) *renderer {
	t.Helper()
	values := testValues(t, map[string]any{"global": map[string]any{"agentgateway": map[string]any{"image": "example.com/agentgateway:tested", "replicaCount": 2}}})
	r := testRenderer(t, values)
	contents := map[string]string{}
	for _, name := range []string{egressGatewayTemplateName, agentgatewayTemplateName} {
		content, err := os.ReadFile("templates/" + name + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		contents[name] = string(content)
	}
	if err := r.updateTemplates(contents, values, defaultProxyConfig()); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAgentgatewayDeploymentUsesFileConfig(t *testing.T) {
	gw, cm := agentgatewayFixture()
	gw.Annotations = map[string]string{"gateway.agentio.kruise.io/agentgateway-certs": "gateway-certs", "gateway.istio.io/agentgatewayImage": "untrusted/image"}
	gw.Spec.Infrastructure.Labels = map[gatewayv1.LabelKey]gatewayv1.LabelValue{"agentio.kruise.io/dataplane-mode": "sidecar"}
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	d := rig.newController()
	d.renderer = agentgatewayRenderer(t)
	if err := d.Reconcile(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}); err != nil {
		t.Fatal(err)
	}
	p := rig.patcher.find("deployments")
	if p == nil {
		t.Fatal("no Deployment created")
	}
	var dep appsv1.Deployment
	if err := json.Unmarshal(p.data, &dep); err != nil {
		t.Fatal(err)
	}
	pod := dep.Spec.Template
	c := pod.Spec.Containers[0]
	if c.Name != "agentgateway" || c.Image != "example.com/agentgateway:tested" || strings.Join(c.Args, " ") != "-f /etc/agentgateway/config.yaml" {
		t.Fatalf("wrong container: %+v", c)
	}
	if *dep.Spec.Replicas != 2 || pod.Annotations["gateway.agentio.kruise.io/config-hash"] == "" {
		t.Fatalf("bad rollout configuration: %+v", pod.ObjectMeta)
	}
	if pod.Labels[dataplaneModeLabel] != "none" {
		t.Fatal("gateway was enrolled in a data plane")
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Fatal("file mode should not mount a Kubernetes token")
	}
	if len(dep.OwnerReferences) != 1 || dep.OwnerReferences[0].Name != gw.Name {
		t.Fatal("Gateway ownership missing")
	}
	if pod.Spec.Volumes[0].ConfigMap.Name != cm.Name || pod.Spec.Volumes[2].Secret.SecretName != "gateway-certs" || c.VolumeMounts[0].SubPath != agentgatewayConfigKey {
		t.Fatal("config or certificate mounts are wrong")
	}
	for _, e := range c.Env {
		if e.Name == "XDS_ADDRESS" || e.Name == "CA_ADDRESS" {
			t.Fatal("file mode must not connect to unsupported xDS")
		}
	}
	if rig.patcher.find("configmaps") != nil || rig.patcher.find("secrets") != nil {
		t.Fatal("deployer adopted operator-owned input")
	}
	if rig.patcher.find("services") == nil || rig.patcher.find("serviceaccounts") == nil {
		t.Fatal("missing gateway children")
	}
}

func TestAgentgatewayInvalidConfigReportsStatusWithoutDeploying(t *testing.T) {
	for _, tc := range []string{"missing-ref", "wrong-kind", "missing-config", "other-namespace", "empty", "invalid-yaml"} {
		t.Run(tc, func(t *testing.T) {
			gw, cm := agentgatewayFixture()
			switch tc {
			case "missing-ref":
				gw.Spec.Infrastructure = nil
			case "wrong-kind":
				gw.Spec.Infrastructure.ParametersRef.Kind = "Secret"
			case "missing-config":
				gw.Spec.Infrastructure.ParametersRef.Name = "absent"
			case "other-namespace":
				cm.Namespace = "other"
			case "empty":
				cm.Data[agentgatewayConfigKey] = " "
			case "invalid-yaml":
				cm.Data[agentgatewayConfigKey] = "binds: ["
			}
			rig := newControllerTestRig(t, gw, cm)
			defer rig.close()
			d := rig.newController()
			d.renderer = agentgatewayRenderer(t)
			if err := d.Reconcile(types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}); err != nil {
				t.Fatal(err)
			}
			if rig.patcher.find("deployments") != nil {
				t.Fatal("invalid input deployed")
			}
			p := rig.patcher.find("gateways")
			if p == nil || !strings.Contains(string(p.data), "InvalidParameters") || !strings.Contains(string(p.data), `"status":"False"`) {
				t.Fatalf("missing failure status: %v", p)
			}
		})
	}
}

func TestAgentgatewayConfigUpdatesChangeRolloutHash(t *testing.T) {
	gw, cm := agentgatewayFixture()
	rig := newControllerTestRig(t, gw, cm)
	defer rig.close()
	d := rig.newController()
	input := buildTemplateInput(*gw, builtinClasses["agentio-agentgateway"], "cluster", 132, "")
	if err := d.agentgatewayInput(&input); err != nil {
		t.Fatal(err)
	}
	first := input.AgentgatewayConfigHash
	cm.Data[agentgatewayConfigKey] = "binds: []\nconfig: {adminAddr: '127.0.0.1:15000'}\n"
	if _, err := rig.kubeClient.CoreV1().ConfigMaps(cm.Namespace).Update(context.Background(), cm, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitCondition(t, time.Second, func() bool {
		return d.agentgatewayInput(&input) == nil && input.AgentgatewayConfigHash != first
	}, "updated config hash")
}

func TestGatewayTemplatesReloadAtomically(t *testing.T) {
	provider, err := newTemplateProvider(Options{}, defaultProxyConfig())
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{egressGatewayTemplateName: "kind: Service\nmetadata: {name: envoy}", agentgatewayTemplateName: "kind: Service\nmetadata: {name: agentgateway}"}
	encode := func() string {
		b, err := yaml.Marshal(injectorTemplateConfig{Templates: contents})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if err := provider.updateFromInjectorConfig(encode(), "global: {hub: good}"); err != nil {
		t.Fatal(err)
	}
	contents[egressGatewayTemplateName] = "kind: Service\nmetadata: {name: replaced}"
	contents[agentgatewayTemplateName] = "{{broken"
	if err := provider.updateFromInjectorConfig(encode(), "global: {hub: bad}"); err == nil {
		t.Fatal("malformed template accepted")
	}
	for name, want := range map[string]string{egressGatewayTemplateName: "envoy", agentgatewayTemplateName: "agentgateway"} {
		docs, err := provider.Renderer().Render(name, TemplateInput{})
		if err != nil || !strings.Contains(strings.Join(docs, ""), want) {
			t.Fatalf("lost last known template %s: %v", name, err)
		}
	}
	if nestedString(provider.currentValues(), "global", "hub") != "good" {
		t.Fatal("invalid update replaced values")
	}
	// Older injector ConfigMaps remain valid and remove the optional template.
	delete(contents, agentgatewayTemplateName)
	if err := provider.updateFromInjectorConfig(encode(), "global: {hub: old-chart}"); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Renderer().Render(agentgatewayTemplateName, TemplateInput{}); err == nil {
		t.Fatal("removed template remained active")
	}
}

func TestAgentgatewayChartTemplateMatches(t *testing.T) {
	local, err := os.ReadFile("templates/agentgateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	chart, err := os.ReadFile("../../manifests/charts/agentio/files/agentgateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if string(local) != string(chart) {
		t.Fatal("chart and tested agentgateway template diverged")
	}
}

func TestAgentgatewayProgrammedWaitsForNewConfig(t *testing.T) {
	replicas := int32(1)
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Generation: 2}, Spec: appsv1.DeploymentSpec{Replicas: &replicas,
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"gateway.agentio.kruise.io/config-hash": "new"}}}},
		Status: appsv1.DeploymentStatus{ObservedGeneration: 2, Replicas: 1, UpdatedReplicas: 1, AvailableReplicas: 1}}
	if !agentgatewayRolloutReady(dep, "new") {
		t.Fatal("completed rollout not ready")
	}
	if agentgatewayRolloutReady(dep, "newer") {
		t.Fatal("old config reported ready")
	}
	dep.Status.ObservedGeneration = 1
	if agentgatewayRolloutReady(dep, "new") {
		t.Fatal("unobserved deployment reported ready")
	}
	dep.Status.ObservedGeneration = 2
	dep.Status.Replicas = 2
	if agentgatewayRolloutReady(dep, "new") {
		t.Fatal("surging deployment reported ready")
	}
	dep.Status.Replicas = 1
	dep.Status.AvailableReplicas = 0
	if agentgatewayRolloutReady(dep, "new") {
		t.Fatal("unavailable deployment reported ready")
	}
}
