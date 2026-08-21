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

package gateway

import (
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayapi "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"

	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/test/util/file"
	"istio.io/istio/pkg/test/util/tmpl"
	"istio.io/istio/pkg/test/util/yml"
)

const agentioSandboxEgressLabel = "networking.agents.kruise.io/sandbox-egress"

func renderAgentioWaypointDeployment(t *testing.T, sandboxEgress, sniTrafficPolicyEnabled bool) *appsv1.Deployment {
	t.Helper()

	template, err := inject.ParseTemplates(map[string]string{
		"waypoint": file.AsStringOrFail(t, filepath.Join(
			env.IstioSrc, "manifests/charts/agentio/files/waypoint-injection-template.yaml")),
	})
	if err != nil {
		t.Fatal(err)
	}

	policyEnv := ""
	if sniTrafficPolicyEnabled {
		policyEnv = "\n    ENABLE_SNI_TRAFFIC_POLICY: true"
	}
	values, err := inject.NewValuesConfig(`
global:
  hub: test
  tag: test
  pilotCertProvider: istiod
  proxy:
    image: proxyv2
    clusterDomain: cluster.local
    readinessFailureThreshold: 4
    readinessInitialDelaySeconds: 0
    readinessPeriodSeconds: 15
  waypoint: {}
pilot:
  env:
    PILOT_ENABLE_AMBIENT: "true"` + policyEnv)
	if err != nil {
		t.Fatal(err)
	}

	labels := map[string]string{}
	if sandboxEgress {
		labels[agentioSandboxEgressLabel] = "true"
	}
	gw := &gatewayapi.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress",
			Namespace: "agentio-system",
		},
		Spec: gatewayapi.GatewaySpec{
			GatewayClassName: "istio-waypoint",
		},
	}
	proxyConfig := mesh.DefaultProxyConfig()
	input := derivedInput{
		TemplateInput: TemplateInput{
			Gateway:              gw,
			GatewayClass:         "istio-waypoint",
			DeploymentName:       "egress",
			ServiceAccount:       "egress",
			KubeVersion:          30,
			ProxyUID:             1337,
			ProxyGID:             1337,
			InfrastructureLabels: labels,
			GatewayNameLabel:     "gateway.networking.k8s.io/gateway-name",
			ControllerLabel:      "istio.io-mesh-controller",
		},
		ProxyImage:  "example.com/proxyv2:test",
		ProxyConfig: proxyConfig,
		MeshConfig:  mesh.DefaultMeshConfig(),
		Values:      values.Map(),
	}

	rendered, err := tmpl.Execute(template["waypoint"], input)
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range yml.SplitString(rendered) {
		var typeMeta metav1.TypeMeta
		if err := yaml.Unmarshal([]byte(document), &typeMeta); err != nil {
			t.Fatal(err)
		}
		if typeMeta.Kind != "Deployment" {
			continue
		}
		deployment := &appsv1.Deployment{}
		if err := yaml.Unmarshal([]byte(document), deployment); err != nil {
			t.Fatal(err)
		}
		return deployment
	}
	t.Fatal("waypoint template did not render a Deployment")
	return nil
}

func TestAgentioWaypointPolicyCapabilities(t *testing.T) {
	const sniTrafficPolicyCapability = "sni_traffic_policy"
	tests := []struct {
		name                    string
		sandboxEgress           bool
		sniTrafficPolicyEnabled bool
		want                    bool
	}{
		{
			name:                    "enabled sandbox egress gateway",
			sandboxEgress:           true,
			sniTrafficPolicyEnabled: true,
			want:                    true,
		},
		{
			name:                    "ordinary waypoint",
			sniTrafficPolicyEnabled: true,
		},
		{
			name:          "feature disabled",
			sandboxEgress: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deployment := renderAgentioWaypointDeployment(t, tt.sandboxEgress, tt.sniTrafficPolicyEnabled)
			capabilities := map[string]*corev1.EnvVar{}
			for i := range deployment.Spec.Template.Spec.Containers[0].Env {
				envVar := &deployment.Spec.Template.Spec.Containers[0].Env[i]
				if envVar.Name == "POLICY_BINDING_DISCOVERY" || envVar.Name == "POLICY_RUNTIME_CAPABILITIES" {
					capabilities[envVar.Name] = envVar
				}
			}
			if tt.want {
				if capability := capabilities["POLICY_BINDING_DISCOVERY"]; capability == nil || capability.Value != "true" {
					t.Fatalf("POLICY_BINDING_DISCOVERY = %#v, want true", capability)
				}
				if capability := capabilities["POLICY_RUNTIME_CAPABILITIES"]; capability == nil || capability.Value != sniTrafficPolicyCapability {
					t.Fatalf("POLICY_RUNTIME_CAPABILITIES = %#v, want %q", capability, sniTrafficPolicyCapability)
				}
			} else if len(capabilities) != 0 {
				t.Fatalf("policy capabilities = %#v, want absent", capabilities)
			}
		})
	}
}
