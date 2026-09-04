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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type parityFixture struct {
	Name         string
	TemplateName string
	Gateway      *gatewayv1.Gateway
}

func parityFixtures() []parityFixture {
	mesh := gatewayv1.ProtocolType("HBONE")
	return []parityFixture{
		{
			Name:         "egress-minimal",
			TemplateName: "egress-gateway",
			Gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: "egress", Namespace: "agentio-system", UID: "uid-1",
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "agentio-egress",
					Listeners: []gatewayv1.Listener{
						{Name: "mesh", Port: 15008, Protocol: mesh},
					},
				},
			},
		},
		{
			Name:         "egress-annotated",
			TemplateName: "egress-gateway",
			Gateway: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: "egress-custom", Namespace: "demo", UID: "uid-2",
					Labels: map[string]string{"team": "search"},
					Annotations: map[string]string{
						"gateway.agentio.kruise.io/service-type":    "NodePort",
						"gateway.agentio.kruise.io/name-override":   "egress-renamed",
						"gateway.agentio.kruise.io/service-account": "egress-sa",
					},
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "agentio-egress",
					Infrastructure: &gatewayv1.GatewayInfrastructure{
						Labels: map[gatewayv1.LabelKey]gatewayv1.LabelValue{
							"infra":                     "yes",
							"agentio.kruise.io/network": "edge-net",
						},
						Annotations: map[gatewayv1.AnnotationKey]gatewayv1.AnnotationValue{"note": "keep"},
					},
					Listeners: []gatewayv1.Listener{
						{Name: "mesh", Port: 15008, Protocol: mesh},
					},
				},
			},
		},
	}
}

// parityValuesOverlay mirrors runtimeOverlay() in values.go plus a pinned image.
func parityValuesOverlay() map[string]any {
	return mergeMaps(runtimeOverlay(Options{
		ClusterID:       "test-cluster",
		SystemNamespace: "agentio-system",
		TrustDomain:     "cluster.local",
		ClusterDomain:   "cluster.local",
		CAAddress:       "agentiod.agentio-system.svc:15012",
	}), map[string]any{
		"global": map[string]any{"hub": "example.com/agentio", "tag": "1.0.0-test"},
	})
}

const parityKubeVersion = 133
