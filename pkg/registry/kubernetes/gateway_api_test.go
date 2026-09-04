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

package kubernetes

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestDecodeEgressGatewayReusesTransferSchema(t *testing.T) {
	config, err := decodeEgressGateway(`
tlsTermination:
  includeHosts: ["*.example.com"]
extProc:
  service: gateway-ext-proc.agentio-system.svc.cluster.local
  port: 9003
connectionPool:
  http:
    streamIdleTimeout: 90s
connectRateLimit:
  tokenBucket:
    maxTokens: 20
    tokensPerFill: 5
    fillInterval: 1s
serviceEntries:
- hosts: [" API.Example.COM. "]
  endpoints:
  - address: " 10.10.20.30 "
`)
	if err != nil {
		t.Fatalf("decodeEgressGateway(): %v", err)
	}
	if got := config.GetTlsTermination().GetIncludeHosts(); len(got) != 1 || got[0] != "*.example.com" {
		t.Fatalf("TLS termination hosts = %v", got)
	}
	if config.GetExtProc().GetService() != "gateway-ext-proc.agentio-system.svc.cluster.local" ||
		config.GetExtProc().GetPort() != 9003 {
		t.Fatalf("ext_proc = %+v", config.GetExtProc())
	}
	if got := config.GetConnectionPool().GetHttp().GetStreamIdleTimeout().AsDuration(); got != 90*time.Second {
		t.Fatalf("stream idle timeout = %s", got)
	}
	if got := config.GetConnectRateLimit().GetTokenBucket().GetMaxTokens(); got != 20 {
		t.Fatalf("connect rate max tokens = %d", got)
	}
	entry := config.GetServiceEntries()[0]
	if got := entry.GetHosts()[0]; got != "api.example.com" {
		t.Fatalf("static service host = %q, want canonical host", got)
	}
	if got := entry.GetEndpoints()[0].GetAddress(); got != "10.10.20.30" {
		t.Fatalf("static endpoint address = %q, want canonical IPv4 address", got)
	}
}

func TestDecodeEgressGatewayRejectsEmbeddedIdentity(t *testing.T) {
	for _, content := range []string{
		"name: egress",
		"namespace: agentio-system",
	} {
		if _, err := decodeEgressGateway(content); err == nil {
			t.Fatalf("decodeEgressGateway(%q) accepted embedded identity", content)
		}
	}
}

func TestGatewayAPIConfigurationsResolveSameNamespaceParameters(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	gateways := krt.NewStaticCollection[*gatewayv1.Gateway](nil, nil, options...)
	classes := krt.NewStaticCollection[*gatewayv1.GatewayClass](nil, nil, options...)
	configMaps := krt.NewStaticCollection[*corev1.ConfigMap](nil, nil, options...)
	configurations := newGatewayAPIConfigurations(gateways, classes, configMaps, options...)

	classes.ConditionalUpdateObject(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-egress"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: agentioGatewayController,
		},
	})
	configMaps.ConditionalUpdateObject(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "egress-parameters",
		},
		Data: map[string]string{
			gatewayConfigKey: `extProc:
  service: gateway-ext-proc.demo.svc.cluster.local
  port: 9003
`,
		},
	})
	configMaps.ConditionalUpdateObject(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "other",
			Name:      "egress-parameters",
		},
		Data: map[string]string{
			gatewayConfigKey: "name: must-not-be-read",
		},
	})
	gateways.ConditionalUpdateObject(&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "egress",
			Labels:    map[string]string{"istio.io/rev": "canary"},
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: &gatewayv1.LocalParametersReference{
					Kind: "ConfigMap",
					Name: "egress-parameters",
				},
			},
		},
	})

	if !configurations.WaitUntilSynced(stop) {
		t.Fatal("Gateway API configuration collection did not sync")
	}
	eventually(t, func() bool {
		gateway := configurations.GetKey("demo/egress")
		return gateway != nil &&
			gateway.Source == model.GatewaySourceGatewayAPI &&
			gateway.Config.GetExtProc().GetService() == "gateway-ext-proc.demo.svc.cluster.local"
	}, "same-namespace Gateway parameters")
}

func TestGatewayAPIConfigurationsRetainLastKnownGoodParameters(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	gateways := krt.NewStaticCollection[*gatewayv1.Gateway](nil, nil, options...)
	classes := krt.NewStaticCollection[*gatewayv1.GatewayClass](nil, nil, options...)
	configMaps := krt.NewStaticCollection[*corev1.ConfigMap](nil, nil, options...)
	configurations := newGatewayAPIConfigurations(gateways, classes, configMaps, options...)
	classes.ConditionalUpdateObject(&gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "agentio-egress"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: agentioGatewayController,
		},
	})
	parameters := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "parameters",
		},
		Data: map[string]string{
			gatewayConfigKey: "extProc:\n  service: valid.demo.svc.cluster.local\n",
		},
	}
	configMaps.ConditionalUpdateObject(parameters)
	gateways.ConditionalUpdateObject(&gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "egress",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "agentio-egress",
			Infrastructure: &gatewayv1.GatewayInfrastructure{
				ParametersRef: &gatewayv1.LocalParametersReference{
					Kind: "ConfigMap",
					Name: "parameters",
				},
			},
		},
	})
	if !configurations.WaitUntilSynced(stop) {
		t.Fatal("Gateway API configuration collection did not sync")
	}
	eventually(t, func() bool {
		gateway := configurations.GetKey("demo/egress")
		return gateway != nil && gateway.Config.GetExtProc().GetService() == "valid.demo.svc.cluster.local"
	}, "valid initial Gateway parameters")

	invalid := parameters.DeepCopy()
	invalid.Data[gatewayConfigKey] = "extProc: ["
	configMaps.ConditionalUpdateObject(invalid)
	time.Sleep(100 * time.Millisecond)
	gateway := configurations.GetKey("demo/egress")
	if gateway == nil || gateway.Config.GetExtProc().GetService() != "valid.demo.svc.cluster.local" {
		t.Fatalf("invalid parameters replaced last-known-good Gateway: %+v", gateway)
	}

	invalidStaticEntry := parameters.DeepCopy()
	invalidStaticEntry.Data[gatewayConfigKey] = `serviceEntries:
- hosts: ["*.example.com"]
  endpoints:
  - address: 10.10.20.30
`
	configMaps.ConditionalUpdateObject(invalidStaticEntry)
	time.Sleep(100 * time.Millisecond)
	gateway = configurations.GetKey("demo/egress")
	if gateway == nil || gateway.Config.GetExtProc().GetService() != "valid.demo.svc.cluster.local" {
		t.Fatalf("invalid static service entry replaced last-known-good Gateway: %+v", gateway)
	}
}
