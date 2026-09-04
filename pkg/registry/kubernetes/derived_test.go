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
	"sort"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
	"istio.io/istio/pkg/util/sets"
)

func TestWorkloadServicePortsNormalizeServiceAndEndpointIntent(t *testing.T) {
	service := serviceFromKubernetes("cluster.local", &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"},
		Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
			{Name: "numeric", Port: 80, TargetPort: intstr.FromInt32(8080), Protocol: corev1.ProtocolTCP},
			{Name: "named", Port: 81, TargetPort: intstr.FromString("http-backend"), Protocol: corev1.ProtocolTCP},
		}},
	})
	if len(service.Ports) != 2 {
		t.Fatalf("service ports = %+v, want 2", service.Ports)
	}
	if got := service.Ports[0]; got.Name != "numeric" || got.Port != 80 || got.TargetPort != 8080 || got.TargetPortName != "" || got.Protocol != "TCP" {
		t.Fatalf("numeric service port = %+v", got)
	}
	if got := service.Ports[1]; got.Name != "named" || got.Port != 81 || got.TargetPort != 0 || got.TargetPortName != "http-backend" || got.Protocol != "TCP" {
		t.Fatalf("named service port = %+v", got)
	}

	portName := "named"
	udpPortName := "named-udp"
	port := int32(9090)
	protocol, udpProtocol := corev1.ProtocolTCP, corev1.ProtocolUDP
	ready, serving, terminating := false, true, true
	endpoints := endpointsFromSlice("cluster.local", &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "backend-abc",
			Labels: map[string]string{discoveryv1.LabelServiceName: "backend"},
		},
		Ports: []discoveryv1.EndpointPort{
			{Name: &portName, Port: &port, Protocol: &protocol},
			{Name: &udpPortName, Port: &port, Protocol: &udpProtocol},
		},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"10.0.0.1"},
			Conditions: discoveryv1.EndpointConditions{
				Ready: &ready, Serving: &serving, Terminating: &terminating,
			},
			TargetRef: &corev1.ObjectReference{Kind: "Pod", Name: "pod-a", UID: types.UID("pod-a-uid")},
		}},
	})
	if len(endpoints) != 1 {
		t.Fatalf("endpoints = %+v, want 1", endpoints)
	}
	got := endpoints[0]
	if got.PortName != "named" || got.Port != 9090 || got.Protocol != "TCP" {
		t.Fatalf("endpoint port = %+v", got)
	}
	if got.TargetUID != "pod-a-uid" || got.TargetName != "pod-a" || got.TargetNamespace != "demo" || !got.HasTargetRef {
		t.Fatalf("endpoint target = %+v", got)
	}
	if got.Ready {
		t.Fatalf("terminating serving endpoint became ready: %+v", got)
	}
}

func TestHeadlessServiceDoesNotPublishNoneAddress(t *testing.T) {
	service := serviceFromKubernetes("cluster.local", &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "manual"},
		Spec: corev1.ServiceSpec{
			ClusterIP:  corev1.ClusterIPNone,
			ClusterIPs: []string{corev1.ClusterIPNone},
		},
	})
	if len(service.Addresses) != 0 {
		t.Fatalf("headless service addresses = %v, want none", service.Addresses)
	}
}

func TestServiceTrafficPolicyTranslation(t *testing.T) {
	local := corev1.ServiceInternalTrafficPolicyLocal
	preferSameNode := corev1.ServiceTrafficDistributionPreferSameNode
	service := serviceFromKubernetes("cluster.local", &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "backend"},
		Spec: corev1.ServiceSpec{
			InternalTrafficPolicy: &local,
			TrafficDistribution:   &preferSameNode,
			IPFamilies:            []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol},
		},
	})
	if !service.InternalTrafficPolicyLocal {
		t.Fatal("internalTrafficPolicy=Local was not translated")
	}
	if service.TrafficDistribution != model.TrafficDistributionPreferSameNode {
		t.Fatalf("traffic distribution = %v, want PreferSameNode", service.TrafficDistribution)
	}
	if service.IPFamilies != model.IPFamiliesDual {
		t.Fatalf("ip families = %v, want dual", service.IPFamilies)
	}

	annotated := serviceFromKubernetes("cluster.local", &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "annotated",
			Annotations: map[string]string{"networking.istio.io/traffic-distribution": "PreferClose"},
		},
		Spec: corev1.ServiceSpec{IPFamilies: []corev1.IPFamily{corev1.IPv6Protocol}},
	})
	if annotated.TrafficDistribution != model.TrafficDistributionPreferSameZone {
		t.Fatalf("annotated traffic distribution = %v, want PreferSameZone", annotated.TrafficDistribution)
	}
	if annotated.IPFamilies != model.IPFamiliesIPv6Only {
		t.Fatalf("annotated ip families = %v, want IPv6 only", annotated.IPFamilies)
	}
	if annotated.InternalTrafficPolicyLocal {
		t.Fatal("cluster internal traffic policy became local")
	}
}

func TestServicePreservesWDSNetworkingSemantics(t *testing.T) {
	h2c := "kubernetes.io/h2c"
	grpc := "grpc"
	service := serviceFromKubernetes("cluster.local", &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "backend",
		},
		Spec: corev1.ServiceSpec{
			PublishNotReadyAddresses: true,
			Ports: []corev1.ServicePort{
				{
					Name: "http-api",
					Port: 80,
				},
				{
					Name:        "backend",
					Port:        81,
					AppProtocol: &h2c,
				},
				{
					Name:        "rpc",
					Port:        82,
					AppProtocol: &grpc,
				},
			},
		},
	})

	if !service.Canonical {
		t.Fatal("Kubernetes Service was not marked canonical")
	}
	if !service.PublishNotReadyAddresses {
		t.Fatal("publishNotReadyAddresses was not preserved")
	}
	want := []model.AppProtocol{
		model.AppProtocolHTTP11,
		model.AppProtocolHTTP2,
		model.AppProtocolGRPC,
	}
	for index, port := range service.Ports {
		if port.AppProtocol != want[index] {
			t.Fatalf("port %d app protocol = %q, want %q", index, port.AppProtocol, want[index])
		}
	}
}

func TestEndpointTargetRefFQDNSliceIsIgnored(t *testing.T) {
	portName := "http"
	port := int32(8080)
	protocol := corev1.ProtocolTCP
	got := endpointsFromSlice("cluster.local", &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "external-abc",
			Labels: map[string]string{discoveryv1.LabelServiceName: "external"},
		},
		AddressType: discoveryv1.AddressTypeFQDN,
		Ports:       []discoveryv1.EndpointPort{{Name: &portName, Port: &port, Protocol: &protocol}},
		Endpoints: []discoveryv1.Endpoint{{
			Addresses: []string{"backend.example.com"},
			TargetRef: &corev1.ObjectReference{
				Kind: "Pod", Namespace: "demo", Name: "pod-a", UID: types.UID("pod-a-uid"),
			},
		}},
	})
	if len(got) != 0 {
		t.Fatalf("FQDN targetRef endpoints = %+v, want none", got)
	}
}

func eventually(t testing.TB, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition never held: %s", message)
}

func egressPod(namespace, name, gatewayName, address string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace, Name: name,
			Labels: map[string]string{podsource.LabelGatewayName: gatewayName},
		},
		Spec:   corev1.PodSpec{ServiceAccountName: gatewayName, NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: address, PodIPs: []corev1.PodIP{{IP: address}}},
	}
}

func TestResolveScopeAuthorizesRegisteredGatewayServiceAccounts(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: "agentio-system", Name: "agentio-config",
	}, Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress
`}}
	valid := egressPod("demo", "egress-rollout-a", "egress", "10.0.0.1")
	valid.UID = "valid-uid"
	implicit := egressPod("demo", "egress-rollout-b", "egress", "10.0.0.2")
	implicit.UID = "implicit-uid"
	implicit.Labels = nil
	spoofed := egressPod("demo", "attacker", "egress", "10.0.0.3")
	spoofed.UID = "spoofed-uid"
	spoofed.Spec.ServiceAccountName = "attacker"
	unconfigured := egressPod("demo", "missing", "missing", "10.0.0.4")
	unconfigured.UID = "unconfigured-uid"
	r := newTestRegistry(t, ctx, []runtime.Object{config, valid, implicit, spoofed, unconfigured}, nil)

	for _, test := range []struct {
		name           string
		pod            *corev1.Pod
		serviceAccount string
		wantClass      model.ClientClass
		wantKey        string
		wantSandboxUID string
	}{
		{name: "explicit config with standard label", pod: valid, serviceAccount: "egress", wantClass: model.ClientEgressGateway, wantKey: "demo/egress"},
		{name: "manual deployment without labels", pod: implicit, serviceAccount: "egress", wantClass: model.ClientEgressGateway, wantKey: "demo/egress"},
		{name: "label cannot grant gateway scope", pod: spoofed, serviceAccount: "attacker", wantClass: model.ClientDedicatedZTunnel, wantSandboxUID: "test//Pod/demo/attacker"},
		{name: "unregistered identity gets only sandbox scope", pod: unconfigured, serviceAccount: "missing", wantClass: model.ClientDedicatedZTunnel, wantSandboxUID: "test//Pod/demo/missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			principal := model.Principal{
				Kind:        model.PrincipalServiceAccount,
				TrustDomain: "cluster.local",
				ServiceAccount: model.ServiceAccountRef{
					Namespace:      test.pod.Namespace,
					ServiceAccount: test.serviceAccount,
				},
			}
			peer := model.PeerIdentity{
				Principal:  principal,
				AttestedBy: model.AttestationKubernetes,
				Kubernetes: model.KubernetesPeer{
					WorkloadName: test.pod.Name,
					WorkloadUID:  string(test.pod.UID),
				},
			}
			scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "")
			if err != nil {
				t.Fatalf("ResolveScope(): %v", err)
			}
			if scope.Class != test.wantClass || scope.GatewayKey != test.wantKey || scope.SandboxUID != test.wantSandboxUID {
				t.Fatalf("ResolveScope() = %+v, want class %s gateway %q sandbox %q", scope, test.wantClass, test.wantKey, test.wantSandboxUID)
			}
		})
	}
}

func TestResolveScopeAuthorizesGatewayAPIServiceAccount(t *testing.T) {
	ctx := t.Context()
	watcher := newFakeGatewayCRDWatcher()
	pod := egressPod("demo", "egress-rollout-a", "egress", "10.0.0.1")
	pod.UID = "gateway-uid"
	r := newGatewayTestRegistry(t, ctx, watcher, ownedGatewayClass(), ownedGateway(), pod)
	watcher.install(gatewayResource, ctx.Done())
	watcher.install(gatewayClassResource, ctx.Done())
	eventually(t, func() bool { return r.Gateways.GetKey("demo/egress") != nil }, "Gateway API registration")

	peer := model.PeerIdentity{
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      "demo",
				ServiceAccount: "egress",
			},
		},
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName: pod.Name,
			WorkloadUID:  string(pod.UID),
		},
	}
	scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "")
	if err != nil {
		t.Fatalf("ResolveScope(): %v", err)
	}
	if scope.Class != model.ClientEgressGateway || scope.GatewayKey != "demo/egress" {
		t.Fatalf("ResolveScope() = %+v, want Gateway API-owned gateway demo/egress", scope)
	}
}

// Unbound tokens cannot establish Pod or node ownership.
func TestResolveScopeRejectsUnboundTokensForPodScopes(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: "agentio-system", Name: "agentio-config",
	}, Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress
`}}
	gateway := egressPod("demo", "egress-rollout-a", "egress", "10.0.0.1")
	gateway.UID = "gateway-uid"
	sandbox := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "sandbox", UID: "sandbox-uid",
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: "10.0.0.5"},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{config, gateway, sandbox}, nil)
	eventually(t, func() bool { return len(r.Pods.List()) == 2 }, "pods loaded")

	gatewayPrincipal := model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "egress",
		},
	}
	sandboxPrincipal := model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      "demo",
			ServiceAccount: "app",
		},
	}

	for _, test := range []struct {
		name      string
		principal model.Principal
		bound     bool
		podName   string
		podUID    string
		wantClass model.ClientClass
		wantKey   string
	}{
		{name: "unbound token claiming gateway pod", principal: gatewayPrincipal, podName: "egress-rollout-a"},
		{name: "unbound token asserting gateway pod UID", principal: gatewayPrincipal, podName: "egress-rollout-a", podUID: "gateway-uid"},
		{name: "unbound token claiming sandbox pod", principal: sandboxPrincipal, podName: "sandbox"},
		{name: "bound token resolves gateway scope", principal: gatewayPrincipal, bound: true, podName: "egress-rollout-a", podUID: "gateway-uid",
			wantClass: model.ClientEgressGateway, wantKey: "demo/egress"},
		{name: "bound token resolves sandbox scope", principal: sandboxPrincipal, bound: true, podName: "sandbox", podUID: "sandbox-uid",
			wantClass: model.ClientDedicatedZTunnel, wantKey: "test//Pod/demo/sandbox"},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := model.PeerIdentity{
				Principal:  test.principal,
				AttestedBy: model.AttestationKubernetes,
			}
			if test.bound {
				peer.Kubernetes.WorkloadName = test.podName
				peer.Kubernetes.WorkloadUID = test.podUID
			}
			scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "")
			if !test.bound {
				if err == nil {
					t.Fatalf("ResolveScope() = %+v, want unbound token rejection", scope)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveScope(): %v", err)
			}
			if scope.Class != test.wantClass {
				t.Fatalf("ResolveScope() class = %v, want %v", scope.Class, test.wantClass)
			}
			if test.wantClass == model.ClientEgressGateway && scope.GatewayKey != test.wantKey {
				t.Fatalf("ResolveScope() gateway key = %q, want %q", scope.GatewayKey, test.wantKey)
			}
			if test.wantClass == model.ClientDedicatedZTunnel && scope.SandboxUID != test.wantKey {
				t.Fatalf("ResolveScope() sandbox UID = %q, want %q", scope.SandboxUID, test.wantKey)
			}
		})
	}
}

// Gateways are configured identities, not a projection of currently running Pods.
func TestGatewaysDeriveConfiguredIdentitiesWithoutPods(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: "agentio-system", Name: "agentio-config",
	}, Data: map[string]string{"config": `sandboxExtProc:
  service: epe.agentio-system.svc.cluster.local
  port: 9002
egressGateways:
- namespace: demo
  name: egress-a
- namespace: other
  name: egress-b
`}}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)

	eventually(t, func() bool { return len(r.Gateways.List()) == 2 }, "configured gateways derived without Pods")
	for _, key := range []string{"demo/egress-a", "other/egress-b"} {
		gateway := r.Gateways.GetKey(key)
		if gateway == nil {
			t.Fatalf("configured gateway %s missing; have %v", key, gatewayNames(r.Gateways.List()))
		}
		if gateway.Source != model.GatewaySourceAgentioConfig {
			t.Fatalf("gateway %s source state = %+v", key, gateway)
		}
		if gateway.Config == nil || gateway.Config.GetNamespace() != "" || gateway.Config.GetName() != "" {
			t.Fatalf("gateway %s normalized config = %+v", key, gateway.Config)
		}
	}
}

type gatewayRecorder struct {
	mu      sync.Mutex
	changed sets.Set[string]
}

func newGatewayRecorder(gateways krt.EventStream[model.Gateway]) *gatewayRecorder {
	recorder := &gatewayRecorder{changed: sets.New[string]()}
	gateways.RegisterBatch(func(events []krt.Event[model.Gateway]) {
		recorder.mu.Lock()
		defer recorder.mu.Unlock()
		for _, event := range events {
			recorder.changed.Insert(event.Latest().ResourceName())
		}
	}, false)
	return recorder
}

func (r *gatewayRecorder) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]string, 0, len(r.changed))
	for name := range r.changed {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func (r *gatewayRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changed = sets.New[string]()
}

// Gateway projections must own their selected protobuf fragments.
func TestGatewayProjectionDoesNotAliasEffectiveConfiguration(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: "agentio-system", Name: "agentio-config",
	}, Data: map[string]string{"config": `sandboxExtProc:
  service: epe.agentio-system.svc.cluster.local
  port: 9002
egressGateways:
- namespace: demo
  name: egress-a
  tlsTermination:
    includeHosts: ["a.example.com"]
- namespace: demo
  name: egress-b
`}}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)
	eventually(t, func() bool { return len(r.Gateways.List()) == 2 }, "configured gateways")

	a := r.Gateways.GetKey("demo/egress-a")
	b := r.Gateways.GetKey("demo/egress-b")
	a.Config.TlsTermination.IncludeHosts[0] = "mutated.invalid"

	if got := r.AgentioConfig.GetKey("effective").Value.GetSandboxExtProc().GetService(); got != "epe.agentio-system.svc.cluster.local" {
		t.Fatalf("mutating gateway projection changed effective sandbox ext_proc to %q", got)
	}
	if b.Config.GetTlsTermination() != nil {
		t.Fatalf("mutating egress-a projection changed egress-b config to %+v", b.Config)
	}
	if got := r.AgentioConfig.GetKey("effective").Value.GetEgressGateways()[0].GetTlsTermination().GetIncludeHosts()[0]; got != "a.example.com" {
		t.Fatalf("mutating gateway projection changed effective egress entry to %q", got)
	}
}

// sandbox_ext_proc remains a separate global compiler input. Changing it must
// not duplicate the fallback into, or emit changes from, the Gateway source.
func TestSharedGatewayFallbackChangeDoesNotChangeGatewaySource(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: "agentio-system", Name: "agentio-config",
	}, Data: map[string]string{"config": `sandboxExtProc:
  service: epe-old.agentio-system.svc.cluster.local
  port: 9002
egressGateways:
- namespace: demo
  name: egress-a
- namespace: demo
  name: egress-b
`}}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)
	eventually(t, func() bool { return len(r.Gateways.List()) == 2 }, "configured gateways")
	recorder := newGatewayRecorder(r.Gateways)

	config.Data["config"] = `sandboxExtProc:
  service: epe-new.agentio-system.svc.cluster.local
  port: 9002
egressGateways:
- namespace: demo
  name: egress-a
- namespace: demo
  name: egress-b
`
	if _, err := r.client.CoreV1().ConfigMaps(config.Namespace).Update(ctx, config, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		return r.AgentioConfig.GetKey("effective").Value.GetSandboxExtProc().GetService() ==
			"epe-new.agentio-system.svc.cluster.local"
	}, "shared fallback updates independently")
	time.Sleep(200 * time.Millisecond)
	if got := recorder.names(); len(got) != 0 {
		t.Fatalf("shared fallback changed Gateway source entries %v", got)
	}
}

// Duplicate configured identities collapse to one explicit conflict value so
// every downstream consumer fails the same key closed.
func TestGatewayProjectionMarksDuplicateConfiguredEntriesAsConflict(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: "agentio-system", Name: "agentio-config",
	}, Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress
- namespace: demo
  name: egress
  tlsTermination:
    includeHosts: ["*.example.com"]
`}}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)
	eventually(t, func() bool {
		gateway := r.Gateways.GetKey("demo/egress")
		return gateway != nil && gateway.Source == model.GatewaySourceConflict && gateway.Config == nil
	}, "duplicate configured gateway conflict")
}

// A gateway add, update, or delete publishes only that namespace/name gateway.
func TestGatewayConfigChangesAffectOnlyItsIdentity(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: "agentio-system", Name: "agentio-config",
	}, Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress-a
`}}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)
	eventually(t, func() bool { return r.Gateways.GetKey("demo/egress-a") != nil }, "initial configured gateway")
	recorder := newGatewayRecorder(r.Gateways)

	config.Data["config"] = `egressGateways:
- namespace: demo
  name: egress-a
- namespace: demo
  name: egress-b
`
	if _, err := r.client.CoreV1().ConfigMaps(config.Namespace).Update(ctx, config, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return r.Gateways.GetKey("demo/egress-b") != nil }, "gateway configuration add")
	time.Sleep(200 * time.Millisecond)
	if got := recorder.names(); len(got) != 1 || got[0] != "demo/egress-b" {
		t.Fatalf("gateway add changed %v, want only demo/egress-b", got)
	}

	recorder.reset()
	config.Data["config"] = `egressGateways:
- namespace: demo
  name: egress-a
- namespace: demo
  name: egress-b
  tlsTermination:
    includeHosts: ["*.example.com"]
`
	if _, err := r.client.CoreV1().ConfigMaps(config.Namespace).Update(ctx, config, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		gateway := r.Gateways.GetKey("demo/egress-b")
		return gateway != nil && len(gateway.Config.GetTlsTermination().GetIncludeHosts()) == 1
	}, "gateway configuration update")
	time.Sleep(200 * time.Millisecond)
	if got := recorder.names(); len(got) != 1 || got[0] != "demo/egress-b" {
		t.Fatalf("gateway update changed %v, want only demo/egress-b", got)
	}

	recorder.reset()
	config.Data["config"] = `egressGateways:
- namespace: demo
  name: egress-a
`
	if _, err := r.client.CoreV1().ConfigMaps(config.Namespace).Update(ctx, config, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return r.Gateways.GetKey("demo/egress-b") == nil }, "gateway configuration delete")
	time.Sleep(200 * time.Millisecond)
	if got := recorder.names(); len(got) != 1 || got[0] != "demo/egress-b" {
		t.Fatalf("gateway delete changed %v, want only demo/egress-b", got)
	}
}

// Pod lifecycle is not a gateway graph input.
func TestUnrelatedGatewayPodChangeDoesNotInvalidateConfiguredGraphs(t *testing.T) {
	ctx := t.Context()
	config := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Namespace: "agentio-system", Name: "agentio-config",
	}, Data: map[string]string{"config": `egressGateways:
- namespace: demo
  name: egress-a
- namespace: demo
  name: egress-b
`}}
	r := newTestRegistry(t, ctx, []runtime.Object{config}, nil)
	eventually(t, func() bool { return len(r.Gateways.List()) == 2 }, "configured gateways")
	recorder := newGatewayRecorder(r.Gateways)

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "unrelated"}}
	if _, err := r.client.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return r.Pods.GetKey("demo/unrelated") != nil }, "unrelated Pod reaches identity cache")
	time.Sleep(200 * time.Millisecond)
	if got := recorder.names(); len(got) != 0 {
		t.Fatalf("unrelated Pod changed gateway graphs %v", got)
	}
}

// Pod lookup remains the authorization source of truth, while only Pods with
// usable network addresses become Workload attesters for WDS generation.
func TestWorkloadsExcludeIneligiblePodsButRetainPodAuthorizationInputs(t *testing.T) {
	ctx := t.Context()
	terminal := egressPod("demo", "done", "egress", "10.0.0.9")
	terminal.Status.Phase = corev1.PodSucceeded
	addressless := egressPod("demo", "waiting", "egress", "")
	malformed := egressPod("demo", "bad-address", "egress", "not-an-ip")
	r := newTestRegistry(t, ctx, []runtime.Object{
		egressPod("demo", "valid", "egress", "10.0.0.1"), terminal, addressless, malformed,
	}, nil)

	if got := len(r.Pods.List()); got != 4 {
		t.Fatalf("authorization Pod inputs = %d, want 4", got)
	}
	if got := r.Workloads.List(); len(got) != 1 || got[0].Name != "valid" {
		t.Fatalf("Workloads = %+v, want only valid Pod", got)
	}
}

// Endpoints are derived from EndpointSlices, so deleting a slice has to withdraw
// exactly the endpoints it produced.
func TestEndpointsFollowTheirSlice(t *testing.T) {
	ctx := t.Context()
	port := int32(8080)
	ready := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "backend-abc",
			Labels: map[string]string{discoveryv1.LabelServiceName: "backend"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.1.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			{Addresses: []string{"10.1.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
		Ports: []discoveryv1.EndpointPort{{Port: &port}},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{slice}, nil)

	eventually(t, func() bool { return len(r.Endpoints.List()) == 2 }, "endpoints derived from the slice")
	for _, endpoint := range r.Endpoints.List() {
		if endpoint.ServiceKey != "demo/backend.demo.svc.cluster.local" {
			t.Fatalf("service key = %q", endpoint.ServiceKey)
		}
		if endpoint.SourceKey != "demo/backend-abc" {
			t.Fatalf("source key = %q", endpoint.SourceKey)
		}
	}

	if err := r.client.DiscoveryV1().EndpointSlices("demo").Delete(ctx, "backend-abc", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return len(r.Endpoints.List()) == 0 }, "endpoints withdrawn with the slice")
}

// A slice with no service label produces nothing rather than a bogus hostname.
func TestEndpointSliceWithoutServiceLabelIsIgnored(t *testing.T) {
	ctx := t.Context()
	port := int32(8080)
	r := newTestRegistry(t, ctx, []runtime.Object{&discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "orphan"},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.1.0.1"}}},
		Ports:      []discoveryv1.EndpointPort{{Port: &port}},
	}}, nil)

	// Nothing to wait for, so give the transformation a chance to run and then
	// assert the collection stayed empty.
	time.Sleep(200 * time.Millisecond)
	if got := r.Endpoints.List(); len(got) != 0 {
		t.Fatalf("endpoints = %+v, want none", got)
	}
}

func TestResolveSharedZTunnelRequiresPodBoundToken(t *testing.T) {
	ctx := t.Context()
	ztunnel := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "ztunnel-abc",
			UID:       "ztunnel-uid",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "ztunnel",
			NodeName:           "node-b",
		},
		Status: corev1.PodStatus{
			PodIP: "10.9.0.1",
		},
	}
	elsewhere := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "agentio-system",
			Name:      "ztunnel-xyz",
			UID:       "elsewhere-uid",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "ztunnel",
			NodeName:           "node-c",
		},
		Status: corev1.PodStatus{
			PodIP: "10.9.0.2",
		},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{ztunnel, elsewhere}, nil)
	eventually(t, func() bool { return len(r.Pods.List()) == 2 }, "pods loaded")

	principal := model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      "agentio-system",
			ServiceAccount: "ztunnel",
		},
	}
	unbound := model.PeerIdentity{
		Principal:  principal,
		AttestedBy: model.AttestationKubernetes,
	}
	if scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(unbound, "node-b"); err == nil {
		t.Fatalf("ResolveScope() = %+v, want unbound node token rejection", scope)
	}

	bound := unbound
	bound.Kubernetes = model.KubernetesPeer{
		WorkloadName: ztunnel.Name,
		WorkloadUID:  string(ztunnel.UID),
	}
	scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(bound, "node-b")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope.Class != model.ClientSharedZTunnel || scope.NodeName != "node-b" {
		t.Fatalf("scope = %+v", scope)
	}
}

// A token bound to a Pod UID must not grant a same-name replacement Pod.
func TestResolveScopeRejectsReplacedPodUID(t *testing.T) {
	ctx := t.Context()
	live := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "sandbox", UID: "replacement-uid",
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: "10.0.0.10"},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{live}, nil)
	eventually(t, func() bool { return len(r.Pods.List()) == 1 }, "replacement pod loaded")

	for _, test := range []struct {
		name      string
		uid       string
		wantError bool
	}{
		{name: "stale bound UID", uid: "original-uid", wantError: true},
		{name: "matching bound UID", uid: "replacement-uid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := model.PeerIdentity{
				Principal: model.Principal{
					Kind:        model.PrincipalServiceAccount,
					TrustDomain: "cluster.local",
					ServiceAccount: model.ServiceAccountRef{
						Namespace:      "demo",
						ServiceAccount: "app",
					},
				},
				AttestedBy: model.AttestationKubernetes,
				Kubernetes: model.KubernetesPeer{WorkloadName: "sandbox", WorkloadUID: test.uid, NodeName: "node-a"},
			}

			scope, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, "node-a")
			if test.wantError {
				if err == nil {
					t.Fatalf("ResolveScope() = %+v, want stale bound UID rejection", scope)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveScope() matching UID: %v", err)
			}
			if scope.Class != model.ClientDedicatedZTunnel || scope.SandboxUID != "test//Pod/demo/sandbox" {
				t.Fatalf("ResolveScope() = %+v, want live replacement sandbox scope", scope)
			}
		})
	}
}

func TestResolveScopeUsesFinalWorkloadCollection(t *testing.T) {
	ctx := t.Context()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo", Name: "sandbox", UID: "sandbox-uid",
		},
		Spec:   corev1.PodSpec{ServiceAccountName: "app", NodeName: "node-a"},
		Status: corev1.PodStatus{PodIP: "10.0.0.10"},
	}
	r := newTestRegistry(t, ctx, []runtime.Object{pod}, nil)
	workload := r.Workloads.GetKey("test//Pod/demo/sandbox")
	if workload == nil {
		t.Fatal("default Pod workload was not created")
	}
	workload.SandboxBindings = []model.SandboxBinding{{SandboxUID: "runtime-sandbox"}}
	finalWorkloads := krt.NewStaticCollection[model.Workload](nil, []model.Workload{*workload}, krt.WithStop(ctx.Done()))

	peer := model.PeerIdentity{
		Principal:  workload.Principal,
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{
			WorkloadName: pod.Name,
			WorkloadUID:  string(pod.UID),
		},
	}
	scope, err := r.PodScopeResolver(finalWorkloads).ResolveScope(peer, "")
	if err != nil {
		t.Fatal(err)
	}
	if scope.SandboxUID != "runtime-sandbox" {
		t.Fatalf("sandbox scope = %q, want final Workload binding", scope.SandboxUID)
	}
}

func gatewayNames(gateways []model.Gateway) []string {
	result := make([]string, 0, len(gateways))
	for _, gateway := range gateways {
		result = append(result, gateway.ResourceName())
	}
	return result
}

// An unsupported Principal kind has no Pod ownership to prove.
func TestResolveScopeRejectsUnsupportedPrincipalKind(t *testing.T) {
	ctx := t.Context()
	r := newTestRegistry(t, ctx, nil, nil)

	peer := model.PeerIdentity{
		Principal: model.Principal{
			Kind:        "workload-v1",
			TrustDomain: "cluster.local",
		},
		AttestedBy: model.AttestationKubernetes,
	}
	if _, err := r.PodScopeResolver(r.Workloads).ResolveScope(peer, ""); err == nil {
		t.Fatal("unsupported Principal kind resolved a Kubernetes scope")
	}
}
