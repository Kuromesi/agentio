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

package compiler

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/test"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"istio.io/istio/pkg/util/sets"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

const testServiceKey = "demo/backend.demo.svc.cluster.local"

func TestCompilerPublishesDiscoveryOnlyWorkloadWithoutSandboxBinding(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workload := testWDSWorkload("opaque-endpoint", "", "10.0.0.9")
	workload.Principal = model.Principal{}
	workload.SandboxBindings = nil
	workload.HostNetwork = true

	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{workload}, options...)
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := compileSynced(t, compiler)
	resource, found := snapshot.Get(model.ResourceKey{TypeURL: model.AddressType, Name: workload.UID})
	if !found {
		t.Fatalf("discovery-only WDS Address %q is missing; failures: %v", workload.UID, compiler.Failures())
	}
	address := &workloadv1.Address{}
	if err := resource.Value.UnmarshalTo(address); err != nil {
		t.Fatal(err)
	}
	if got := address.GetWorkload().GetNetworkMode(); got != workloadv1.NetworkMode_HOST_NETWORK {
		t.Fatalf("network mode = %v, want HOST_NETWORK", got)
	}
	if got := address.GetWorkload().GetAuthorizationPolicies(); len(got) != 0 {
		t.Fatalf("authorization policies = %v, want none", got)
	}
}

func TestWorkloadMetadataFiltersLabels(t *testing.T) {
	test.SetForTest(t, &features.MeshInternalTrafficPolicy,
		extensionsv1.MeshInternalTrafficPolicy_MESH_INTERNAL_PASSTHROUGH)
	labels := map[string]string{
		"keep":              "yes",
		"pod-template-hash": "no",
		"controller-a":      "no",
	}
	workloadInput := testWDSWorkload("sandbox", "sandbox-uid", "10.0.0.1")
	workloadInput.Labels = labels
	resources, err := buildWDSAddress(wdsProjection{
		ClusterID: "cluster",
		Workload:  workloadInput,
		MetadataConfiguration: &workloadMetadataConfiguration{
			IgnoredLabels: []string{"pod-template-hash", "controller-*"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	address := &workloadv1.Address{}
	if err := resources[0].Value.UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal Address: %v", err)
	}
	workload := address.GetWorkload()
	if got := workload.GetWorkloadType(); got != workloadv1.WorkloadType_POD {
		t.Fatalf("VM-compatible workload type = %v, want POD", got)
	}
	var metadataExtension *workloadv1.Extension
	for _, extension := range workload.GetExtensions() {
		if extension.GetName() == "workload-metadata" {
			metadataExtension = extension
			break
		}
	}
	if metadataExtension == nil {
		t.Fatalf("workload extensions = %+v, want workload metadata", workload.GetExtensions())
	}
	metadata := &extensionsv1.WorkloadMetadata{}
	if err := metadataExtension.GetConfig().UnmarshalTo(metadata); err != nil {
		t.Fatalf("unmarshal workload metadata: %v", err)
	}
	if got := metadata.GetLabels(); !reflect.DeepEqual(got, map[string]string{"keep": "yes"}) {
		t.Fatalf("metadata labels = %v, want keep label only", got)
	}
	if got := metadata.GetMeshInternalTrafficPolicy(); got != extensionsv1.MeshInternalTrafficPolicy_MESH_INTERNAL_PASSTHROUGH {
		t.Fatalf("mesh internal traffic policy = %v, want PASSTHROUGH", got)
	}
	if got := labels["pod-template-hash"]; got != "no" {
		t.Fatalf("source labels were mutated: pod-template-hash = %q", got)
	}
}

func TestServiceResourcePreservesNormalizedTargetPort(t *testing.T) {
	for _, test := range []struct {
		name string
		port model.ServicePort
		want *workloadv1.Port
	}{
		{
			name: "numeric target port",
			port: model.ServicePort{Name: "http", Port: 80, TargetPort: 8080, Protocol: "TCP"},
			want: &workloadv1.Port{ServicePort: 80, TargetPort: 8080},
		},
		{
			name: "named target sentinel",
			port: model.ServicePort{Name: "http", Port: 80, TargetPortName: "backend-http", Protocol: "TCP"},
			want: &workloadv1.Port{ServicePort: 80, TargetPort: 0},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			resource, err := buildWDSService(model.Service{
				Namespace: "demo", Name: "backend", Hostname: "backend.demo.svc.cluster.local",
				Ports: []model.ServicePort{test.port},
			}, "")
			if err != nil {
				t.Fatal(err)
			}
			address := &workloadv1.Address{}
			if err := resource.Value.UnmarshalTo(address); err != nil {
				t.Fatalf("unmarshal Service Address: %v", err)
			}
			ports := address.GetService().GetPorts()
			if len(ports) != 1 || !proto.Equal(ports[0], test.want) {
				t.Fatalf("service ports = %+v, want [%+v]", ports, test.want)
			}
		})
	}
}

func TestServiceResourcePreservesNetworkingSemantics(t *testing.T) {
	resource, err := buildWDSService(model.Service{
		Namespace:                "demo",
		Name:                     "backend",
		Hostname:                 "backend.demo.svc.cluster.local",
		Canonical:                true,
		PublishNotReadyAddresses: true,
		Ports: []model.ServicePort{
			{
				Name:        "http",
				Port:        80,
				TargetPort:  8080,
				Protocol:    "TCP",
				AppProtocol: model.AppProtocolHTTP11,
			},
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	address := &workloadv1.Address{}
	if err := resource.Value.UnmarshalTo(address); err != nil {
		t.Fatalf("unmarshal Service Address: %v", err)
	}
	service := address.GetService()
	if !service.GetCanonical() {
		t.Fatal("canonical Service flag was not projected")
	}
	if got := service.GetLoadBalancing().GetHealthPolicy(); got != workloadv1.LoadBalancing_ALLOW_ALL {
		t.Fatalf("health policy = %v, want ALLOW_ALL", got)
	}
	if got := service.GetPorts()[0].GetAppProtocol(); got != workloadv1.AppProtocol_HTTP11 {
		t.Fatalf("app protocol = %v, want HTTP11", got)
	}
}

func TestServiceResourceTrafficPolicyEncoding(t *testing.T) {
	for _, test := range []struct {
		name     string
		service  model.Service
		wantLB   *workloadv1.LoadBalancing
		wantIPFs workloadv1.IPFamilies
	}{
		{
			name:    "internal traffic policy local",
			service: model.Service{InternalTrafficPolicyLocal: true},
			wantLB: &workloadv1.LoadBalancing{
				RoutingPreference: []workloadv1.LoadBalancing_Scope{workloadv1.LoadBalancing_NODE},
				Mode:              workloadv1.LoadBalancing_STRICT,
			},
		},
		{
			name: "local wins over traffic distribution",
			service: model.Service{
				InternalTrafficPolicyLocal: true,
				TrafficDistribution:        model.TrafficDistributionPreferSameZone,
			},
			wantLB: &workloadv1.LoadBalancing{
				RoutingPreference: []workloadv1.LoadBalancing_Scope{workloadv1.LoadBalancing_NODE},
				Mode:              workloadv1.LoadBalancing_STRICT,
			},
		},
		{
			name:    "prefer same zone",
			service: model.Service{TrafficDistribution: model.TrafficDistributionPreferSameZone},
			wantLB: &workloadv1.LoadBalancing{
				RoutingPreference: []workloadv1.LoadBalancing_Scope{
					workloadv1.LoadBalancing_NETWORK,
					workloadv1.LoadBalancing_REGION,
					workloadv1.LoadBalancing_ZONE,
				},
				Mode: workloadv1.LoadBalancing_FAILOVER,
			},
		},
		{
			name: "prefer same node with publish not ready",
			service: model.Service{
				TrafficDistribution:      model.TrafficDistributionPreferSameNode,
				PublishNotReadyAddresses: true,
			},
			wantLB: &workloadv1.LoadBalancing{
				RoutingPreference: []workloadv1.LoadBalancing_Scope{
					workloadv1.LoadBalancing_NETWORK,
					workloadv1.LoadBalancing_REGION,
					workloadv1.LoadBalancing_ZONE,
					workloadv1.LoadBalancing_SUBZONE,
					workloadv1.LoadBalancing_NODE,
				},
				Mode:         workloadv1.LoadBalancing_FAILOVER,
				HealthPolicy: workloadv1.LoadBalancing_ALLOW_ALL,
			},
		},
		{
			name:     "dual stack",
			service:  model.Service{IPFamilies: model.IPFamiliesDual},
			wantIPFs: workloadv1.IPFamilies_DUAL,
		},
		{
			name:     "ipv4 only",
			service:  model.Service{IPFamilies: model.IPFamiliesIPv4Only},
			wantIPFs: workloadv1.IPFamilies_IPV4_ONLY,
		},
		{
			name:     "ipv6 only",
			service:  model.Service{IPFamilies: model.IPFamiliesIPv6Only},
			wantIPFs: workloadv1.IPFamilies_IPV6_ONLY,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := test.service
			service.Namespace, service.Name = "demo", "backend"
			service.Hostname = "backend.demo.svc.cluster.local"
			resource, err := buildWDSService(service, "")
			if err != nil {
				t.Fatal(err)
			}
			address := &workloadv1.Address{}
			if err := resource.Value.UnmarshalTo(address); err != nil {
				t.Fatalf("unmarshal Service Address: %v", err)
			}
			wire := address.GetService()
			if !proto.Equal(wire.GetLoadBalancing(), test.wantLB) {
				t.Fatalf("load balancing = %+v, want %+v", wire.GetLoadBalancing(), test.wantLB)
			}
			if wire.GetIpFamilies() != test.wantIPFs {
				t.Fatalf("ip families = %v, want %v", wire.GetIpFamilies(), test.wantIPFs)
			}
		})
	}
}

func extensionNames(extensions []*workloadv1.Extension) []string {
	result := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		result = append(result, extension.GetName())
	}
	return result
}

func TestWorkloadServicePortsPreserveServiceAndTargetPorts(t *testing.T) {
	tests := []struct {
		name      string
		service   model.ServicePort
		endpoint  model.Endpoint
		wantPorts []*workloadv1.Port
	}{
		{
			name: "numeric target port",
			service: model.ServicePort{
				Name: "http", Port: 80, TargetPort: 8080, Protocol: "TCP",
			},
			endpoint: model.Endpoint{
				ServiceKey: testServiceKey, SourceKey: "demo/backend-a", Address: "10.0.0.1",
				PortName: "http", Port: 8080, Protocol: "TCP", Ready: true,
			},
			wantPorts: []*workloadv1.Port{{ServicePort: 80, TargetPort: 8080}},
		},
		{
			name: "numeric target port contradicting EndpointSlice is omitted",
			service: model.ServicePort{
				Name: "http", Port: 80, TargetPort: 8080, Protocol: "TCP",
			},
			endpoint: model.Endpoint{
				ServiceKey: testServiceKey, SourceKey: "demo/backend-a", Address: "10.0.0.1",
				PortName: "http", Port: 9090, Protocol: "TCP", Ready: true,
			},
			wantPorts: nil,
		},
		{
			name: "named target port retained while service port name is EndpointSlice join key",
			service: model.ServicePort{
				Name: "web", Port: 81, TargetPortName: "http-backend", Protocol: "TCP",
			},
			endpoint: model.Endpoint{
				ServiceKey: testServiceKey, SourceKey: "demo/backend-a", Address: "10.0.0.1",
				PortName: "web", Port: 9090, Protocol: "TCP", Ready: true,
			},
			wantPorts: []*workloadv1.Port{{ServicePort: 81, TargetPort: 9090}},
		},
		{
			name: "named target port with mismatched service port name is omitted",
			service: model.ServicePort{
				Name: "web", Port: 81, TargetPortName: "http-backend", Protocol: "TCP",
			},
			endpoint: model.Endpoint{
				ServiceKey: testServiceKey, SourceKey: "demo/backend-a", Address: "10.0.0.1",
				PortName: "metrics", Port: 9090, Protocol: "TCP", Ready: true,
			},
			wantPorts: nil,
		},
		{
			name: "protocol mismatch is omitted",
			service: model.ServicePort{
				Name: "dns", Port: 53, TargetPort: 5353, Protocol: "UDP",
			},
			endpoint: model.Endpoint{
				ServiceKey: testServiceKey, SourceKey: "demo/backend-a", Address: "10.0.0.1",
				PortName: "dns", Port: 5353, Protocol: "TCP", Ready: true,
			},
			wantPorts: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			workload, _ := compileWorkloadServices(t,
				[]model.ServicePort{test.service}, []model.Endpoint{test.endpoint},
				[]model.Workload{testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1")},
			)
			got := workload.GetServices()[testServiceKey]
			if got == nil {
				t.Fatalf("service %q missing", testServiceKey)
			}
			if !reflect.DeepEqual(got.GetPorts(), test.wantPorts) {
				t.Fatalf("ports = %+v, want %+v", got.GetPorts(), test.wantPorts)
			}
		})
	}
}

func TestPublishNotReadyServiceIncludesUnhealthyEndpoint(t *testing.T) {
	service := model.Service{
		Namespace:                "demo",
		Name:                     "backend",
		Hostname:                 "backend.demo.svc.cluster.local",
		PublishNotReadyAddresses: true,
		Ports: []model.ServicePort{
			{
				Name:       "http",
				Port:       80,
				TargetPort: 8080,
				Protocol:   "TCP",
			},
		},
	}
	workloads, _ := compileWorkloadsAndHashesForService(t, service, []model.Endpoint{
		{
			ServiceKey: testServiceKey,
			SourceKey:  "demo/backend-a",
			Address:    "10.0.0.1",
			PortName:   "http",
			Port:       8080,
			Protocol:   "TCP",
			Ready:      false,
		},
	}, []model.Workload{
		testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1"),
	})

	ports := workloads["pod-a"].GetServices()[testServiceKey].GetPorts()
	want := []*workloadv1.Port{
		{
			ServicePort: 80,
			TargetPort:  8080,
		},
	}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("publish-not-ready ports = %+v, want %+v", ports, want)
	}
}

func TestWorkloadServicePortsAreStableAcrossEndpointOrder(t *testing.T) {
	ports := []model.ServicePort{
		{Name: "http", Port: 80, TargetPort: 8080, Protocol: "TCP"},
		{Name: "metrics", Port: 15020, TargetPortName: "metrics-backend", Protocol: "TCP"},
	}
	firstEndpoints := []model.Endpoint{
		{ServiceKey: testServiceKey, SourceKey: "demo/backend-b", Address: "10.0.0.1", PortName: "metrics", Port: 15021, Protocol: "TCP", Ready: true},
		{ServiceKey: testServiceKey, SourceKey: "demo/backend-a", Address: "10.0.0.1", PortName: "http", Port: 8080, Protocol: "TCP", Ready: true},
	}
	secondEndpoints := []model.Endpoint{firstEndpoints[1], firstEndpoints[0]}
	first, firstHash := compileWorkloadServices(t, ports, firstEndpoints, []model.Workload{testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1")})
	second, secondHash := compileWorkloadServices(t, []model.ServicePort{ports[1], ports[0]}, secondEndpoints, []model.Workload{testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1")})
	if !reflect.DeepEqual(first.GetServices(), second.GetServices()) {
		t.Fatalf("service mappings differ by input order: first=%+v second=%+v", first.GetServices(), second.GetServices())
	}
	if firstHash != secondHash {
		t.Fatalf("workload hashes differ by input order: %s != %s", firstHash, secondHash)
	}
}

func TestEndpointTargetRefPreventsHostNetworkCrossAttachment(t *testing.T) {
	endpoint := model.Endpoint{
		ServiceKey:      testServiceKey,
		SourceKey:       "demo/backend-a",
		Address:         "10.0.0.1",
		PortName:        "http",
		Port:            8080,
		Protocol:        "TCP",
		Ready:           true,
		HasTargetRef:    true,
		TargetKind:      "Pod",
		TargetUID:       "pod-a-uid",
		TargetName:      "pod-a",
		TargetNamespace: "demo",
	}
	workloadInputs := []model.Workload{
		testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1"),
		testWDSWorkload("pod-b", "pod-b-uid", "10.0.0.1"),
	}
	workloads := compileWorkloads(t, []model.ServicePort{{
		Name:       "http",
		Port:       80,
		TargetPort: 8080,
		Protocol:   "TCP",
	}}, []model.Endpoint{endpoint}, workloadInputs)
	if _, found := workloads["pod-a"].GetServices()[testServiceKey]; !found {
		t.Fatalf("pod-a services = %+v, want %q", workloads["pod-a"].GetServices(), testServiceKey)
	}
	if _, found := workloads["pod-b"].GetServices()[testServiceKey]; found {
		t.Fatalf("pod-b cross-attached targetRef service: %+v", workloads["pod-b"].GetServices())
	}

	stale := endpoint
	stale.TargetUID = "stale-pod-a-uid"
	workloads = compileWorkloads(t, []model.ServicePort{{
		Name:       "http",
		Port:       80,
		TargetPort: 8080,
		Protocol:   "TCP",
	}}, []model.Endpoint{stale}, workloadInputs[:1])
	if _, found := workloads["pod-a"].GetServices()[testServiceKey]; found {
		t.Fatalf("stale UID attached by matching name or IP: %+v", workloads["pod-a"].GetServices())
	}
}

func TestEndpointTargetRefUsesNameOnlyWithoutUIDAndIPOnlyWithoutRef(t *testing.T) {
	base := model.Endpoint{
		ServiceKey: testServiceKey,
		SourceKey:  "demo/backend-a",
		Address:    "10.0.0.1",
		PortName:   "http",
		Port:       8080,
		Protocol:   "TCP",
		Ready:      true,
	}
	workloadInputs := []model.Workload{
		testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1"),
		testWDSWorkload("pod-b", "pod-b-uid", "10.0.0.1"),
	}
	servicePorts := []model.ServicePort{{
		Name:       "http",
		Port:       80,
		TargetPort: 8080,
		Protocol:   "TCP",
	}}

	byName := base
	byName.HasTargetRef = true
	byName.TargetKind = "Pod"
	byName.TargetName = "pod-a"
	byName.TargetNamespace = "demo"
	workloads := compileWorkloads(t, servicePorts, []model.Endpoint{byName}, workloadInputs)
	if _, found := workloads["pod-a"].GetServices()[testServiceKey]; !found {
		t.Fatalf("UID-less targetRef did not attach by name: %+v", workloads["pod-a"].GetServices())
	}
	if _, found := workloads["pod-b"].GetServices()[testServiceKey]; found {
		t.Fatalf("UID-less targetRef fell back to shared IP: %+v", workloads["pod-b"].GetServices())
	}

	workloads = compileWorkloads(t, servicePorts, []model.Endpoint{base}, workloadInputs)
	for _, name := range []string{"pod-a", "pod-b"} {
		if _, found := workloads[name].GetServices()[testServiceKey]; !found {
			t.Fatalf("targetRef-absent endpoint did not use IP fallback for %s: %+v", name, workloads[name].GetServices())
		}
	}
}

func TestWorkloadResourceCarriesScopeAndServiceFacts(t *testing.T) {
	workloadInput := testWDSWorkload("pod-a", "pod-a-uid", "10.0.0.1")
	workloadInput.NodeName = "node-a"
	resources, err := buildWDSAddress(wdsProjection{
		ClusterID: "cluster",
		Workload:  workloadInput,
		Endpoints: []model.Endpoint{{
			ServiceKey: testServiceKey,
			SourceKey:  "demo/backend-a",
			Address:    "10.0.0.1",
			PortName:   "http",
			Port:       8080,
			Protocol:   "TCP",
			Ready:      true,
		}},
		Services: []model.Service{{
			Namespace: "demo",
			Name:      "backend",
			Hostname:  "backend.demo.svc.cluster.local",
			Ports: []model.ServicePort{{
				Name:       "http",
				Port:       80,
				TargetPort: 8080,
				Protocol:   "TCP",
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 1 || resources[0].Key.TypeURL != model.AddressType {
		t.Fatalf("workload resources = %+v, want one canonical Address", resources)
	}
	for _, resource := range resources {
		facts := resource.Facts.Workload
		if facts == nil || facts.SandboxUID != workloadInput.SandboxBindings[0].SandboxUID ||
			facts.NodeName != "node-a" || facts.Principal != workloadInput.Principal ||
			!slices.Contains(facts.ServiceKeys, testServiceKey) {
			t.Fatalf("resource %s facts = %+v", resource.Key.TypeURL, resource.Facts)
		}
	}
}

func TestGatewayWDSResourcesCarryOwnership(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	configuredWorkload := testWDSWorkload("egress-a-pod", "egress-a-uid", "10.0.0.10")
	configuredWorkload.Namespace = "agentio-system"
	configuredWorkload.Principal.ServiceAccount.Namespace = configuredWorkload.Namespace
	configuredWorkload.Principal.ServiceAccount.ServiceAccount = "egress-a"
	lookalikeWorkload := testWDSWorkload("lookalike", "lookalike-uid", "10.0.0.11")
	lookalikeWorkload.Namespace = "agentio-system"
	lookalikeWorkload.Principal.ServiceAccount.Namespace = lookalikeWorkload.Namespace
	lookalikeWorkload.Principal.ServiceAccount.ServiceAccount = "lookalike"
	configuredService := model.Service{
		Namespace: "agentio-system",
		Name:      "egress-a",
		Hostname:  "egress-a.agentio-system.svc.cluster.local",
		Addresses: []string{"10.96.0.10"},
	}
	lookalikeService := model.Service{
		Namespace: "agentio-system",
		Name:      "lookalike",
		Hostname:  "lookalike.agentio-system.svc.cluster.local",
		Addresses: []string{"10.96.0.11"},
	}
	inputs := validCompilerInputs(stop)
	inputs.Workloads = krt.NewStaticCollection(nil, []model.Workload{configuredWorkload, lookalikeWorkload}, options...)
	inputs.Services = krt.NewStaticCollection(nil, []model.Service{configuredService, lookalikeService}, options...)
	inputs.Gateways = krt.NewStaticCollection(nil, []model.Gateway{{
		Namespace: "agentio-system",
		Name:      "egress-a",
		Config:    &configv1.EgressGateway{},
		Source:    model.GatewaySourceAgentioConfig,
	}}, options...)
	inputs.AgentioConfig = krt.NewStaticCollection(nil, []model.AgentioConfiguration{{
		Value: &configv1.AgentioConfig{EgressGateways: []*configv1.EgressGateway{{
			Namespace: "agentio-system",
			Name:      "egress-a",
		}}},
	}}, options...)
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := compileSynced(t, compiler)
	owned := "agentio-system/egress-a"
	for _, key := range []model.ResourceKey{
		{
			TypeURL: model.AddressType,
			Name:    configuredWorkload.UID,
		},
		{
			TypeURL: model.AddressType,
			Name:    configuredService.ResourceName(),
		},
	} {
		resource, found := snapshot.Get(key)
		if !found || resource.Facts.GatewayOwner != owned {
			t.Fatalf("resource %v = %+v, missing Gateway ownership", key, resource)
		}
	}
	for _, key := range []model.ResourceKey{
		{
			TypeURL: model.AddressType,
			Name:    lookalikeWorkload.UID,
		},
		{
			TypeURL: model.AddressType,
			Name:    lookalikeService.ResourceName(),
		},
	} {
		resource, found := snapshot.Get(key)
		if !found {
			t.Fatalf("lookalike resource %v is missing", key)
		}
		if resource.Facts.GatewayOwner != "" {
			t.Fatalf("lookalike resource %v has Gateway ownership: %v", key, resource.Facts)
		}
	}
}

func testWDSWorkload(name, sourceUID, address string) model.Workload {
	uid := "cluster//Pod/demo/" + name
	return model.Workload{
		UID: uid,
		SandboxBindings: []model.SandboxBinding{
			{
				SandboxUID: uid,
			},
		},
		SourceUID: sourceUID,
		Namespace: "demo",
		Name:      name,
		Addresses: []string{address},
		Ready:     true,
		Principal: model.Principal{
			Kind:        model.PrincipalServiceAccount,
			TrustDomain: "cluster.local",
			ServiceAccount: model.ServiceAccountRef{
				Namespace:      "demo",
				ServiceAccount: "default",
			},
		},
	}
}

func compileWorkloadServices(t testing.TB, ports []model.ServicePort, endpoints []model.Endpoint, workloadInputs []model.Workload) (*workloadv1.Workload, string) {
	t.Helper()
	workloads, hashes := compileWorkloadsAndHashes(t, ports, endpoints, workloadInputs)
	return workloads[workloadInputs[0].Name], hashes[workloadInputs[0].Name]
}

func compileWorkloads(t testing.TB, ports []model.ServicePort, endpoints []model.Endpoint, workloadInputs []model.Workload) map[string]*workloadv1.Workload {
	t.Helper()
	workloads, _ := compileWorkloadsAndHashes(t, ports, endpoints, workloadInputs)
	return workloads
}

func compileWorkloadsAndHashes(t testing.TB, ports []model.ServicePort, endpoints []model.Endpoint, workloadInputs []model.Workload) (map[string]*workloadv1.Workload, map[string]string) {
	t.Helper()
	return compileWorkloadsAndHashesForService(t, model.Service{
		Namespace: "demo",
		Name:      "backend",
		Hostname:  "backend.demo.svc.cluster.local",
		Ports:     ports,
	}, endpoints, workloadInputs)
}

func compileWorkloadsAndHashesForService(
	t testing.TB,
	service model.Service,
	endpoints []model.Endpoint,
	workloadInputs []model.Workload,
) (map[string]*workloadv1.Workload, map[string]string) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	inputs := validCompilerInputs(stop)
	inputs.Services = krt.NewStaticCollection(nil, []model.Service{service}, options...)
	inputs.Endpoints = krt.NewStaticCollection(nil, endpoints, options...)
	inputs.Workloads = krt.NewStaticCollection(nil, workloadInputs, options...)
	compiler, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatalf("new compiler: %v", err)
	}
	snapshot := compileSynced(t, compiler)
	workloads := make(map[string]*workloadv1.Workload, len(workloadInputs))
	hashes := make(map[string]string, len(workloadInputs))
	for _, workloadInput := range workloadInputs {
		resource, found := snapshot.Get(model.ResourceKey{
			TypeURL: model.AddressType,
			Name:    workloadInput.UID,
		})
		if !found {
			t.Fatalf("workload %q missing", workloadInput.UID)
		}
		address := &workloadv1.Address{}
		if err := resource.Value.UnmarshalTo(address); err != nil {
			t.Fatalf("unmarshal workload %q: %v", workloadInput.UID, err)
		}
		workloads[workloadInput.Name] = address.GetWorkload()
		hashes[workloadInput.Name] = resource.Hash
	}
	return workloads, hashes
}

func validCompilerInputs(stop <-chan struct{}) Inputs {
	options := []krt.CollectionOption{krt.WithStop(stop)}
	return Inputs{
		ClusterID:                  "cluster",
		RootNamespace:              "agentio-system",
		DiscoveryAddress:           "agentiod.agentio-system.svc:15012",
		TrustDomain:                "cluster.local",
		Sandboxes:                  krt.NewStaticCollection[model.Sandbox](nil, nil, options...),
		Workloads:                  krt.NewStaticCollection[model.Workload](nil, nil, options...),
		Pods:                       krt.NewStaticCollection[*corev1.Pod](nil, nil, options...),
		KubernetesServices:         krt.NewStaticCollection[*corev1.Service](nil, nil, options...),
		EndpointSlices:             krt.NewStaticCollection[*discoveryv1.EndpointSlice](nil, nil, options...),
		Services:                   krt.NewStaticCollection[model.Service](nil, nil, options...),
		Endpoints:                  krt.NewStaticCollection[model.Endpoint](nil, nil, options...),
		Gateways:                   krt.NewStaticCollection[model.Gateway](nil, nil, options...),
		TrafficPolicies:            krt.NewStaticCollection[model.TrafficPolicy](nil, nil, options...),
		SecurityProfiles:           krt.NewStaticCollection[model.SecurityProfile](nil, nil, options...),
		GatewayPatches:             krt.NewStaticCollection[model.GatewayPatch](nil, nil, options...),
		Telemetry:                  krt.NewStaticCollection[model.Telemetry](nil, nil, options...),
		TelemetryProviderOverrides: krt.NewStatic[model.TelemetryProviderOverrides](nil, true, options...),
		AgentioConfig:              krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...),
	}
}

// testGatewaySource models the Registry boundary for compiler-only tests. The
// production compiler receives a source-merged Gateway collection directly.
func testGatewaySource(
	configurations krt.Collection[model.AgentioConfiguration],
	options ...krt.CollectionOption,
) krt.Collection[model.Gateway] {
	return krt.NewManyCollection(configurations,
		func(_ krt.HandlerContext, configuration model.AgentioConfiguration) []model.Gateway {
			return model.GatewaysFromAgentioConfig(configuration.Value)
		}, options...)
}

func TestNewRequiresKRTStop(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	inputs := validCompilerInputs(stop)
	_, err := New(inputs, krt.NewOptionsBuilder(nil, "", nil))
	if err == nil || !strings.Contains(err.Error(), "KRT stop channel") {
		t.Fatalf("New() error = %v, want KRT stop channel error", err)
	}
}

func TestNewPreservesKRTCollectionNames(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	debugger := new(krt.DebugHandler)
	compiler, err := New(validCompilerInputs(stop), krt.NewOptionsBuilder(stop, "", debugger))
	if err != nil {
		t.Fatalf("New(): %v", err)
	}

	debugDump, err := json.Marshal(debugger)
	if err != nil {
		t.Fatalf("marshal KRT debug collections: %v", err)
	}
	var collections []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(debugDump, &collections); err != nil {
		t.Fatalf("unmarshal KRT debug collections: %v", err)
	}
	names := sets.NewWithLength[string](len(collections))
	for _, collection := range collections {
		names.Insert(collection.Name)
	}
	for _, want := range []string{"configuration", "authorizations"} {
		if !names.Contains(want) {
			t.Fatalf("derived KRT collection %q not found in %v", want, names)
		}
	}
	if got := internalCollectionName(t, compiler.graph.resources); got != "resources" {
		t.Fatalf("resources collection name = %q, want %q", got, "resources")
	}
}

// internalCollectionName reads the unexported krt collection name via reflection (test-only).
func internalCollectionName(t testing.TB, collection any) string {
	t.Helper()
	value := reflect.ValueOf(collection)
	if value.Kind() != reflect.Pointer {
		t.Fatalf("KRT collection type = %T, want pointer", collection)
	}
	name := value.Elem().FieldByName("collectionName")
	if !name.IsValid() || name.Kind() != reflect.String {
		t.Fatalf("KRT collection type = %T has no collectionName", collection)
	}
	return name.String()
}
