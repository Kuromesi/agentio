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
	"errors"
	"sync/atomic"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"istio.io/istio/pkg/test"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	extensionsv1 "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/features"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/networking"
)

func TestFailureRecorderSerializesGatewayDeleteAndRecreate(t *testing.T) {
	const name = "demo/egress"
	failures := newFailureRecorder()
	failures.record("Gateway", name, errors.New("old invalid gateway"))

	var exists atomic.Bool
	deleteChecked := make(chan struct{})
	releaseDelete := make(chan struct{})
	deleteDone := make(chan struct{})
	go func() {
		failures.clearIf("Gateway", name, func() bool {
			absent := !exists.Load()
			close(deleteChecked)
			<-releaseDelete
			return absent
		})
		close(deleteDone)
	}()

	<-deleteChecked
	exists.Store(true)
	recordDone := make(chan struct{})
	go func() {
		failures.recordIf("Gateway", name, errors.New("new invalid gateway"), exists.Load)
		close(recordDone)
	}()

	close(releaseDelete)
	<-deleteDone
	<-recordDone
	if got := failures.snapshot()["Gateway/"+name]; got != "new invalid gateway" {
		t.Fatalf("current gateway failure = %q, want new invalid gateway", got)
	}
}

func TestRecordGatewayFailureRequiresCurrentGateway(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	gateways := krt.NewStaticCollection[model.Gateway](nil, nil,
		krt.NewOptionsBuilder(stop, "", nil).WithName("test-gateways")...)
	failures := newFailureRecorder()
	configured := model.Gateway{
		Namespace: "demo",
		Name:      "egress",
		Config:    &configv1.EgressGateway{},
		Source:    model.GatewaySourceAgentioConfig,
	}
	gateways.ConditionalUpdateObject(configured)

	recordGatewayFailureIfCurrent(gateways, failures, configured, errors.New("invalid current gateway"))
	if _, found := failures.snapshot()["Gateway/demo/egress"]; !found {
		t.Fatal("current invalid gateway did not record a failure")
	}
	failures.clear("Gateway", configured.ResourceName())

	replacement := configured
	replacement.Config = &configv1.EgressGateway{
		TlsTermination: &configv1.TlsTerminationConfig{
			IncludeHosts: []string{"new.example.com"},
		},
	}
	gateways.ConditionalUpdateObject(replacement)
	recordGatewayFailureIfCurrent(gateways, failures, configured, errors.New("stale replaced gateway"))
	if _, found := failures.snapshot()["Gateway/demo/egress"]; found {
		t.Fatal("replaced gateway recorded a stale failure")
	}

	gateways.DeleteObject(replacement.ResourceName())
	recordGatewayFailureIfCurrent(gateways, failures, replacement, errors.New("stale deleted gateway"))
	if _, found := failures.snapshot()["Gateway/demo/egress"]; found {
		t.Fatal("deleted gateway recorded a stale failure")
	}
}

func TestGatewayAPIDeclarationOverridesOnlyLegacyPolicyFallback(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	builder := krt.NewOptionsBuilder(stop, "", nil)
	options := func(name string) []krt.CollectionOption { return builder.WithName(name) }
	configurations := krt.NewStatic[configuration](&configuration{
		ResourceVersion: "legacy-policy",
		Config: &configv1.AgentioConfig{
			EgressPolicies: []*extensionsv1.EgressPolicy{{
				Policy: extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{
					Service: "egress.agentio-system.svc.cluster.local",
					Port:    15008,
				},
			}},
		},
	}, true, options("configuration")...)
	externalConfig := &configv1.EgressGateway{
		ExtProc: &configv1.ExtProcProvider{Service: "epe.agentio-system.svc.cluster.local", Port: 9002},
	}
	external := krt.NewStaticCollection[model.Gateway](nil, []model.Gateway{{
		Namespace: "agentio-system",
		Name:      "egress",
		Config:    externalConfig,
		Source:    model.GatewaySourceGatewayAPI,
	}}, options("gateway-api")...)

	merged := newGatewayDeclarations(configurations, external, options)
	if !merged.WaitUntilSynced(stop) {
		t.Fatal("merged gateway declarations did not sync")
	}
	eventually(t, func() bool {
		gateway := merged.GetKey("agentio-system/egress")
		return gateway != nil && gateway.Source == model.GatewaySourceGatewayAPI &&
			gateway.Config.GetExtProc().GetService() == externalConfig.GetExtProc().GetService()
	}, "Gateway API declaration to replace the inferred legacy fallback")
}

func TestGatewayAPIParameterUpdatePublishesIncrementalRoutesWithLegacyPolicyReference(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	agentioConfig := krt.NewStaticCollection[model.AgentioConfiguration](nil, nil, options...)
	gatewayAPI := krt.NewStaticCollection[model.Gateway](nil, nil, options...)
	inputs := validCompilerInputs(stop)
	inputs.AgentioConfig = agentioConfig
	inputs.Gateways = gatewayAPI

	agentioConfig.ConditionalUpdateObject(model.AgentioConfiguration{
		ResourceVersion: "legacy-policy",
		Value: &configv1.AgentioConfig{
			EgressPolicies: []*extensionsv1.EgressPolicy{{
				Policy: extensionsv1.EgressPolicyAction_GATEWAY,
				Gateway: &extensionsv1.GatewayAddress{
					Service: "egress.agentio-system.svc.cluster.local",
					Port:    15008,
				},
			}},
		},
	})
	gatewayWithTimeout := func(timeout time.Duration) model.Gateway {
		return model.Gateway{
			Namespace: "agentio-system",
			Name:      "egress",
			Source:    model.GatewaySourceGatewayAPI,
			Config: &configv1.EgressGateway{ConnectionPool: &configv1.ConnectionPoolSettings{
				Http: &configv1.ConnectionPoolHttpSettings{
					DefaultRoute: &configv1.HttpRouteSettings{Timeout: durationpb.New(timeout)},
				},
			}},
		}
	}
	gatewayAPI.ConditionalUpdateObject(gatewayWithTimeout(7 * time.Second))
	compiled, err := New(inputs, krt.NewOptionsBuilder(stop, "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.WaitUntilSynced(stop) {
		t.Fatal("compiler did not sync")
	}
	routeTimeout := func() time.Duration {
		for _, resource := range currentSnapshot(t, compiled).ListResourcesOwnedByGateway(model.RouteType, "agentio-system/egress") {
			if resource.XDSName != networking.HTTPDynamicForwardProxy {
				continue
			}
			route := &routev3.RouteConfiguration{}
			if err := resource.Value.UnmarshalTo(route); err != nil {
				t.Fatal(err)
			}
			for _, candidate := range route.GetVirtualHosts()[0].GetRoutes() {
				if candidate.GetName() == "default" {
					return candidate.GetRoute().GetTimeout().AsDuration()
				}
			}
		}
		return 0
	}
	eventually(t, func() bool { return routeTimeout() == 7*time.Second }, "initial Gateway API route timeout")
	recorder := newRecorder(compiled.Resources())

	gatewayAPI.ConditionalUpdateObject(gatewayWithTimeout(11 * time.Second))
	eventually(t, func() bool {
		return routeTimeout() == 11*time.Second && recorder.has(gatewayResourceName(
			model.RouteType, "agentio-system/egress", networking.HTTPDynamicForwardProxy))
	}, "parametersRef-equivalent update to publish an incremental RDS resource")
}

func TestGatewayResourcesCarryClusterOptions(t *testing.T) {
	const rootCAPath = "/etc/ssl/custom.pem"
	test.SetForTest(t, &features.GatewayConnectTimeout, 7*time.Second)
	test.SetForTest(t, &features.GatewayRootCAPath, rootCAPath)
	resources, err := gatewayResourcesFor(
		model.Gateway{
			Namespace: "agentio-system",
			Name:      "egress",
			Config:    &configv1.EgressGateway{},
		},
		nil,
		"agentiod.agentio-system.svc:15012",
		"cluster.local",
		nil,
		"",
		"",
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("gatewayResourcesFor: %v", err)
	}
	clusters := make(map[string]*clusterv3.Cluster)
	for _, resource := range resources {
		if resource.Key.TypeURL != model.ClusterType {
			continue
		}
		cluster := &clusterv3.Cluster{}
		if err := resource.Value.UnmarshalTo(cluster); err != nil {
			t.Fatalf("unmarshal cluster %s: %v", resource.XDSName, err)
		}
		clusters[resource.XDSName] = cluster
	}
	if got := clusters[networking.PassthroughCluster].GetConnectTimeout().AsDuration(); got != 7*time.Second {
		t.Fatalf("passthrough connect timeout = %s, want 7s", got)
	}
	tlsContext := &tlsv3.UpstreamTlsContext{}
	if err := clusters[networking.TLSConnectOriginate].GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
		t.Fatalf("unmarshal TLS origination context: %v", err)
	}
	if got := tlsContext.GetCommonTlsContext().GetValidationContext().GetTrustedCa().GetFilename(); got != rootCAPath {
		t.Fatalf("TLS origination root CA = %q, want %q", got, rootCAPath)
	}
}
