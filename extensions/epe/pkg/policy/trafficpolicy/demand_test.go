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

package trafficpolicy

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"k8s.io/apimachinery/pkg/util/wait"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	xdsbackend "github.com/openkruise/agentio/extensions/epe/pkg/store/xds"
	"github.com/openkruise/agentio/pkg/model"
	controlxds "github.com/openkruise/agentio/pkg/xds"
	controlstore "github.com/openkruise/agentio/pkg/xds/store"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

type demandAuthenticator struct{}

func (demandAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	return model.PeerIdentity{AttestedBy: model.AttestationKubernetes}, nil
}

// Exercise the EPE resolver through the real client, ADS generators and publication
// store: a cold request must discover both its Workload and its policy dependencies.
func TestDemandDiscovery(t *testing.T) {
	const clusterID = "edge"
	const uid = "edge//Pod/ns/pod"
	pack := func(value proto.Message) *anypb.Any {
		t.Helper()
		result, err := anypb.New(value)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	resource := func(typ, name string, value proto.Message, facts model.ResourceFacts) model.Resource {
		t.Helper()
		result, err := model.NewResource(model.ResourceKey{TypeURL: typ, Name: name}, name, pack(value), nil, facts)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	workloadResource := func(name, pod, policy string) model.Resource {
		return resource(
			model.AddressType,
			name,
			&workload.Address{Type: &workload.Address_Workload{Workload: &workload.Workload{
				Uid:       name,
				Name:      pod,
				Namespace: "ns",
				ClusterId: clusterID,
				Extensions: []*workload.Extension{{
					Name: "traffic-policy-reference",
					Config: pack(&ext.PolicyReference{
						TypeUrl:       model.TrafficPolicyType,
						ResourceNames: []string{policy},
					})}},
			}}},
			model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
				WorkloadUID:       name,
				Namespace:         "ns",
				TrafficPolicyRefs: []string{policy},
			}},
		)
	}
	policyResource := func(name string, action sec.TrafficPolicy_Action) model.Resource {
		return resource(model.TrafficPolicyType, name, &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{
			Rules: []*sec.TrafficPolicy_Rule{{Action: action, Match: &sec.TrafficPolicy_Match{}}},
		}}, model.ResourceFacts{})
	}
	requestedWorkload := workloadResource(uid, "pod", "policy")
	requestedPolicy := policyResource("policy", sec.TrafficPolicy_ALLOW)
	initial, err := model.NewResourceSet([]model.Resource{
		requestedWorkload, requestedPolicy,
		workloadResource("edge//Pod/ns/unused", "unused", "unused"),
		policyResource("unused", sec.TrafficPolicy_ALLOW),
	})
	if err != nil {
		t.Fatal(err)
	}
	publications := controlstore.New(initial)
	principal, err := model.NewPrincipal("cluster.local", "ns/gateways/sa/default")
	if err != nil {
		t.Fatal(err)
	}
	server, err := controlxds.NewServer(demandAuthenticator{}, controlxds.ScopeFuncs{
		model.AttestationKubernetes: func(*core.Node, model.PeerIdentity) (model.ClientScope, error) {
			return model.ClientScope{
				Class:       model.ClientEgressGateway,
				Principal:   principal,
				GatewayKey:  "gateways/egress",
				WorkloadUID: "gateway",
				Source:      model.SourceRef{Registry: "kubernetes/edge", Key: "gateway-pod"},
			}, nil
		},
	}, publications, func() bool { return true }, 16, map[string]controlxds.ResourceGenerator{
		model.WorkloadType:      controlxds.WorkloadGenerator{},
		model.TrafficPolicyType: controlxds.TrafficPolicyGenerator{},
	}, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(grpcServer.Stop)
	conn, err := grpc.NewClient("passthrough:///demand-test", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})
	client, err := xdsclient.New(conn, xdsclient.Config{Node: &core.Node{Id: "epe"}, Watches: xdsbackend.Watches()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	aggregate := store.NewAggregate(xdsbackend.New(client))
	RegisterQueries(aggregate, clusterID)
	await := func(condition func() bool) {
		t.Helper()
		if err := wait.PollUntilContextCancel(ctx, time.Millisecond, true, func(context.Context) (bool, error) {
			aggregate.Refresh()
			return condition(), nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	await(aggregate.Ready)
	for typ, values := range client.Snapshot().Resources {
		if len(values) != 0 {
			t.Fatalf("initial %s watch fetched %d unsolicited resources", typ, len(values))
		}
	}
	resolver := &resolver{source: aggregate}
	pod := inputs.Pod{Namespace: "ns", Name: "pod"}
	target := netip.MustParseAddrPort("203.0.113.7:443")
	checkAction := func(want egressauthz.Action) {
		t.Helper()
		cfg, err := resolver.config(ctx, pod)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.Evaluate(target).Action; got != want {
			t.Fatalf("action = %v, want %v", got, want)
		}
	}
	checkAction(egressauthz.Allow)
	for typ, values := range client.Snapshot().Resources {
		if len(values) != 1 {
			t.Fatalf("%s cached %d resources, want just the requested one", typ, len(values))
		}
	}
	apply := func(changes ...model.ResourceChange) {
		t.Helper()
		if _, err := publications.Apply(changes); err != nil {
			t.Fatal(err)
		}
	}
	denied := policyResource("policy", sec.TrafficPolicy_DENY)
	apply(model.ResourceChange{Key: denied.Key, New: &denied})
	await(func() bool {
		value, err := aggregate.Get(store.Key{Type: store.TrafficPolicy, Name: "policy"})
		return err == nil && value != nil &&
			value.Value.(*sec.TrafficPolicy).Egress.Rules[0].Action == sec.TrafficPolicy_DENY
	})
	checkAction(egressauthz.Deny)
	apply(model.ResourceChange{Key: requestedWorkload.Key, Old: &requestedWorkload},
		model.ResourceChange{Key: denied.Key, Old: &denied})
	await(func() bool {
		snapshot := client.Snapshot()
		return len(snapshot.Resources[model.WorkloadType]) == 0 && len(snapshot.Resources[model.TrafficPolicyType]) == 0
	})
	if _, err := resolver.config(ctx, pod); err == nil {
		t.Fatal("deleted Workload authorized")
	}
	apply(model.ResourceChange{Key: requestedWorkload.Key, New: &requestedWorkload},
		model.ResourceChange{Key: requestedPolicy.Key, New: &requestedPolicy})
	checkAction(egressauthz.Allow)
	// A new binding must demand a previously uncached policy before authorizing.
	rebound := workloadResource(uid, "pod", "unused")
	apply(model.ResourceChange{Key: rebound.Key, New: &rebound})
	await(func() bool {
		value, err := aggregate.Get(store.Key{Type: store.Workload, Name: uid})
		if err != nil || value == nil {
			return false
		}
		refs, err := references(value.Value.(*workload.Workload))
		return err == nil && len(refs) == 1 && refs[0] == "unused"
	})
	checkAction(egressauthz.Allow)
	await(func() bool {
		snapshot := client.Snapshot()
		return snapshot.Resources[model.TrafficPolicyType]["policy"] == nil
	})
	snapshot := client.Snapshot()
	if len(snapshot.Resources[model.WorkloadType]) != 1 || len(snapshot.Resources[model.TrafficPolicyType]) != 1 ||
		snapshot.Resources[model.TrafficPolicyType]["unused"] == nil {
		t.Fatal("rebinding should replace the policy without fetching unrelated Workloads")
	}
}
