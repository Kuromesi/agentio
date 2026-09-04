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

package xds

import (
	"context"
	"fmt"
	"io"
	"maps"
	"sync"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"istio.io/istio/pkg/util/sets"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

// fakeStream is an in-memory DeltaStream: queued requests, collected responses, EOF when exhausted.
type fakeStream struct {
	ctx      context.Context
	requests chan *discoveryv3.DeltaDiscoveryRequest

	mu         sync.Mutex
	responses  []*discoveryv3.DeltaDiscoveryResponse
	sendErr    error
	beforeSend func()
}

var _ DeltaStream = (*fakeStream)(nil)

func newFakeStream(ctx context.Context, capacity int) *fakeStream {
	return &fakeStream{ctx: ctx, requests: make(chan *discoveryv3.DeltaDiscoveryRequest, capacity)}
}

func (f *fakeStream) send(request *discoveryv3.DeltaDiscoveryRequest) { f.requests <- request }
func (f *fakeStream) closeRequests()                                  { close(f.requests) }

func (f *fakeStream) Send(response *discoveryv3.DeltaDiscoveryResponse) error {
	if f.beforeSend != nil {
		f.beforeSend()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.responses = append(f.responses, response)
	return nil
}

func (f *fakeStream) setSendErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sendErr = err
}

func (f *fakeStream) Recv() (*discoveryv3.DeltaDiscoveryRequest, error) {
	select {
	case request, ok := <-f.requests:
		if !ok {
			return nil, io.EOF
		}
		return request, nil
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	}
}

func (f *fakeStream) sent() []*discoveryv3.DeltaDiscoveryResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*discoveryv3.DeltaDiscoveryResponse(nil), f.responses...)
}

// responsesFor returns the responses emitted for one type, in order.
func (f *fakeStream) responsesFor(typeURL string) []*discoveryv3.DeltaDiscoveryResponse {
	var result []*discoveryv3.DeltaDiscoveryResponse
	for _, response := range f.sent() {
		if response.GetTypeUrl() == typeURL {
			result = append(result, response)
		}
	}
	return result
}

func (f *fakeStream) Context() context.Context     { return f.ctx }
func (f *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)       {}
func (f *fakeStream) SendMsg(any) error            { return nil }
func (f *fakeStream) RecvMsg(any) error            { return nil }

type fakeAuthenticator struct {
	caller model.PeerIdentity
	err    error
}

func (f fakeAuthenticator) Authenticate(context.Context) (model.PeerIdentity, error) {
	return f.caller, f.err
}

type fakeResolver struct {
	scope model.ClientScope
	err   error
}

func (f fakeResolver) scopeFuncs() ScopeFuncs {
	return ScopeFuncs{model.AttestationKubernetes: func(*corev3.Node, model.PeerIdentity) (model.ClientScope, error) {
		return f.scope, f.err
	}}
}

// fakeResourceStore supplies a snapshot and update subscriptions for the Delta ADS harness.
type fakeResourceStore struct {
	mu            sync.Mutex
	snapshot      model.ResourceSet
	updates       chan Update
	subscriptions sets.Set[*fakeResourceSubscription]
}

type fakeResourceSubscription struct {
	store   *fakeResourceStore
	updates chan Update
	types   sets.Set[string]
}

func newFakeResourceStore(snapshot model.ResourceSet) *fakeResourceStore {
	return &fakeResourceStore{
		snapshot:      snapshot,
		updates:       make(chan Update),
		subscriptions: sets.New[*fakeResourceSubscription](),
	}
}

func (f *fakeResourceStore) Snapshot() model.ResourceSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snapshot
}

func (f *fakeResourceStore) Subscribe(ctx context.Context) ResourceSubscription {
	subscription := &fakeResourceSubscription{
		store: f, updates: make(chan Update, 1), types: sets.New[string](),
	}
	f.mu.Lock()
	f.subscriptions.Insert(subscription)
	f.mu.Unlock()
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		f.subscriptions.Delete(subscription)
		f.mu.Unlock()
	}()
	return subscription
}

func (f *fakeResourceSubscription) Watch(typeURL string) {
	f.store.mu.Lock()
	f.types.Insert(typeURL)
	f.store.mu.Unlock()
}

func (f *fakeResourceSubscription) Updates() <-chan Update { return f.updates }

// updateReversedFrom builds a store update whose before publication is derived
// by reversing changes against the after snapshot.
func updateReversedFrom(t testing.TB, after model.ResourceSet, changes []model.ResourceChange) Update {
	t.Helper()
	reverse := make([]model.ResourceChange, 0, len(changes))
	for _, change := range changes {
		reverse = append(reverse, model.ResourceChange{Key: change.Key, New: change.Old})
	}
	before, _, err := after.Apply(reverse)
	if err != nil {
		t.Fatal(err)
	}
	return updateBetween(before, after, changes)
}

func (f *fakeResourceStore) publish(snapshot model.ResourceSet) {
	f.mu.Lock()
	before := f.snapshot
	changes := before.Diff(snapshot)
	if len(changes) == 0 {
		f.mu.Unlock()
		return
	}
	f.snapshot = snapshot
	update := updateBetween(before, snapshot, changes)
	for subscription := range f.subscriptions {
		affected := false
		for typeURL := range subscription.types {
			if update.Affects(typeURL) {
				affected = true
				break
			}
		}
		if !affected {
			continue
		}
		select {
		case subscription.updates <- update:
		default:
			merged := update
			select {
			case pending := <-subscription.updates:
				merged = mergeUpdates(pending, update)
			default:
			}
			select {
			case subscription.updates <- merged:
			default:
			}
		}
	}
	f.mu.Unlock()
}

func (f *fakeResourceStore) apply(changes []model.ResourceChange) error {
	f.mu.Lock()
	current := f.snapshot
	f.mu.Unlock()
	next, changed, err := current.Apply(changes)
	if err != nil || !changed {
		return err
	}
	f.publish(next)
	return nil
}

// fakeSecrets serves on-demand certificates for the domains it knows and refuses
// everything else, mirroring OnDemandIssuer's contract without its CA machinery.
type fakeSecrets struct {
	allowed sets.Set[string]

	mu      sync.Mutex
	calls   int
	evicted sets.Set[string]
}

func newFakeSecrets(domains ...string) *fakeSecrets {
	allowed := sets.NewWithLength[string](len(domains))
	for _, domain := range domains {
		allowed.Insert(domain)
	}
	return &fakeSecrets{allowed: allowed, evicted: sets.New[string]()}
}

func (f *fakeSecrets) Get(_ context.Context, _ model.ClientScope, name string) (mitm.SignedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getLocked(name)
}

func (f *fakeSecrets) getLocked(name string) (mitm.SignedCertificate, error) {
	f.calls++
	if !f.allowed.Contains(name) {
		return mitm.SignedCertificate{}, fmt.Errorf("domain %q is not authorized", name)
	}
	f.evicted.Delete(name)
	return mitm.SignedCertificate{
		CertificateChain: []byte("certificate-chain-" + name),
		PrivateKey:       []byte("private-key-" + name),
		NotAfter:         time.Now().Add(time.Hour),
		SignedAt:         time.Now(),
		SignerRevision:   "one",
	}, nil
}

func (f *fakeSecrets) GetForSDS(
	_ context.Context,
	_ model.ClientScope,
	name string,
	retryEvicted bool,
) (mitm.SignedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.evicted.Contains(name) && !retryEvicted {
		return mitm.SignedCertificate{}, mitm.ErrDomainCertificateEvicted
	}
	return f.getLocked(name)
}

func (f *fakeSecrets) Evicted() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]string, 0, len(f.evicted))
	for name := range f.evicted {
		result = append(result, name)
	}
	return result
}

func (f *fakeSecrets) evict(name string) {
	f.mu.Lock()
	f.evicted.Insert(name)
	f.mu.Unlock()
}

// testServer wires a Server over a snapshot and a client scope.
type testServer struct {
	server    *Server
	resources *fakeResourceStore
	scope     model.ClientScope
}

func newTestServer(t testing.TB, scope model.ClientScope, resources []model.Resource, secrets DomainCertificateProvider) *testServer {
	return newTestServerWithScheduler(t, scope, resources, secrets, nil)
}

func newTestServerWithGenerators(
	t testing.TB,
	scope model.ClientScope,
	resources []model.Resource,
	generators map[string]ResourceGenerator,
) *testServer {
	t.Helper()
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	source := newFakeResourceStore(snapshot)
	server, err := NewServer(
		fakeAuthenticator{caller: model.PeerIdentity{
			Principal:  scope.Principal,
			AttestedBy: model.AttestationKubernetes,
			Kubernetes: model.KubernetesPeer{WorkloadName: "client-pod"},
		}},
		fakeResolver{scope: scope}.scopeFuncs(),
		source,
		func() bool { return true },
		16,
		testGenerators(generators),
		100,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return &testServer{server: server, resources: source, scope: scope}
}

func newTestServerWithScheduler(
	t testing.TB,
	scope model.ClientScope,
	resources []model.Resource,
	secrets DomainCertificateProvider,
	pushScheduler *PushScheduler,
) *testServer {
	t.Helper()
	snapshot, err := model.NewResourceSet(resources)
	if err != nil {
		t.Fatal(err)
	}
	source := newFakeResourceStore(snapshot)
	authenticator := fakeAuthenticator{caller: model.PeerIdentity{
		Principal:  scope.Principal,
		AttestedBy: model.AttestationKubernetes,
		Kubernetes: model.KubernetesPeer{WorkloadName: "client-pod"},
	}}
	resolver := fakeResolver{scope: scope}
	ready := func() bool { return true }
	generators := testGenerators(nil)
	if secrets != nil {
		generators[model.SecretType] = newTestSDSGenerator(t, secrets)
	}
	var server *Server
	if pushScheduler == nil {
		server, err = NewServer(
			authenticator,
			resolver.scopeFuncs(),
			source,
			ready,
			16,
			generators,
			100,
			0,
		)
	} else {
		server, err = newServerWithScheduler(
			authenticator,
			resolver.scopeFuncs(),
			source,
			ready,
			16,
			generators,
			pushScheduler,
			0,
		)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return &testServer{server: server, resources: source, scope: scope}
}

func testGenerators(overrides map[string]ResourceGenerator) map[string]ResourceGenerator {
	result := map[string]ResourceGenerator{
		model.AddressType:               WorkloadGenerator{},
		model.WorkloadType:              WorkloadGenerator{},
		model.WorkloadAuthorizationType: AuthorizationGenerator{},
	}
	maps.Copy(result, overrides)
	return result
}

// A typed-nil source must be rejected at construction, before a stream reaches
// the interface call and panics.
func TestNewServerRejectsTypedNilResourceSource(t *testing.T) {
	var source *fakeResourceStore
	server, err := NewServer(
		fakeAuthenticator{},
		fakeResolver{}.scopeFuncs(),
		source,
		func() bool { return true },
		1,
		nil,
		100,
		0,
	)
	if err == nil || server != nil {
		t.Fatalf("NewServer() = (%#v, %v), want nil server and validation error", server, err)
	}
}

// start runs the stream with the request side open so tests can publish between responses.
func (s *testServer) start(stream *fakeStream) <-chan error {
	done := make(chan error, 1)
	go func() { done <- s.server.DeltaAggregatedResources(stream) }()
	return done
}

// finish closes the request side and waits for the server to return.
func (s *testServer) finish(t testing.TB, stream *fakeStream, done <-chan error) error {
	t.Helper()
	stream.closeRequests()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not finish")
		return nil
	}
}

// awaitResponses blocks until at least count responses have been sent for a type.
func (f *fakeStream) awaitResponses(t testing.TB, typeURL string, count int) []*discoveryv3.DeltaDiscoveryResponse {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if responses := f.responsesFor(typeURL); len(responses) >= count {
			return responses
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("only %d responses for %s, want %d", len(f.responsesFor(typeURL)), typeURL, count)
	return nil
}

func awaitTotalResponses(t testing.TB, stream *fakeStream, count int) []*discoveryv3.DeltaDiscoveryResponse {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if responses := stream.sent(); len(responses) >= count {
			return responses
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("only %d total responses, want %d", len(stream.sent()), count)
	return nil
}

// run drives the stream to completion with the queued requests and returns the
// server's error, so a test can assert both the responses and the outcome.
func (s *testServer) run(t testing.TB, stream *fakeStream) error {
	t.Helper()
	stream.closeRequests()
	done := make(chan error, 1)
	go func() { done <- s.server.DeltaAggregatedResources(stream) }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not finish")
		return nil
	}
}

func nodeRequest(typeURL string, subscribe ...string) *discoveryv3.DeltaDiscoveryRequest {
	return &discoveryv3.DeltaDiscoveryRequest{
		Node: &corev3.Node{
			Id: "router~10.0.0.1~client-pod.demo~demo.svc.cluster.local",
			Metadata: &structpb.Struct{Fields: map[string]*structpb.Value{
				"POD_NAME":      structpb.NewStringValue("client-pod"),
				"POD_NAMESPACE": structpb.NewStringValue("demo"),
			}},
		},
		TypeUrl:                typeURL,
		ResourceNamesSubscribe: subscribe,
	}
}

func request(typeURL string, subscribe ...string) *discoveryv3.DeltaDiscoveryRequest {
	return &discoveryv3.DeltaDiscoveryRequest{TypeUrl: typeURL, ResourceNamesSubscribe: subscribe}
}

func mustAny(message proto.Message) *anypb.Any {
	value, err := anypb.New(message)
	if err != nil {
		panic(err)
	}
	return value
}

// mustWireAny wraps a message in an Any under an explicit wire type URL that
// differs from the descriptor's own type URL.
func mustWireAny(typeURL string, message proto.Message) *anypb.Any {
	data, err := proto.Marshal(message)
	if err != nil {
		panic(err)
	}
	return &anypb.Any{TypeUrl: typeURL, Value: data}
}

// addressResource builds a WDS Address-typed resource; payload only needs to
// vary between resources whose hashes must differ.
func addressResource(t testing.TB, name, payload string, aliases ...string) model.Resource {
	t.Helper()
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.AddressType, Name: name}, "",
		mustAny(&workloadv1.Address{Type: &workloadv1.Address_Workload{
			Workload: &workloadv1.Workload{Uid: name, Name: payload, Namespace: "demo"},
		}}), aliases,
		model.ResourceFacts{Workload: &model.WorkloadResourceFacts{
			SandboxUID: "cluster//Pod/demo/client-pod",
			NodeName:   "node-a",
			Principal:  serviceAccountPrincipal("demo", "default"),
		}})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

// gatewayResource builds a gateway-scoped resource: the wire name is shared
// across gateways while the snapshot key is not.
func gatewayResource(t testing.TB, gatewayKey, xdsName, payload string) model.Resource {
	t.Helper()
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.ClusterType, Name: gatewayKey + "|" + xdsName}, xdsName,
		mustAny(&clusterv3.Cluster{Name: xdsName, AltStatName: payload}), nil,
		model.ResourceFacts{GatewayOwner: gatewayKey})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func gatewayResourceOfType(t testing.TB, typeURL, gatewayKey, xdsName, payload string) model.Resource {
	t.Helper()
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: typeURL, Name: gatewayKey + "|" + xdsName}, xdsName,
		&anypb.Any{TypeUrl: typeURL, Value: []byte(payload)}, nil,
		model.ResourceFacts{GatewayOwner: gatewayKey})
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func gatewayScope() model.ClientScope {
	return model.ClientScope{
		Class:      model.ClientEgressGateway,
		Principal:  serviceAccountPrincipal("demo", "egress"),
		GatewayKey: "demo/egress",
	}
}

func ztunnelScope() model.ClientScope {
	return model.ClientScope{
		Class:      model.ClientDedicatedZTunnel,
		Principal:  serviceAccountPrincipal("demo", "default"),
		SandboxUID: "cluster//Pod/demo/client-pod",
	}
}

func serviceAccountPrincipal(namespace, serviceAccount string) model.Principal {
	return model.Principal{
		Kind:        model.PrincipalServiceAccount,
		TrustDomain: "cluster.local",
		ServiceAccount: model.ServiceAccountRef{
			Namespace:      namespace,
			ServiceAccount: serviceAccount,
		},
	}
}

func resourceNames(response *discoveryv3.DeltaDiscoveryResponse) []string {
	result := make([]string, 0, len(response.GetResources()))
	for _, resource := range response.GetResources() {
		result = append(result, resource.GetName())
	}
	return result
}
