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
	"errors"
	"slices"
	"strings"
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/structpb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

type recordingGenerator struct {
	calls int
	delta GeneratedDelta
	err   error
}

type subscriptionRecordingGenerator struct {
	sentNames []string
}

type scopeRecordingGenerator struct {
	scope model.ClientScope
}

type requestRecordingGenerator struct {
	request GenerationRequest
}

func (g *subscriptionRecordingGenerator) Generate(_ context.Context, request GenerationRequest) (GeneratedDelta, error) {
	g.sentNames = request.Subscription.SentNames()
	request.Subscription.sent["cluster//Pod/demo/unrelated"] = "mutated"
	return GeneratedDelta{}, nil
}

func (g *recordingGenerator) Generate(context.Context, GenerationRequest) (GeneratedDelta, error) {
	g.calls++
	return g.delta, g.err
}

func (g *scopeRecordingGenerator) Generate(_ context.Context, request GenerationRequest) (GeneratedDelta, error) {
	g.scope = request.Scope
	return GeneratedDelta{}, nil
}

func (g *requestRecordingGenerator) Generate(_ context.Context, request GenerationRequest) (GeneratedDelta, error) {
	g.request = request
	return GeneratedDelta{}, nil
}

func TestDirtyGenerationUsesQueuedPublicationTransition(t *testing.T) {
	oldResource := addressResource(t, "cluster//Pod/demo/a", "old")
	middleResource := addressResource(t, "cluster//Pod/demo/a", "middle")
	newResource := addressResource(t, "cluster//Pod/demo/a", "new")
	snapshot := func(resource model.Resource) model.ResourceSet {
		result, err := model.NewResourceSet([]model.Resource{resource})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot(oldResource)
	after := snapshot(middleResource)
	live := snapshot(newResource)
	generator := &requestRecordingGenerator{}
	server := newTestServerWithGenerators(t, ztunnelScope(), []model.Resource{newResource}, map[string]ResourceGenerator{
		model.AddressType: generator,
	})
	watch := &watchState{wildcard: true, started: true, names: sets.New[string](), sent: map[string]string{}}
	update := updateBetween(before, after, []model.ResourceChange{{
		Key: oldResource.Key, Old: &oldResource, New: &middleResource,
	}})

	if got := server.resources.Snapshot().Version(); got != live.Version() {
		t.Fatalf("live snapshot version = %q, want %q", got, live.Version())
	}
	if err := server.server.sendDirty(newFakeStream(context.Background(), 1), server.scope, log,
		model.AddressType, watch, update); err != nil {
		t.Fatal(err)
	}

	if got := generator.request.Update.Before().Version(); got != before.Version() {
		t.Fatalf("generator Before version = %q, want %q", got, before.Version())
	}
	if got := generator.request.Snapshot.Version(); got != after.Version() {
		t.Fatalf("generator After version = %q, want queued %q rather than live %q", got, after.Version(), live.Version())
	}
}

func TestServerPassesResolvedScopeToGeneratorUnchanged(t *testing.T) {
	scope := ztunnelScope()
	generator := &scopeRecordingGenerator{}
	server := newTestServerWithGenerators(t, scope, nil, map[string]ResourceGenerator{
		model.AddressType: generator,
	})
	stream := newFakeStream(context.Background(), 1)
	request := nodeRequest(model.AddressType)
	request.Node.Metadata.Fields["ISTIO_VERSION"] = structpb.NewStringValue("1.24.2")
	stream.send(request)
	if err := server.run(t, stream); err != nil {
		t.Fatal(err)
	}

	if generator.scope != scope {
		t.Fatalf("generator scope = %#v, want resolved scope %#v", generator.scope, scope)
	}
}

func TestDirtyGenerationCopiesOnlyRelevantSentState(t *testing.T) {
	oldResource := addressResource(t, "cluster//Pod/demo/a", "old")
	newResource := addressResource(t, "cluster//Pod/demo/a", "new")
	generator := &subscriptionRecordingGenerator{}
	server := newTestServerWithGenerators(t, ztunnelScope(), []model.Resource{newResource}, map[string]ResourceGenerator{
		model.AddressType: generator,
	})
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent: map[string]string{
			oldResource.XDSName:           oldResource.Hash,
			"cluster//Pod/demo/unrelated": "unchanged-hash",
		},
	}
	update := updateReversedFrom(t, server.resources.Snapshot(), []model.ResourceChange{{
		Key: newResource.Key, Old: &oldResource, New: &newResource,
	}})
	if err := server.server.sendDirty(newFakeStream(context.Background(), 1), server.scope, log, model.AddressType, watch, update); err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(generator.sentNames, []string{oldResource.XDSName}) {
		t.Fatalf("dirty sent-state copy = %v, want only %q", generator.sentNames, oldResource.XDSName)
	}
	if got := watch.sent["cluster//Pod/demo/unrelated"]; got != "unchanged-hash" {
		t.Fatalf("generator mutated live sent state to %q", got)
	}
}

func TestFailedSendDoesNotCommitGeneratedDelta(t *testing.T) {
	oldResource := addressResource(t, "cluster//Pod/demo/old", "old")
	newResource := addressResource(t, "cluster//Pod/demo/new", "new")
	generator := &recordingGenerator{delta: GeneratedDelta{
		Resources: []model.Resource{newResource},
		Removed:   []string{oldResource.XDSName},
	}}
	server := newTestServerWithGenerators(t, ztunnelScope(), nil, map[string]ResourceGenerator{
		model.AddressType: generator,
	})
	watch := &watchState{
		wildcard: true,
		started:  true,
		names:    sets.New[string](),
		sent:     map[string]string{oldResource.XDSName: oldResource.Hash},
		nonce:    "previous",
	}
	stream := newFakeStream(context.Background(), 1)
	stream.setSendErr(errors.New("send failed"))
	err := server.server.generateAndSend(stream, log, watch, GenerationRequest{
		Scope: server.scope, TypeURL: model.AddressType, Subscription: newSubscriptionView(watch), Full: true,
	}, false)
	if err == nil || err.Error() != "send failed" {
		t.Fatalf("send error = %v, want send failed", err)
	}
	if !slices.Equal(watchSentNames(watch), []string{oldResource.XDSName}) || watch.sent[oldResource.XDSName] != oldResource.Hash {
		t.Fatalf("failed send committed sent state: %v", watch.sent)
	}
	if watch.nonce != "previous" {
		t.Fatalf("failed send committed nonce %q", watch.nonce)
	}
}

func TestServerRejectsMismatchedGeneratorResource(t *testing.T) {
	resource := addressResource(t, "cluster//Pod/demo/a", "a")
	generator := &recordingGenerator{delta: GeneratedDelta{Resources: []model.Resource{resource}}}
	server := newTestServerWithGenerators(t, gatewayScope(), nil, map[string]ResourceGenerator{
		model.SecretType: generator,
	})
	stream := newFakeStream(context.Background(), 1)
	stream.send(nodeRequest(model.SecretType, "api.example.com"))
	err := server.run(t, stream)
	if err == nil || !strings.Contains(err.Error(), "mismatched type URL") {
		t.Fatalf("stream error = %v, want mismatched type URL", err)
	}
	if responses := stream.sent(); len(responses) != 0 {
		t.Fatalf("invalid generator result was sent: %#v", responses)
	}
}

func watchSentNames(watch *watchState) []string {
	return newSubscriptionView(watch).SentNames()
}

func TestServerDispatchesGeneratorByTypeURL(t *testing.T) {
	resource, err := model.NewResource(
		model.ResourceKey{TypeURL: model.SecretType, Name: "demo/egress|api.example.com"},
		"api.example.com",
		mustAny(&tlsv3.Secret{Name: "api.example.com"}),
		nil,
		model.ResourceFacts{GatewayOwner: "demo/egress"},
	)
	if err != nil {
		t.Fatal(err)
	}
	generator := &recordingGenerator{delta: GeneratedDelta{Resources: []model.Resource{resource}}}
	server := newTestServerWithGenerators(t, gatewayScope(), nil, map[string]ResourceGenerator{
		model.SecretType: generator,
	})
	stream := newFakeStream(context.Background(), 1)
	stream.send(nodeRequest(model.SecretType, "api.example.com"))
	if err := server.run(t, stream); err != nil {
		t.Fatal(err)
	}

	if generator.calls != 1 {
		t.Fatalf("generator calls = %d, want 1", generator.calls)
	}
	responses := stream.responsesFor(model.SecretType)
	if len(responses) != 1 || len(responses[0].GetResources()) != 1 {
		t.Fatalf("responses = %#v, want one resource", responses)
	}
	if got := responses[0].GetResources()[0].GetName(); got != "api.example.com" {
		t.Fatalf("resource name = %q, want api.example.com", got)
	}
}

func TestLegacyWorkloadConfigSubscriptionKeepsDedicatedZTunnelStreamOpen(t *testing.T) {
	// Neither WorkloadConfig shape is served anymore; both must degrade to an
	// empty compatibility response that keeps the stream open.
	workloadConfigTypes := []string{
		"type.googleapis.com/kruise.extensions.WorkloadConfig",
		"type.googleapis.com/kruise.networking.extensions.v1.WorkloadConfig",
	}
	for _, workloadConfigType := range workloadConfigTypes {
		server := newTestServer(t, ztunnelScope(), nil, nil)
		stream := newFakeStream(context.Background(), 2)
		stream.send(nodeRequest(model.AddressType))
		stream.send(request(workloadConfigType))

		if err := server.run(t, stream); err != nil {
			t.Fatalf("WorkloadConfig subscription %s closed the stream: %v", workloadConfigType, err)
		}
		responses := stream.responsesFor(workloadConfigType)
		if len(responses) != 1 || len(responses[0].GetResources()) != 0 {
			t.Fatalf("WorkloadConfig responses for %s = %#v, want one empty compatibility response", workloadConfigType, responses)
		}
	}
}

func TestUnknownTypeSubscriptionReturnsEmptyResponseWithoutClosingStream(t *testing.T) {
	const unknownType = "type.googleapis.com/example.OptionalResource"
	server := newTestServer(t, ztunnelScope(), nil, nil)
	stream := newFakeStream(context.Background(), 2)
	stream.send(nodeRequest(model.AddressType))
	stream.send(request(unknownType))

	if err := server.run(t, stream); err != nil {
		t.Fatalf("unknown type subscription closed the stream: %v", err)
	}
	responses := stream.responsesFor(unknownType)
	if len(responses) != 1 || len(responses[0].GetResources()) != 0 {
		t.Fatalf("unknown type responses = %#v, want one empty response", responses)
	}
}

func TestWorkloadTypeIsGatewayOnly(t *testing.T) {
	for _, class := range []model.ClientClass{
		model.ClientSharedZTunnel,
		model.ClientDedicatedZTunnel,
	} {
		if allowedType(class, model.WorkloadType) {
			t.Errorf("allowedType(%q, WorkloadType) = true, want false", class)
		}
	}
	if !allowedType(model.ClientEgressGateway, model.WorkloadType) {
		t.Fatal("egress gateway cannot subscribe WorkloadType")
	}
}
