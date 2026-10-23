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
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

type pendingCertificate struct {
	name   string
	ctx    context.Context
	result chan mitm.SignedCertificate
}

type controlledCertificates struct {
	requests           chan pendingCertificate
	calls              atomic.Int32
	ignoreCancellation bool
	mu                 sync.Mutex
	revision           string
	authErr            error
}

func (p *controlledCertificates) Get(
	ctx context.Context,
	_ model.ClientScope,
	name string,
) (mitm.SignedCertificate, error) {
	p.calls.Add(1)
	request := pendingCertificate{name: name, ctx: ctx, result: make(chan mitm.SignedCertificate, 1)}
	p.requests <- request
	if p.ignoreCancellation {
		return <-request.result, nil
	}
	select {
	case certificate := <-request.result:
		return certificate, nil
	case <-ctx.Done():
		return mitm.SignedCertificate{}, ctx.Err()
	}
}
func (p *controlledCertificates) Authorize(model.ClientScope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.authErr
}
func (p *controlledCertificates) SignerRevision() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revision
}

func TestSDSColdReplayKeepsADSResponsiveAndPrioritizesFreshDemand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		provider := &controlledCertificates{requests: make(chan pendingCertificate, 128), revision: "one"}
		server := newTestServer(t, gatewayScope(), []model.Resource{
			gatewayResource(t, "demo/egress", "main_internal", "mine"),
		}, provider)
		stream := newFakeStream(ctx, 8)
		names := make([]string, 100)
		for idx := range names {
			names[idx] = fmt.Sprintf("replay-%d.example.com", idx)
		}
		stream.send(nodeRequest(model.SecretType, names...))
		done := make(chan error, 1)
		go func() { done <- server.server.serveDelta(stream) }()
		synctest.Wait()
		if got := provider.calls.Load(); got != sdsStreamConcurrency {
			t.Fatalf("active requests = %d", got)
		}
		stream.send(request(model.ClusterType))
		stream.send(request(model.SecretType, "fresh.example.com"))
		synctest.Wait()
		if len(stream.responsesFor(model.ClusterType)) != 1 {
			t.Fatal("cold SDS replay blocked CDS")
		}
		if len(stream.responsesFor(model.SecretType)) != 0 {
			t.Fatal("blocked signer produced a response")
		}
		first := <-provider.requests
		for range sdsStreamConcurrency - 1 {
			<-provider.requests
		}
		first.result <- testSDSCertificate()
		synctest.Wait()
		responses := stream.responsesFor(model.SecretType)
		if len(responses) != 1 || !slices.Equal(resourceNames(responses[0]), []string{first.name}) {
			t.Fatal("ready certificate waited for replay batch")
		}
		fresh := <-provider.requests
		if fresh.name != "fresh.example.com" {
			t.Fatalf("next issuance = %s, want fresh demand", fresh.name)
		}
		fresh.result <- testSDSCertificate()
		synctest.Wait()
		responses = stream.responsesFor(model.SecretType)
		if len(responses) != 2 || !slices.Equal(resourceNames(responses[1]), []string{fresh.name}) {
			t.Fatal("fresh demand did not complete")
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("disconnect = %v", err)
		}
	})
}

func TestSDSUnsubscribeDiscardsLateResultAfterResubscribe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider := &controlledCertificates{
			requests:           make(chan pendingCertificate, 2),
			revision:           "one",
			ignoreCancellation: true,
		}
		server := newTestServer(t, gatewayScope(), nil, provider)
		stream := newFakeStream(t.Context(), 4)
		done := make(chan error, 1)
		go func() { done <- server.server.serveDelta(stream) }()
		const name = "api.example.com"
		stream.send(nodeRequest(model.SecretType, name))
		synctest.Wait()
		old := <-provider.requests
		unsubscribe := request(model.SecretType)
		unsubscribe.ResourceNamesUnsubscribe = []string{name}
		stream.send(unsubscribe)
		stream.send(request(model.SecretType, name))
		synctest.Wait()
		if !errors.Is(old.ctx.Err(), context.Canceled) {
			t.Fatal("unsubscribe did not cancel issuance")
		}
		current := <-provider.requests
		current.result <- testSDSCertificate()
		synctest.Wait()
		late := testSDSCertificate()
		late.CertificateChain = []byte("stale certificate")
		old.result <- late
		synctest.Wait()
		responses := stream.responsesFor(model.SecretType)
		if len(responses) != 1 || !slices.Equal(resourceNames(responses[0]), []string{name}) ||
			len(responses[0].RemovedResources) != 0 {
			t.Fatalf("late result affected replacement: %v", responses)
		}
		stream.closeRequests()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestSDSCompletionRevalidatesBeforeSend(t *testing.T) {
	for _, change := range []string{"rotation", "expiry", "authorization"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider := &controlledCertificates{requests: make(chan pendingCertificate, 2), revision: "one"}
				server := newTestServer(t, gatewayScope(), nil, provider)
				generator := newTestSDSGenerator(t, provider)
				q := newSDSSession(t.Context(), generator, gatewayScope())
				defer q.cancel()
				const name = "api.example.com"
				watch := &watchState{names: sets.New(name), sent: make(map[string]string), sds: q}
				stream := newFakeStream(t.Context(), 1)
				q.subscribe([]string{name})
				q.start(server.resources.Snapshot())
				pending := <-provider.requests
				pending.result <- testSDSCertificate()
				ready := <-q.ready
				switch change {
				case "rotation":
					provider.revision = "two"
				case "expiry":
					time.Sleep(time.Hour)
				case "authorization":
					provider.authErr = errors.New("gateway deleted")
				}
				if err := server.server.sendSDSCompletions(stream, log, watch, ready); err != nil {
					t.Fatal(err)
				}
				if change == "authorization" {
					responses := stream.sent()
					if len(responses) != 1 || len(responses[0].Resources) != 0 ||
						!slices.Equal(responses[0].RemovedResources, []string{name}) {
						t.Fatal("revoked gateway received certificate")
					}
					return
				}
				if len(stream.sent()) != 0 || len(watch.sent) != 0 {
					t.Fatal("stale completion sent or committed")
				}
				retry := <-provider.requests
				cert := testSDSCertificate()
				cert.SignerRevision = provider.revision
				retry.result <- cert
				if err := server.server.sendSDSCompletions(stream, log, watch, <-q.ready); err != nil {
					t.Fatal(err)
				}
				if len(stream.sent()) != 1 ||
					!strings.HasPrefix(watch.sent[name], sdsVersionPrefix(provider.revision)) {
					t.Fatal("fresh generation not committed")
				}
			})
		})
	}
}

func TestSDSUnsubscribeWinsWithinOneRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider := &controlledCertificates{requests: make(chan pendingCertificate, 1), revision: "one"}
		server := newTestServer(t, gatewayScope(), nil, provider)
		stream := newFakeStream(t.Context(), 1)
		initial := nodeRequest(model.SecretType, "api.example.com")
		initial.ResourceNamesUnsubscribe = []string{"api.example.com"}
		stream.send(initial)
		if err := server.run(t, stream); err != nil {
			t.Fatal(err)
		}
		if provider.calls.Load() != 0 {
			t.Fatal("unsubscribed name was issued")
		}
	})
}

func TestSDSReconnectInvalidatesOldCABeforeSlowReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		provider := &controlledCertificates{requests: make(chan pendingCertificate, 1), revision: "two"}
		server := newTestServer(t, gatewayScope(), nil, provider)
		stream := newFakeStream(ctx, 1)
		initial := nodeRequest(model.SecretType, "api.example.com")
		initial.InitialResourceVersions = map[string]string{"api.example.com": sdsVersionPrefix("one") + "old-cert"}
		stream.send(initial)
		done := make(chan error, 1)
		go func() { done <- server.server.serveDelta(stream) }()
		defer func() {
			cancel()
			<-done
		}()
		synctest.Wait()
		for _, r := range stream.sent() {
			if slices.Contains(r.RemovedResources, "api.example.com") {
				return
			}
		}
		t.Fatal("old CA version was not invalidated; replacement is blocked and no future CA event is guaranteed")
	})
}

type reconnectTestSigner struct {
	calls   atomic.Int32
	started chan context.Context
	release chan struct{}
}

func (s *reconnectTestSigner) SignDNS(
	ctx context.Context,
	_ string,
	lifetime time.Duration,
) (mitm.SignedCertificate, error) {
	serial := s.calls.Add(1)
	if s.started != nil {
		s.started <- ctx
	}
	if s.release != nil {
		<-s.release
	}
	now := time.Now()
	return mitm.SignedCertificate{
		CertificateChain: []byte(fmt.Sprintf("certificate-%d", serial)),
		PrivateKey:       []byte("key"),
		SignedAt:         now,
		NotAfter:         now.Add(lifetime),
		SignerRevision:   "one",
	}, nil
}
func (*reconnectTestSigner) Authorize(model.ClientScope) error { return nil }

func TestSDSExpiryCoincidingWithReconnect(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		signer := &reconnectTestSigner{}
		state := krt.NewStatic(&mitm.SignerState{Revision: "one"}, true)
		issuer, err := mitm.NewOnDemandIssuer(ctx, mitm.DomainSignerSource{Signer: signer, State: state}, signer,
			mitm.OnDemandOptions{LeafLifetime: 15 * time.Minute, RenewBefore: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cancel()
			<-issuer.Done()
		}()
		server := newTestServer(t, gatewayScope(), nil, issuer)
		first := newFakeStream(ctx, 1)
		first.send(nodeRequest(model.SecretType, "api.example.com"))
		if err := server.run(t, first); err != nil {
			t.Fatal(err)
		}
		old := first.sent()[0].Resources[0]
		time.Sleep(14 * time.Minute)
		second := newFakeStream(ctx, 1)
		req := nodeRequest(model.SecretType, "api.example.com")
		req.InitialResourceVersions = map[string]string{"api.example.com": old.Version}
		second.send(req)
		if err := server.run(t, second); err != nil {
			t.Fatal(err)
		}
		newer := second.sent()[0].Resources[0]
		if signer.calls.Load() != 2 || old.Version == newer.Version || newer.Ttl.AsDuration() != 14*time.Minute {
			t.Fatalf("expiry reconnect did not renew: calls=%d old=%s new=%v", signer.calls.Load(), old.Version, newer)
		}
	})
}

func TestSDSNewStreamSurvivesOldStreamCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		signer := &reconnectTestSigner{started: make(chan context.Context, 2), release: make(chan struct{})}
		state := krt.NewStatic(&mitm.SignerState{Revision: "one"}, true)
		issuer, err := mitm.NewOnDemandIssuer(ctx, mitm.DomainSignerSource{Signer: signer, State: state}, signer,
			mitm.OnDemandOptions{LeafLifetime: 15 * time.Minute, RenewBefore: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cancel()
			<-issuer.Done()
		}()
		server := newTestServer(t, gatewayScope(), nil, issuer)
		oldCtx, cancelOld := context.WithCancel(ctx)
		old := newFakeStream(oldCtx, 1)
		old.send(nodeRequest(model.SecretType, "api.example.com"))
		oldDone := server.start(old)
		synctest.Wait()
		flightCtx := <-signer.started
		current := newFakeStream(ctx, 1)
		current.send(nodeRequest(model.SecretType, "api.example.com"))
		newDone := server.start(current)
		synctest.Wait()
		cancelOld()
		<-oldDone
		synctest.Wait()
		if flightCtx.Err() != nil {
			t.Fatal("old stream canceled flight still needed by new stream")
		}
		close(signer.release)
		synctest.Wait()
		if signer.calls.Load() != 1 || len(current.sent()) != 1 {
			t.Fatalf(
				"new stream did not receive shared result: calls=%d responses=%d",
				signer.calls.Load(),
				len(current.sent()),
			)
		}
		current.closeRequests()
		if err := <-newDone; err != nil {
			t.Fatal(err)
		}
	})
}
