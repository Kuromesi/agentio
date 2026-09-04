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
	"testing"
	"time"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

type fakeCertificateProvider struct {
	certificate        mitm.SignedCertificate
	evicted            []string
	signCalls          int
	err                error
	evictAfterSnapshot bool
}

func TestNewSDSGeneratorRejectsNilProvider(t *testing.T) {
	if _, err := NewSDSGenerator(nil); err == nil {
		t.Fatal("NewSDSGenerator accepted a nil certificate provider")
	}
}

func newTestSDSGenerator(t testing.TB, provider DomainCertificateProvider) *SDSGenerator {
	t.Helper()
	generator, err := NewSDSGenerator(provider)
	if err != nil {
		t.Fatalf("NewSDSGenerator: %v", err)
	}
	return generator
}

func (f *fakeCertificateProvider) Get(_ context.Context, _ model.ClientScope, name string) (mitm.SignedCertificate, error) {
	f.signCalls++
	if f.err != nil {
		return mitm.SignedCertificate{}, f.err
	}
	retained := f.evicted[:0]
	for _, evicted := range f.evicted {
		if mitm.CanonicalDomain(evicted) != mitm.CanonicalDomain(name) {
			retained = append(retained, evicted)
		}
	}
	f.evicted = retained
	return f.certificate, nil
}

func (f *fakeCertificateProvider) GetForSDS(
	ctx context.Context,
	scope model.ClientScope,
	name string,
	retryEvicted bool,
) (mitm.SignedCertificate, error) {
	if !retryEvicted {
		for _, evicted := range f.evicted {
			if mitm.CanonicalDomain(evicted) == mitm.CanonicalDomain(name) {
				return mitm.SignedCertificate{}, mitm.ErrDomainCertificateEvicted
			}
		}
	}
	return f.Get(ctx, scope, name)
}

func (f *fakeCertificateProvider) Evicted() []string {
	result := append([]string(nil), f.evicted...)
	if f.evictAfterSnapshot {
		f.evicted = append(f.evicted, "old.example.com")
		f.evictAfterSnapshot = false
	}
	return result
}

func TestSDSGeneratorEvictionAndResign(t *testing.T) {
	tests := []struct {
		name               string
		evicted            []string
		signErr            error
		evictAfterSnapshot bool
		watched            []string
		sent               map[string]string
		subscribedNames    []string
		wantResources      []string
		wantRemoved        []string
		wantSignCalls      int
		wantEvicted        []string
	}{
		{
			name:          "evicted domain removed without immediate resign",
			evicted:       []string{"old.example.com"},
			watched:       []string{"old.example.com"},
			sent:          map[string]string{"old.example.com": "old-version"},
			wantRemoved:   []string{"old.example.com"},
			wantSignCalls: 0,
			wantEvicted:   []string{"old.example.com"},
		},
		{
			name:               "eviction between snapshot and get does not resign",
			evictAfterSnapshot: true,
			watched:            []string{"old.example.com"},
			sent:               map[string]string{"old.example.com": "old-version"},
			wantRemoved:        []string{"old.example.com"},
			wantSignCalls:      0,
			wantEvicted:        []string{"old.example.com"},
		},
		{
			name:          "evicted watched domain without sent version removed",
			evicted:       []string{"old.example.com"},
			watched:       []string{"old.example.com"},
			sent:          map[string]string{},
			wantRemoved:   []string{"old.example.com"},
			wantSignCalls: 0,
			wantEvicted:   []string{"old.example.com"},
		},
		{
			name:          "removals sorted from unordered eviction snapshot",
			evicted:       []string{"z.example.com", "a.example.com", "m.example.com"},
			watched:       []string{"a.example.com", "m.example.com", "z.example.com"},
			sent:          map[string]string{},
			wantRemoved:   []string{"a.example.com", "m.example.com", "z.example.com"},
			wantSignCalls: 0,
			wantEvicted:   []string{"z.example.com", "a.example.com", "m.example.com"},
		},
		{
			name:            "explicit request resigns and clears evicted domain",
			evicted:         []string{"old.example.com"},
			watched:         []string{"old.example.com"},
			sent:            map[string]string{},
			subscribedNames: []string{"old.example.com"},
			wantResources:   []string{"old.example.com"},
			wantSignCalls:   1,
			wantEvicted:     []string{},
		},
		{
			name:            "subscribing another domain does not resign evicted domain",
			evicted:         []string{"old.example.com"},
			watched:         []string{"old.example.com", "new.example.com"},
			sent:            map[string]string{"old.example.com": "old-version"},
			subscribedNames: []string{"new.example.com"},
			wantResources:   []string{"new.example.com"},
			wantRemoved:     []string{"old.example.com"},
			wantSignCalls:   1,
			wantEvicted:     []string{"old.example.com"},
		},
		{
			name:            "failed explicit resign leaves domain evicted",
			evicted:         []string{"old.example.com"},
			signErr:         errors.New("sign failed"),
			watched:         []string{"old.example.com"},
			sent:            map[string]string{"old.example.com": "old-version"},
			subscribedNames: []string{"old.example.com"},
			wantRemoved:     []string{"old.example.com"},
			wantSignCalls:   1,
			wantEvicted:     []string{"old.example.com"},
		},
		{
			name:            "failed explicit resign without sent version removes domain",
			evicted:         []string{"old.example.com"},
			signErr:         errors.New("sign failed"),
			watched:         []string{"old.example.com"},
			sent:            map[string]string{},
			subscribedNames: []string{"old.example.com"},
			wantRemoved:     []string{"old.example.com"},
			wantSignCalls:   1,
			wantEvicted:     []string{"old.example.com"},
		},
		{
			name:          "rotation refresh resigns watched domain",
			watched:       []string{"old.example.com"},
			sent:          map[string]string{"old.example.com": "old-version"},
			wantResources: []string{"old.example.com"},
			wantSignCalls: 1,
			wantEvicted:   []string{},
		},
		{
			name:            "failed initial secret request removed",
			signErr:         errors.New("sign failed"),
			watched:         []string{"API.Example.COM."},
			sent:            map[string]string{},
			subscribedNames: []string{"API.Example.COM."},
			wantRemoved:     []string{"API.Example.COM."},
			wantSignCalls:   1,
			wantEvicted:     []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &fakeCertificateProvider{
				certificate:        testSDSCertificate(),
				evicted:            tt.evicted,
				err:                tt.signErr,
				evictAfterSnapshot: tt.evictAfterSnapshot,
			}
			watch := &watchState{started: true, names: sets.New(tt.watched...), sent: tt.sent}

			delta, err := newTestSDSGenerator(t, provider).Generate(context.Background(), GenerationRequest{
				Scope:           gatewayScope(),
				TypeURL:         model.SecretType,
				Subscription:    newSubscriptionView(watch),
				Full:            true,
				SubscribedNames: tt.subscribedNames,
			})
			if err != nil {
				t.Fatal(err)
			}
			var gotResources []string
			for _, resource := range delta.Resources {
				gotResources = append(gotResources, resource.XDSName)
			}
			if !slices.Equal(gotResources, tt.wantResources) || !slices.Equal(delta.Removed, tt.wantRemoved) {
				t.Fatalf("delta = resources:%v removed:%v, want resources:%v removed:%v",
					gotResources, delta.Removed, tt.wantResources, tt.wantRemoved)
			}
			if provider.signCalls != tt.wantSignCalls {
				t.Fatalf("sign calls = %d, want %d", provider.signCalls, tt.wantSignCalls)
			}
			if got := provider.Evicted(); !slices.Equal(got, tt.wantEvicted) {
				t.Fatalf("evicted after generate = %v, want %v", got, tt.wantEvicted)
			}
		})
	}
}

func TestLaggingSubscriberRefreshesRestoredDomainAndRemovesRemainingEviction(t *testing.T) {
	provider := &fakeCertificateProvider{
		certificate: testSDSCertificate(), evicted: []string{"a.example.com", "b.example.com"},
	}
	firstWatch := &watchState{
		started: true, names: sets.New("a.example.com", "b.example.com"),
		sent: map[string]string{"a.example.com": "old-a", "b.example.com": "old-b"},
	}
	first, err := newTestSDSGenerator(t, provider).Generate(context.Background(), GenerationRequest{
		Scope: gatewayScope(), TypeURL: model.SecretType, Subscription: newSubscriptionView(firstWatch), Full: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	requestWatch := &watchState{started: true, names: sets.New("a.example.com"), sent: map[string]string{}}
	if _, err := newTestSDSGenerator(t, provider).Generate(context.Background(), GenerationRequest{
		Scope: gatewayScope(), TypeURL: model.SecretType, Subscription: newSubscriptionView(requestWatch), Full: true,
		SubscribedNames: []string{"a.example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	secondWatch := &watchState{
		started: true, names: sets.New("a.example.com", "b.example.com"),
		sent: map[string]string{"a.example.com": "old-a", "b.example.com": "old-b"},
	}
	second, err := newTestSDSGenerator(t, provider).Generate(context.Background(), GenerationRequest{
		Scope: gatewayScope(), TypeURL: model.SecretType, Subscription: newSubscriptionView(secondWatch), Full: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Removed) != 2 || len(second.Resources) != 1 || second.Resources[0].XDSName != "a.example.com" ||
		len(second.Removed) != 1 || second.Removed[0] != "b.example.com" {
		t.Fatalf("deltas = first removed:%v second resources:%v removed:%v", first.Removed, second.Resources, second.Removed)
	}
	if len(provider.Evicted()) != 1 || provider.Evicted()[0] != "b.example.com" {
		t.Fatalf("provider after restored refresh = calls:%d evicted:%v, want only b.example.com evicted",
			provider.signCalls, provider.Evicted())
	}
}

func TestSDSGeneratorBuildsEnvoySecret(t *testing.T) {
	certificate := mitm.SignedCertificate{
		CertificateChain: []byte("certificate-chain"),
		PrivateKey:       []byte("private-key"),
		NotAfter:         time.Now().Add(time.Hour),
		SignedAt:         time.Now(),
		SignerRevision:   "one",
	}
	watch := &watchState{started: true, names: sets.New("api.example.com"), sent: map[string]string{}}
	generated, err := newTestSDSGenerator(t, &fakeCertificateProvider{certificate: certificate}).Generate(
		context.Background(),
		GenerationRequest{
			Scope:        gatewayScope(),
			TypeURL:      model.SecretType,
			Subscription: newSubscriptionView(watch),
			Full:         true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Resources) != 1 {
		t.Fatalf("resources = %d, want 1", len(generated.Resources))
	}
	secret := &tlsv3.Secret{}
	if err := generated.Resources[0].Value.UnmarshalTo(secret); err != nil {
		t.Fatal(err)
	}
	if got := secret.GetName(); got != "api.example.com" {
		t.Fatalf("secret name = %q, want api.example.com", got)
	}
	if got := secret.GetTlsCertificate().GetCertificateChain().GetInlineBytes(); string(got) != "certificate-chain" {
		t.Fatalf("certificate chain = %q, want certificate-chain", got)
	}
	if got := secret.GetTlsCertificate().GetPrivateKey().GetInlineBytes(); string(got) != "private-key" {
		t.Fatalf("private key = %q, want private-key", got)
	}
}

func TestSDSGeneratorPreservesExactSubscribedName(t *testing.T) {
	rawName := "API.Example.COM."
	watch := &watchState{started: true, names: sets.New(rawName), sent: map[string]string{}}
	generated, err := newTestSDSGenerator(t, &fakeCertificateProvider{certificate: testSDSCertificate()}).Generate(
		context.Background(),
		GenerationRequest{
			Scope:           gatewayScope(),
			TypeURL:         model.SecretType,
			Subscription:    newSubscriptionView(watch),
			Full:            true,
			SubscribedNames: []string{rawName},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Resources) != 1 {
		t.Fatalf("resources = %d, want 1", len(generated.Resources))
	}
	if got := generated.Resources[0].XDSName; got != rawName {
		t.Fatalf("xDS resource name = %q, want exact subscription %q", got, rawName)
	}
	secret := &tlsv3.Secret{}
	if err := generated.Resources[0].Value.UnmarshalTo(secret); err != nil {
		t.Fatal(err)
	}
	if got := secret.GetName(); got != rawName {
		t.Fatalf("secret name = %q, want exact subscription %q", got, rawName)
	}
}

func testSDSCertificate() mitm.SignedCertificate {
	now := time.Now()
	return mitm.SignedCertificate{
		CertificateChain: []byte("certificate-chain"),
		PrivateKey:       []byte("private-key"),
		NotAfter:         now.Add(time.Hour),
		SignedAt:         now,
		SignerRevision:   "one",
	}
}
