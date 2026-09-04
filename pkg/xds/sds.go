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
	"reflect"
	"sort"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

// DomainCertificateProvider returns authorized certificate-domain values. SDS
// owns their Envoy wire representation.
type DomainCertificateProvider interface {
	GetForSDS(context.Context, model.ClientScope, string, bool) (mitm.SignedCertificate, error)
	Evicted() []string
}

var _ DomainCertificateProvider = (*mitm.OnDemandIssuer)(nil)

type SDSGenerator struct {
	provider DomainCertificateProvider
}

func NewSDSGenerator(provider DomainCertificateProvider) (*SDSGenerator, error) {
	if isNilCertificateProvider(provider) {
		return nil, fmt.Errorf("domain certificate provider is required")
	}
	return &SDSGenerator{provider: provider}, nil
}

func (g *SDSGenerator) Generate(ctx context.Context, request GenerationRequest) (GeneratedDelta, error) {
	if request.TypeURL != model.SecretType {
		return GeneratedDelta{}, fmt.Errorf("SDS generator cannot generate type %q", request.TypeURL)
	}
	if err := ctx.Err(); err != nil {
		return GeneratedDelta{}, err
	}
	// On-demand certificates are only issued for full generations; dirty pushes
	// use the snapshot generator.
	if !request.Full {
		return (SnapshotGenerator{}).Generate(ctx, request)
	}

	selected := make(map[string]model.Resource)
	for _, resource := range request.Snapshot.List(request.TypeURL) {
		if scopeAllows(request.Scope, resource) && request.Subscription.allows(resource) {
			selected[resource.XDSName] = resource
		}
	}
	result := GeneratedDelta{allowed: make([]string, 0, len(request.Subscription.names))}
	evicted := sets.New[string]()
	for _, name := range g.provider.Evicted() {
		evicted.Insert(mitm.CanonicalDomain(name))
	}
	subscribed := sets.NewWithLength[string](len(request.SubscribedNames))
	for _, name := range request.SubscribedNames {
		subscribed.Insert(mitm.CanonicalDomain(name))
	}
	removed := sets.New[string]()
	if !request.Subscription.Wildcard() {
		for _, requestedName := range request.Subscription.Names() {
			canonicalName := mitm.CanonicalDomain(requestedName)
			explicitlySubscribed := subscribed.Contains(canonicalName)
			if evicted.Contains(canonicalName) {
				removed.Insert(requestedName)
			}
			certificate, err := g.provider.GetForSDS(ctx, request.Scope, requestedName, explicitlySubscribed)
			if err != nil {
				delete(selected, requestedName)
				removed.Insert(requestedName)
				result.denied = append(result.denied, generatedDenial{name: requestedName, err: err})
				continue
			}
			removed.Delete(requestedName)
			result.allowed = append(result.allowed, requestedName)
			secret := &tlsv3.Secret{
				Name: requestedName,
				Type: &tlsv3.Secret_TlsCertificate{TlsCertificate: &tlsv3.TlsCertificate{
					CertificateChain: inlineDataSource(certificate.CertificateChain),
					PrivateKey:       inlineDataSource(certificate.PrivateKey),
				}},
			}
			value, err := anypb.New(secret)
			if err != nil {
				return GeneratedDelta{}, fmt.Errorf("encode SDS secret %q: %w", requestedName, err)
			}
			resource, err := model.NewResource(
				model.ResourceKey{TypeURL: model.SecretType, Name: request.Scope.GatewayKey + "|" + requestedName},
				requestedName,
				value,
				nil,
				model.ResourceFacts{GatewayOwner: request.Scope.GatewayKey},
			)
			if err != nil {
				return GeneratedDelta{}, fmt.Errorf("build SDS secret %q: %w", requestedName, err)
			}
			selected[requestedName] = resource
		}
	}
	delta := diffSelected(request.Subscription, selected)
	for _, name := range delta.Removed {
		removed.Insert(name)
	}
	delta.Removed = delta.Removed[:0]
	for name := range removed {
		delta.Removed = append(delta.Removed, name)
	}
	sort.Strings(delta.Removed)
	delta.denied = result.denied
	delta.allowed = result.allowed
	return delta, nil
}

func inlineDataSource(value []byte) *corev3.DataSource {
	return &corev3.DataSource{Specifier: &corev3.DataSource_InlineBytes{InlineBytes: append([]byte(nil), value...)}}
}

func isNilCertificateProvider(provider DomainCertificateProvider) bool {
	if provider == nil {
		return true
	}
	value := reflect.ValueOf(provider)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
