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

package attestation

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/openkruise/agentio/pkg/model"
	"istio.io/istio/pkg/util/sets"
)

// ErrUnsupportedCredentials reports that an authenticator does not recognize
// the credential type on the connection at all. It is the only error that
// lets an AuthenticatorChain move on to the next attestation authenticator;
// every other error means the credentials were recognized and rejected.
var ErrUnsupportedCredentials = errors.New("unsupported client credentials")

// AuthenticatorChain tries each authenticator in order, skipping ErrUnsupportedCredentials and stopping on any other error.
type AuthenticatorChain []Authenticator

func (c AuthenticatorChain) Authenticate(ctx context.Context) (model.PeerIdentity, error) {
	for _, authenticator := range c {
		peer, err := authenticator.Authenticate(ctx)
		if errors.Is(err, ErrUnsupportedCredentials) {
			continue
		}
		return peer, err
	}
	return model.PeerIdentity{}, fmt.Errorf("no authenticator recognizes the client credentials")
}

type registeredAttestationAuthenticator struct {
	delegate Authenticator
	allowed  sets.Set[model.Attestation]
}

// NewRegisteredAttestationAuthenticator restricts successful authentication to attestations registered by the composition root.
func NewRegisteredAttestationAuthenticator(
	delegate Authenticator,
	attestations []model.Attestation,
) (Authenticator, error) {
	if authenticatorIsNil(delegate) {
		return nil, fmt.Errorf("registered attestation authenticator requires a delegate")
	}
	if chain, ok := delegate.(AuthenticatorChain); ok {
		for index, authenticator := range chain {
			if authenticatorIsNil(authenticator) {
				return nil, fmt.Errorf("registered attestation authenticator delegate %d is nil", index+1)
			}
		}
	}
	if len(attestations) == 0 {
		return nil, fmt.Errorf("registered attestation authenticator requires at least one attestation")
	}
	allowed := sets.NewWithLength[model.Attestation](len(attestations))
	for _, attestation := range attestations {
		if attestation == "" {
			return nil, fmt.Errorf("registered attestation must not be empty")
		}
		allowed.Insert(attestation)
	}
	return registeredAttestationAuthenticator{delegate: delegate, allowed: allowed}, nil
}

func authenticatorIsNil(authenticator Authenticator) bool {
	if authenticator == nil {
		return true
	}
	value := reflect.ValueOf(authenticator)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (a registeredAttestationAuthenticator) Authenticate(ctx context.Context) (model.PeerIdentity, error) {
	peer, err := a.delegate.Authenticate(ctx)
	if err != nil {
		return model.PeerIdentity{}, err
	}
	if !a.allowed.Contains(peer.AttestedBy) {
		return model.PeerIdentity{}, fmt.Errorf("authenticated attestation %q is not registered", peer.AttestedBy)
	}
	return peer, nil
}

type DelegatedIdentityAuthorizer interface {
	Authorize(context.Context, model.PeerIdentity, model.Principal) error
}

// DelegatedIdentityAuthorizers dispatches delegated-identity authorization by
// the caller's authenticated attestation. The selected authorizer owns the
// interpretation of that attestation's evidence and validates the requested
// Principal; an unregistered attestation fails closed.
type DelegatedIdentityAuthorizers map[model.Attestation]DelegatedIdentityAuthorizer

func (a DelegatedIdentityAuthorizers) Authorize(ctx context.Context, caller model.PeerIdentity, requested model.Principal) error {
	authorizer, found := a[caller.AttestedBy]
	if !found || DelegatedAuthorizerIsNil(authorizer) {
		return fmt.Errorf("no authorizer owns %q caller attestation", caller.AttestedBy)
	}
	return authorizer.Authorize(ctx, caller, requested)
}

// DelegatedAuthorizerIsNil reports whether authorizer is nil, including a nil
// concrete value held in a non-nil interface — the shape a partially wired
// composition hands out.
func DelegatedAuthorizerIsNil(authorizer DelegatedIdentityAuthorizer) bool {
	if authorizer == nil {
		return true
	}
	value := reflect.ValueOf(authorizer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
