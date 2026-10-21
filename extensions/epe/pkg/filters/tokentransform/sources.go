// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package tokentransform

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
)

// Sources carries the two built-in credential sources. Fields are the
// CredentialSource interface so tests can substitute fakes.
type Sources struct {
	Secret   CredentialSource
	Provider CredentialSource
}

// SecretSource reads cached credentials within the configured watch scope.
type SecretSource struct {
	secrets   krt.Collection[*corev1.Secret]
	namespace string
}

// NewSecretSource shares a collection across token filters. An empty namespace
// permits references in all namespaces, matching the Kubernetes informer scope.
func NewSecretSource(secrets krt.Collection[*corev1.Secret], namespace string) *SecretSource {
	return &SecretSource{secrets: secrets, namespace: namespace}
}

// Fetch reads apiKey for tokens or accessKeyId/accessKeySecret/securityToken for STS.
func (s *SecretSource) Fetch(_ context.Context, ref Ref) (Credential, error) {
	if s.secrets == nil {
		return Credential{}, fmt.Errorf("secret credential source is not configured")
	}
	if s.namespace != "" && ref.Namespace != s.namespace {
		return Credential{}, fmt.Errorf("%w: secret %s/%s is outside EPEConfig namespace %s",
			ErrNoPermission, ref.Namespace, ref.Name, s.namespace)
	}
	cached := s.secrets.GetKey(ref.Namespace + "/" + ref.Name)
	if cached == nil {
		return Credential{}, fmt.Errorf("secret %s/%s not found", ref.Namespace, ref.Name)
	}
	sec := *cached
	switch ref.Kind {
	case CredentialKindToken:
		v, err := secretValue(sec, "apiKey")
		if err != nil {
			return Credential{}, err
		}
		return Credential{Token: v}, nil
	case CredentialKindSTS:
		ak, err := secretValue(sec, "accessKeyId")
		if err != nil {
			return Credential{}, err
		}
		sk, err := secretValue(sec, "accessKeySecret")
		if err != nil {
			return Credential{}, err
		}
		tok, err := secretValue(sec, "securityToken")
		if err != nil {
			return Credential{}, err
		}
		return Credential{AccessKeyID: ak, AccessKeySecret: sk, SecurityToken: tok}, nil
	default:
		return Credential{}, fmt.Errorf("unsupported credential kind %q", ref.Kind)
	}
}

func secretValue(s *corev1.Secret, key string) (string, error) {
	if s.Data == nil {
		return "", fmt.Errorf("secret %s/%s has no data", s.Namespace, s.Name)
	}
	v, ok := s.Data[key]
	if !ok || len(v) == 0 {
		return "", fmt.Errorf("secret %s/%s missing data key %q", s.Namespace, s.Name, key)
	}
	return string(v), nil
}

// ProviderSource calls the external credential-provider service through clients
// already selected by its caller. It does not resolve or validate ref.Provider.
type ProviderSource struct {
	tokens TokenProvider
	sts    STSProvider
}

// NewProviderSource returns a ProviderSource over the given clients; both
// may be nil, in which case the matching shape errors at fetch time.
func NewProviderSource(tokens TokenProvider, sts STSProvider) *ProviderSource {
	return &ProviderSource{tokens: tokens, sts: sts}
}

// Fetch dispatches on ref.Kind: CredentialKindToken calls the token endpoint,
// CredentialKindSTS the STS endpoint of the credential-provider service.
func (p *ProviderSource) Fetch(ctx context.Context, ref Ref) (Credential, error) {
	if ref.Name == "" {
		return Credential{}, fmt.Errorf("credential provider name is empty")
	}
	switch ref.Kind {
	case CredentialKindToken:
		if p.tokens == nil {
			return Credential{}, fmt.Errorf("credential client is not configured")
		}
		tok, err := p.tokens.GetTokenWithExtraMetadata(
			ctx,
			ref.AccessToken,
			ref.SandboxClientID,
			ref.Name,
			ref.ExtraMetadata,
		)
		if err != nil {
			return Credential{}, fmt.Errorf("credential provider call failed: %w", err)
		}
		return Credential{Token: tok}, nil
	case CredentialKindSTS:
		if p.sts == nil {
			return Credential{}, fmt.Errorf("credential client is not configured")
		}
		sts, err := p.sts.GetSTSCredentialWithExtraMetadata(
			ctx,
			ref.AccessToken,
			ref.SandboxClientID,
			ref.Name,
			ref.ExtraMetadata,
		)
		if err != nil {
			return Credential{}, fmt.Errorf("credential provider call failed: %w", err)
		}
		return Credential{
			AccessKeyID:     sts.AccessKeyID,
			AccessKeySecret: sts.AccessKeySecret,
			SecurityToken:   sts.SecurityToken,
		}, nil
	default:
		return Credential{}, fmt.Errorf("unsupported credential kind %q", ref.Kind)
	}
}
