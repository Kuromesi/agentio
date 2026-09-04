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

// Package wiring assembles the production filter chain. It is the
// composition root of the engine: the one engine-adjacent package allowed
// to know the policy API and concrete filter dependencies. The engine
// itself (pkg/engine) stays free of both — enforced by the arch guard
// tests in this package.
package wiring

import (
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/block"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/bypass"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/headermutation"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/mcpacl"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform"
	_ "github.com/openkruise/agentio/extensions/epe/pkg/filters/tokentransform/signers/aliyun" // registers the AliyunSTS signer
	"github.com/openkruise/agentio/pkg/kube"
)

// Deps carries what plugin builders may need.
type Deps struct {
	// Kube is the shared Agentio Kubernetes client. It backs the token filters' one-shot
	// Secret reads (via its typed clientset) and, when
	// CREDENTIAL_PROVIDER_MTLS_SOURCE is "secret", the scoped watch behind the
	// credential provider's mTLS material. Tests may pass kube.NewFakeClient,
	// or leave it nil to build a chain with no cluster.
	Kube kube.Client
	// Stop bounds the lifetime of the certificate reload machinery Deps starts.
	// A nil channel never closes, which is the right lifetime for a
	// process-long provider and is what a zero-value Deps in tests gets.
	Stop <-chan struct{}
	// CredentialClient, when non-nil, is used as-is; tests use it to point
	// token plugins at an in-process provider. When nil, BuildFilters
	// builds a token-cache-backed client from the environment and Kube.
	CredentialClient *credential.Client
}

// typedClientset returns the typed clientset for filters that do one-shot
// reads, or nil when no cluster is wired. A nil kube.Client cannot be
// dereferenced, and those filters already treat a nil clientset as
// "no Secret source configured".
func typedClientset(deps Deps) kubernetes.Interface {
	if deps.Kube == nil {
		return nil
	}
	return deps.Kube.Kube()
}

// BuildFilters returns the production action order used inside every rule.
// Rules themselves always run in policy order. Bypass precedes block so a
// malformed rule carrying both bypasses; body enforcement follows the cheap
// header-only actions. Generic header mutations precede credential transforms
// so a credential-derived value wins if two policy sources target the same
// header. Which transformation TYPES a rule can use is the tokentransform
// signer registry's decision; an unregistered type fails closed at projection
// time.
//
// The httpcallout filter is deliberately absent: no policy action can produce
// its payload key yet, so registering it would build a shared HTTP client for
// a filter that can never run. It returns to this chain when the policy API
// grows the action, between header mutation and credential transforms.
func BuildFilters(deps Deps) ([]filter.Registration, error) {
	credClient, err := credClientFor(deps)
	if err != nil {
		return nil, err
	}
	ttDeps := tokentransform.Deps{
		Kube:    typedClientset(deps),
		Limiter: tokentransform.NewLimiter(time.Minute, nil),
		Tokens:  credClient,
		STS:     credClient,
	}
	definitions := []filter.Definition{
		bypass.Definition(),
		block.Definition(),
		mcpacl.Definition(),
		headermutation.Definition(),
		tokentransform.NewDefinition(ttDeps),
	}
	return filter.Build(definitions...)
}
