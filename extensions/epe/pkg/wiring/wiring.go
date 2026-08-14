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
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/credential"
	"istio.io/istio/extensions/epe/pkg/credential/tokencache"
	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/filters/block"
	"istio.io/istio/extensions/epe/pkg/filters/bypass"
	"istio.io/istio/extensions/epe/pkg/filters/headermutation"
	"istio.io/istio/extensions/epe/pkg/filters/mcpacl"
	"istio.io/istio/extensions/epe/pkg/filters/tokentransform"
	_ "istio.io/istio/extensions/epe/pkg/filters/tokentransform/signers/aliyun" // registers the AliyunSTS signer
)

// Deps carries what plugin builders may need. Kube is the typed Kubernetes
// clientset for one-shot reads (e.g. Secret reads) that must not spin up
// cluster-wide informers; tests may pass a fake clientset.
type Deps struct {
	Kube kubernetes.Interface
	// CredentialClient, when non-nil, is used as-is; tests use it to point
	// token plugins at an in-process provider. When nil, BuildFilters
	// builds a token-cache-backed client from the environment and Kube.
	CredentialClient *credential.Client
}

var wiringLog = ctrllog.Log.WithName("plugin-wiring")

// credClientFor returns the caller-supplied credential client or builds a
// token-cache-backed one. It uses the typed clientset for the one-shot
// Secret read so no informer attempts a cluster-wide List on Secrets — the
// ServiceAccount only has namespace-scoped read access. When the provider
// URL is not configured, provider-backed fetches fail through each rule's
// FailStrategy.
func credClientFor(deps Deps) *credential.Client {
	if deps.CredentialClient != nil {
		return deps.CredentialClient
	}
	tokenCache := tokencache.NewCacheFromEnv()
	wiringLog.Info("Token cache configured", "config", tokencache.ConfigInfo())
	stsTokenCache := tokencache.NewSTSCacheFromEnv()
	wiringLog.Info("STS token cache configured", "config", tokencache.STSCacheConfigInfo())
	return credential.NewClientWithCache(tokenCache, stsTokenCache, deps.Kube)
}

// BuildFilters returns the production action order used inside every rule.
// Rules themselves always run in policy order. Bypass precedes block so a
// malformed rule carrying both bypasses; body enforcement follows the cheap
// header-only actions. Generic header mutations precede credential transforms
// so a credential-derived value wins if two policy sources target the same
// header. Which transformation TYPES a rule can use is the tokentransform
// signer registry's decision; an unregistered type fails closed at projection
// time.
func BuildFilters(deps Deps) ([]filter.Registration, error) {
	credClient := credClientFor(deps)
	ttDeps := tokentransform.Deps{
		Kube:    deps.Kube,
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
