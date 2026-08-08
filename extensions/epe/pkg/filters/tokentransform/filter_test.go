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
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/eval"
	"istio.io/istio/extensions/epe/pkg/inputs"
)

type fakeSource struct {
	cred Credential
	err  error
	got  []Ref
}

func (f *fakeSource) Fetch(_ context.Context, ref Ref) (Credential, error) {
	f.got = append(f.got, ref)
	return f.cred, f.err
}

// newTestFilter builds a Filter over one config with scripted
// sources and the real ApiKey signer under its key.
func newTestFilter(secret, provider CredentialSource, cfg Config) *Filter {
	tmpl, _ := eval.CompileTemplate("valueTemplate", "Bearer {{ .Token }}")
	if cfg.SignerCfg == nil {
		cfg.SignerCfg = ApiKeyConfig{TargetHeader: "authorization", Template: tmpl}
	}
	return &Filter{
		sources: Sources{Secret: secret, Provider: provider},
		signers: map[string]Signer{TypeAPIKey: apiKeySigner{}},
		rule:    filter.RuleConfig[Config]{Cfg: cfg, Scope: &inputs.Scope{}},
	}
}

func secretCfg(failBlock bool) Config {
	return Config{Type: TypeAPIKey, FailBlock: failBlock,
		Source: SourceSpec{Kind: SourceKindSecret, Name: "s", Namespace: "ns"}}
}

func streamWithPeerToken() *filter.Stream {
	return &filter.Stream{Peer: filter.Peer{
		Pod:   types.NamespacedName{Namespace: "podns", Name: "pod-x"},
		Token: &filter.SandboxToken{AccessToken: "at", SandboxClientID: "cid"},
	}}
}

func streamWithoutPeerToken() *filter.Stream {
	return &filter.Stream{Peer: filter.Peer{Pod: types.NamespacedName{Namespace: "podns", Name: "pod-x"}}}
}

func TestFilterInjectsForEligibleRule(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	f := newTestFilter(src, nil, secretCfg(false))
	act, err := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if err != nil {
		t.Fatal(err)
	}
	muts := act.Mutations()
	if len(muts) != 1 || muts[0].HeaderOps[0].Value != "Bearer k" {
		t.Fatalf("action = %+v", act)
	}
	if len(src.got) != 1 {
		t.Fatalf("fetches = %d, want 1", len(src.got))
	}
}

func TestFilterWhenNotMetSkipsUnit(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	cfg := secretCfg(false)
	cfg.When = &When{Header: "x-guard", Re: regexp.MustCompile(`^go$`)}
	f := newTestFilter(src, nil, cfg)
	st := streamWithPeerToken()
	st.Request.Headers = map[string]string{"x-guard": "stop"}
	act, _ := f.OnRequestHeaders(context.Background(), st)
	if len(act.Mutations()) != 0 || len(src.got) != 0 {
		t.Fatalf("when condition must skip: muts=%v fetches=%d", act.Mutations(), len(src.got))
	}
}

func TestFilterWhenMetClaimsUnit(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	cfg := secretCfg(false)
	cfg.When = &When{Header: "x-guard", Re: regexp.MustCompile(`^go$`)}
	f := newTestFilter(src, nil, cfg)
	st := streamWithPeerToken()
	st.Request.Headers = map[string]string{"x-guard": "go"}
	act, _ := f.OnRequestHeaders(context.Background(), st)
	if len(act.Mutations()) != 1 {
		t.Fatalf("met condition must claim: %+v", act)
	}
}

func TestFilterProviderWithoutPeerTokenAllowContinues(t *testing.T) {
	providerCfg := Config{Type: TypeAPIKey,
		Source: SourceSpec{Kind: SourceKindProvider, Name: "prov"}}
	f := newTestFilter(nil, &fakeSource{}, providerCfg)
	act, _ := f.OnRequestHeaders(context.Background(), streamWithoutPeerToken())
	if act.Kind() != filter.KindContinue || len(act.Mutations()) != 0 {
		t.Fatalf("Allow pre-transform failure must continue: %+v", act)
	}
}

func TestFilterProviderWithoutPeerTokenBlockStops(t *testing.T) {
	cfg := Config{Type: TypeAPIKey, FailBlock: true,
		Source: SourceSpec{Kind: SourceKindProvider, Name: "prov"}}
	f := newTestFilter(nil, &fakeSource{}, cfg)
	act, _ := f.OnRequestHeaders(context.Background(), streamWithoutPeerToken())
	if act.Kind() != filter.KindStop {
		t.Fatalf("kind = %v, want KindStop", act.Kind())
	}
	reply, ok := act.Reply()
	if !ok || reply.Status != 403 || !strings.Contains(string(reply.Body), "tokentransform:") {
		t.Fatalf("reply = %+v, ok=%v", reply, ok)
	}
}

func TestFilterFetchErrorBlockStops(t *testing.T) {
	src := &fakeSource{err: errors.New("boom")}
	f := newTestFilter(src, nil, secretCfg(true))
	act, _ := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if act.Kind() != filter.KindStop {
		t.Fatalf("kind = %v, want KindStop", act.Kind())
	}
}

func TestFilterFetchErrorAllowEndsWalk(t *testing.T) {
	src := &fakeSource{err: errors.New("boom")}
	f := newTestFilter(src, nil, secretCfg(false))
	act, _ := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if act.Kind() != filter.KindContinue || len(act.Mutations()) != 0 {
		t.Fatalf("action = %+v", act)
	}
	if len(src.got) != 1 {
		t.Fatalf("fetches = %d, want 1: claimed unit's Allow failure ends the walk", len(src.got))
	}
}

// A denied credential read resolves through failStrategy like any other fetch
// failure. It used to pass through unconditionally, which meant an RBAC
// regression silently forwarded requests carrying the client's own credential
// even under the CRD-default Block.
func TestFilterNoPermissionHonoursFailStrategy(t *testing.T) {
	forbidden := func() *fakeSource {
		return &fakeSource{err: fmt.Errorf("%w: forbidden", ErrNoPermission)}
	}

	blocked, _ := newTestFilter(forbidden(), nil, secretCfg(true)).
		OnRequestHeaders(context.Background(), streamWithPeerToken())
	if blocked.Kind() != filter.KindStop {
		t.Fatalf("failStrategy=Block must block a denied read: %+v", blocked)
	}

	open, _ := newTestFilter(forbidden(), nil, secretCfg(false)).
		OnRequestHeaders(context.Background(), streamWithPeerToken())
	if open.Kind() != filter.KindContinue || len(open.Mutations()) != 0 {
		t.Fatalf("failStrategy=Open must pass a denied read through unmodified: %+v", open)
	}
}

func TestFilterSecretNamespaceFallback(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	cfg := secretCfg(false)
	cfg.Source.Namespace = "" // force fallback
	f := newTestFilter(src, nil, cfg)
	f.rule.Scope = &inputs.Scope{Profile: inputs.Profile{Namespace: "profilens"}}
	_, _ = f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if len(src.got) != 1 || src.got[0].Namespace != "profilens" {
		t.Fatalf("ref = %+v, want profile-namespace fallback", src.got)
	}
}

func TestFilterSecretNamespaceFallbackToPod(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	cfg := secretCfg(false)
	cfg.Source.Namespace = ""
	f := newTestFilter(src, nil, cfg)
	f.rule.Scope = &inputs.Scope{} // no profile namespace
	_, _ = f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if len(src.got) != 1 || src.got[0].Namespace != "podns" {
		t.Fatalf("ref = %+v, want pod-namespace fallback", src.got)
	}
}

type wantBodySigner struct{ apiKeySigner }

func (wantBodySigner) WantsBody(*filter.Stream) (bool, error) { return true, nil }

func TestFilterDefersToBodyPhase(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	f := newTestFilter(src, nil, secretCfg(false))
	f.signers[TypeAPIKey] = wantBodySigner{}
	st := streamWithPeerToken()
	act, _ := f.OnRequestHeaders(context.Background(), st)
	if act.Kind() != filter.KindNeedBody {
		t.Fatalf("headers action kind = %v, want KindNeedBody", act.Kind())
	}
	if len(src.got) != 0 {
		t.Fatalf("fetches in headers phase = %d, want 0 (deferred)", len(src.got))
	}
	bodyAct, _ := f.OnRequestBody(context.Background(), st, filter.Body{Bytes: []byte("x")})
	if len(bodyAct.Mutations()) != 1 {
		t.Fatalf("body action = %+v, want the injection", bodyAct)
	}
}

type ineligibleSigner struct{ apiKeySigner }

func (ineligibleSigner) WantsBody(*filter.Stream) (bool, error) {
	return false, errors.New("cannot detect scheme")
}

func TestFilterBodyWanterErrorAllowContinues(t *testing.T) {
	src := &fakeSource{cred: Credential{Token: "k"}}
	f := newTestFilter(src, nil, secretCfg(false))
	f.signers[TypeAPIKey] = ineligibleSigner{}
	act, _ := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if act.Kind() != filter.KindContinue || len(act.Mutations()) != 0 {
		t.Fatalf("action = %+v", act)
	}
	if len(src.got) != 0 {
		t.Fatalf("fetches = %d, want 0", len(src.got))
	}
}

func TestFilterBodyWanterErrorBlockStops(t *testing.T) {
	f := newTestFilter(&fakeSource{}, nil, secretCfg(true))
	f.signers[TypeAPIKey] = ineligibleSigner{}
	act, _ := f.OnRequestHeaders(context.Background(), streamWithPeerToken())
	if act.Kind() != filter.KindStop {
		t.Fatalf("kind = %v, want KindStop", act.Kind())
	}
}
