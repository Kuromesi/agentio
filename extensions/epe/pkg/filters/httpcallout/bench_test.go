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
package httpcallout

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/httpreq"
)

// These benchmarks price what a callout costs EPE, not what it costs the
// endpoint. Wall-clock for a real callout is dominated by the round trip, which
// no benchmark can report usefully, so nothing here opens a socket — the numbers
// are the CPU and allocations EPE spends per callout regardless of how fast the
// endpoint answers. That is the part a code change can regress.
//
// The body-size axis is the one to watch. A callout with a body still walks it
// twice: bodyText copies it into a string (invocation.go:185), Invocation.Validate
// scans it for UTF-8, and json.Marshal writes a second, escaped copy into the
// payload (client.go:101). BenchmarkCalloutCPUPath/serialize charges all of it
// together; the stage benchmarks below split it so the shares are visible.
//
// bodyText used to scan for UTF-8 as well, which made three passes for two
// invariants. The scan now lives only in Validate, which cannot give it up:
// json.Marshal replaces invalid bytes with U+FFFD instead of failing, so without
// it a mangled body would reach the endpoint and its verdict would be trusted.

// Sinks defeat dead-code elimination. They are typed rather than one `any`
// because assigning a struct to an interface heap-allocates a copy, which would
// add an allocation these benchmarks do not want to attribute to the code under
// test: decisionAction's no-mutation path returns filter.Continue() and must
// report zero allocations.
var (
	benchInv     Invocation
	benchAction  filter.Action
	benchPayload []byte
	benchErr     error
)

// benchRequestID is fixed so a pre-encoded decision can echo it without the
// client having to build one inside the timed loop.
const benchRequestID = "req-bench"

// benchBodySizes spans a header-sized payload, a typical agent request, and
// DefaultMaxBodyBytes — the largest body a default config will send.
var benchBodySizes = []int{1 << 10, 64 << 10, 1 << 20}

// benchStream builds the stream the engine would hand a filter, carrying
// nOperator ordinary headers per direction on top of the credentials a real
// request and a real upstream response always include. The credentials are
// present so HeaderModeAll pays for the neverForward check that drops them.
func benchStream(nOperator int) *filter.Stream {
	reqHeaders := map[string]string{
		"content-type":  "application/json",
		"authorization": "Bearer caller-credential",
		"cookie":        "session=abc",
	}
	respHeaders := map[string]string{
		"content-type": "application/json",
		"set-cookie":   "session=upstream-minted",
	}
	for i := 0; i < nOperator; i++ {
		suffix := strconv.Itoa(i)
		reqHeaders["x-agent-"+suffix] = "request-value-" + suffix
		respHeaders["x-upstream-"+suffix] = "response-value-" + suffix
	}
	return &filter.Stream{
		Peer: filter.Peer{
			Pod:    types.NamespacedName{Namespace: "default", Name: "agent-0"},
			IP:     "10.0.0.8",
			Labels: map[string]string{"app": "agent", "version": "v2"},
			Token:  &filter.SandboxToken{AccessToken: "secret-token", SandboxClientID: "client-1"},
		},
		RequestID: benchRequestID,
		Request: httpreq.HTTPRequest{
			Host:     "api.example.com",
			Port:     443,
			Path:     "/v1/run",
			RawQuery: "debug=true&trace=1",
			Method:   "POST",
			Scheme:   "https",
			Headers:  reqHeaders,
		},
		Response: httpreq.HTTPResponse{Status: 200, Headers: respHeaders},
	}
}

// benchAllowlist names half the operator headers plus content-type, so allowlist
// mode does real lookups instead of degenerating to an empty result.
func benchAllowlist(nOperator int) []string {
	out := []string{"content-type"}
	for i := 0; i < nOperator/2; i++ {
		out = append(out, "x-agent-"+strconv.Itoa(i))
	}
	return out
}

// benchConfig runs Effective the way the engine does at load time, so the
// benchmarks measure the filter against a config shaped like production's.
// MaxBodyBytes is raised past DefaultMaxBodyBytes because the largest body size
// benchmarked equals the default cap, and bodyText rejects rather than truncates.
func benchConfig(b *testing.B, cfg Config) Config {
	b.Helper()
	cfg.Endpoint = "https://scanner.example.com/inspect"
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 8 << 20
	}
	effective, err := cfg.Effective()
	if err != nil {
		b.Fatalf("Effective: %v", err)
	}
	return effective
}

// benchBody builds a valid UTF-8 body of about n bytes, shaped like the JSON an
// agent actually sends. It is deliberately all ASCII: utf8.Valid has a fast path
// for ASCII runs, so every body number here is a floor for traffic carrying
// multi-byte text.
func benchBody(n int) filter.Body {
	const chunk = `{"role":"user","content":"summarise the quarterly revenue report"},`
	var sb strings.Builder
	sb.Grow(n + len(chunk))
	sb.WriteString(`{"messages":[`)
	for sb.Len() < n {
		sb.WriteString(chunk)
	}
	sb.WriteString(`{"role":"user","content":"done"}]}`)
	return filter.Body{Bytes: []byte(sb.String()), Complete: true}
}

// benchClient answers with the cheapest decision that validates against the
// invocation. It records nothing on purpose: fakeClient appends every invocation
// to a slice, which across b.N iterations would both dominate the allocation
// numbers and grow without bound.
//
// serialize makes it do the CPU half of HTTPClient.Call — marshal the
// invocation, unmarshal a decision — so the composite benchmark can report the
// real per-callout cost with only the socket removed. respJSON is pre-encoded
// because encoding it per call would charge the endpoint's work to EPE.
type benchClient struct {
	mutate    bool
	serialize bool
	respJSON  []byte
}

func newBenchClient(b *testing.B, phase Phase, mutate, serialize bool) *benchClient {
	b.Helper()
	c := &benchClient{mutate: mutate, serialize: serialize}
	if !serialize {
		return c
	}
	raw, err := json.Marshal(c.decision(phase))
	if err != nil {
		b.Fatalf("encode bench decision: %v", err)
	}
	c.respJSON = raw
	return c
}

// decision builds the answer for one phase. A mutation is attached to the field
// that phase allows: continueAction reads Request in the request phase and
// Response in the response phase, and Decision.Validate rejects the other.
func (c *benchClient) decision(phase Phase) Decision {
	d := Decision{
		Version:   ProtocolVersion,
		Phase:     phase,
		RequestID: benchRequestID,
		Action:    actionPtr(ActionContinue),
	}
	if !c.mutate {
		return d
	}
	value := "clean"
	headers := []HeaderMutation{{Operation: HeaderSet, Name: "x-callout-verdict", Value: &value}}
	if phase == PhaseRequest {
		d.Request = &RequestMutation{Headers: headers}
	} else {
		d.Response = &ResponseMutation{Headers: headers}
	}
	return d
}

func (c *benchClient) Call(_ context.Context, _ Config, inv Invocation) (Decision, error) {
	if !c.serialize {
		return c.decision(inv.Phase), nil
	}
	payload, err := json.Marshal(inv)
	if err != nil {
		return Decision{}, err
	}
	benchPayload = payload
	var decision Decision
	if err := json.Unmarshal(c.respJSON, &decision); err != nil {
		return Decision{}, err
	}
	return decision, nil
}

// benchFilter builds one filter the way the engine does, per direction.
func benchFilter(b *testing.B, cfg Config, client Client) filter.Filter {
	b.Helper()
	return NewDescriptor(Deps{Client: client}).New(filter.RuleConfig[Config]{
		ID:  testUnitID(),
		Cfg: benchConfig(b, cfg),
	})
}

// BenchmarkBuildRequestInvocation charges the header disclosure modes against
// each other at two header counts. forwardedHeaders always builds a new map
// (invocation.go:137), so this is where a header-heavy request spends its
// callout budget when no body is collected.
//
// allowlist is bounded by the operator's list and all by what the caller sent,
// which is the asymmetry worth watching: a caller can grow the all-mode map,
// not the allowlist one.
func BenchmarkBuildRequestInvocation(b *testing.B) {
	for _, headers := range []int{8, 32} {
		modes := []struct {
			name string
			cfg  HeadersConfig
		}{
			{"none", HeadersConfig{Mode: HeaderModeNone}},
			{"allowlist", HeadersConfig{Mode: HeaderModeAllowlist, Allowlist: benchAllowlist(headers)}},
			{"all", HeadersConfig{Mode: HeaderModeAll}},
		}
		for _, mode := range modes {
			name := "headers=" + strconv.Itoa(headers) + "/mode=" + mode.name
			b.Run(name, func(b *testing.B) {
				cfg := benchConfig(b, Config{Request: &PhaseConfig{Headers: mode.cfg}})
				st := benchStream(headers)
				id := testUnitID()
				// Guard the fixture: a builder that errors would otherwise be
				// benchmarked on its error path.
				if _, err := buildRequestInvocation(cfg, id, st, filter.Body{}); err != nil {
					b.Fatalf("buildRequestInvocation: %v", err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					benchInv, _ = buildRequestInvocation(cfg, id, st, filter.Body{})
				}
			})
		}
	}
}

// BenchmarkBuildRequestInvocationBody isolates bodyText's share, which is now
// one full copy of the body into a string (invocation.go:185). It should scale
// linearly with size, and that copy is what makes a 1MiB callout allocate a
// megabyte before anything is even serialized.
func BenchmarkBuildRequestInvocationBody(b *testing.B) {
	for _, size := range benchBodySizes {
		b.Run(benchSizeName(size), func(b *testing.B) {
			cfg := benchConfig(b, Config{Request: &PhaseConfig{Body: true}})
			st := benchStream(8)
			id := testUnitID()
			body := benchBody(size)
			if _, err := buildRequestInvocation(cfg, id, st, body); err != nil {
				b.Fatalf("buildRequestInvocation: %v", err)
			}
			b.SetBytes(int64(len(body.Bytes)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchInv, _ = buildRequestInvocation(cfg, id, st, body)
			}
		})
	}
}

// BenchmarkBuildResponseInvocation prices the response direction, which reads
// the upstream's headers under all mode and drops the credentials the upstream
// minted. It carries no request headers or request body by contract
// (invocation.go:54), so it is the cheaper of the two builders at equal size.
func BenchmarkBuildResponseInvocation(b *testing.B) {
	for _, size := range append([]int{0}, benchBodySizes...) {
		b.Run(benchSizeName(size), func(b *testing.B) {
			collect := size > 0
			cfg := benchConfig(b, Config{Response: &PhaseConfig{
				Headers: HeadersConfig{Mode: HeaderModeAll},
				Body:    collect,
			}})
			st := benchStream(8)
			id := testUnitID()
			var body filter.Body
			if collect {
				body = benchBody(size)
				b.SetBytes(int64(len(body.Bytes)))
			}
			if _, err := buildResponseInvocation(cfg, id, st, body); err != nil {
				b.Fatalf("buildResponseInvocation: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchInv, _ = buildResponseInvocation(cfg, id, st, body)
			}
		})
	}
}

// BenchmarkInvocationValidate prices the check the filter runs before spending a
// round trip (filter.go:142). With a body it is one full UTF-8 scan, and it is
// the only one left: this is the sole enforcement point for the contract, so
// whatever it costs is what the invariant costs.
func BenchmarkInvocationValidate(b *testing.B) {
	for _, size := range append([]int{0}, benchBodySizes...) {
		b.Run(benchSizeName(size), func(b *testing.B) {
			collect := size > 0
			cfg := benchConfig(b, Config{Request: &PhaseConfig{
				Headers: HeadersConfig{Mode: HeaderModeAll},
				Body:    collect,
			}})
			var body filter.Body
			if collect {
				body = benchBody(size)
				b.SetBytes(int64(len(body.Bytes)))
			}
			inv, err := buildRequestInvocation(cfg, testUnitID(), benchStream(8), body)
			if err != nil {
				b.Fatalf("buildRequestInvocation: %v", err)
			}
			if err := inv.Validate(); err != nil {
				b.Fatalf("Validate: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchErr = inv.Validate()
			}
		})
	}
}

// BenchmarkMarshalInvocation prices the serialization HTTPClient.Call performs
// (client.go:101). This is the third pass over the body: json.Marshal escapes it
// into a fresh buffer, so the payload is an independent copy on top of the
// string bodyText already made.
func BenchmarkMarshalInvocation(b *testing.B) {
	for _, size := range append([]int{0}, benchBodySizes...) {
		b.Run(benchSizeName(size), func(b *testing.B) {
			collect := size > 0
			cfg := benchConfig(b, Config{Request: &PhaseConfig{
				Headers: HeadersConfig{Mode: HeaderModeAll},
				Body:    collect,
			}})
			var body filter.Body
			if collect {
				body = benchBody(size)
				b.SetBytes(int64(len(body.Bytes)))
			}
			inv, err := buildRequestInvocation(cfg, testUnitID(), benchStream(8), body)
			if err != nil {
				b.Fatalf("buildRequestInvocation: %v", err)
			}
			if _, err := json.Marshal(inv); err != nil {
				b.Fatalf("Marshal: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				payload, _ := json.Marshal(inv)
				benchPayload = payload
			}
		})
	}
}

// BenchmarkDecisionValidate prices the answer-side check, which runs per callout
// against the invocation it claims to answer (filter.go:157). The mutation count
// axis matters because every header mutation is name-validated here and then
// name-validated again in headerOps (apply.go:114).
func BenchmarkDecisionValidate(b *testing.B) {
	cfg := benchConfig(b, Config{Request: &PhaseConfig{Headers: HeadersConfig{Mode: HeaderModeAll}}})
	inv, err := buildRequestInvocation(cfg, testUnitID(), benchStream(8), filter.Body{})
	if err != nil {
		b.Fatalf("buildRequestInvocation: %v", err)
	}
	for _, mutations := range []int{0, 1, 8} {
		b.Run("mutations="+strconv.Itoa(mutations), func(b *testing.B) {
			d := benchContinueDecision(PhaseRequest, mutations)
			if err := d.Validate(inv); err != nil {
				b.Fatalf("Validate: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchErr = d.Validate(inv)
			}
		})
	}
	b.Run("respond", func(b *testing.B) {
		status := 403
		body := "blocked by policy"
		d := Decision{
			Version:   ProtocolVersion,
			Phase:     PhaseRequest,
			RequestID: benchRequestID,
			Action:    actionPtr(ActionRespond),
			Reason:    "callout denied the request",
			Response:  &ResponseMutation{StatusCode: &status, Body: &body},
		}
		if err := d.Validate(inv); err != nil {
			b.Fatalf("Validate: %v", err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchErr = d.Validate(inv)
		}
	})
}

// BenchmarkDecisionAction prices the translation into an engine action, whose
// cost is headerOps re-validating and lower-casing every mutation name
// (apply.go:104).
func BenchmarkDecisionAction(b *testing.B) {
	for _, mutations := range []int{0, 1, 8} {
		b.Run("mutations="+strconv.Itoa(mutations), func(b *testing.B) {
			d := benchContinueDecision(PhaseRequest, mutations)
			if _, err := decisionAction(PhaseRequest, d); err != nil {
				b.Fatalf("decisionAction: %v", err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchAction, _ = decisionAction(PhaseRequest, d)
			}
		})
	}
}

// BenchmarkCalloutCPUPath is the composite: everything one callout costs EPE
// from the filter entry point to the returned action, with only the socket
// removed. It is the number to quote for "what does enabling httpcallout cost
// per request".
//
// The serialize arm routes through the same json.Marshal/json.Unmarshal pair
// HTTPClient.Call uses, so it includes serialization; the stub arm omits it and
// the difference is what the wire format costs. Body sizes run in the serialize
// arm only, since that is where the body's three passes all appear.
//
// The filter is built once rather than per iteration. The engine does build one
// per direction per request, but Filter holds no phase state (filter.go:26), so
// hoisting it only excludes a single small allocation.
func BenchmarkCalloutCPUPath(b *testing.B) {
	ctx := context.Background()

	b.Run("headers/stub", func(b *testing.B) {
		benchHeadersPath(b, ctx, newBenchClient(b, PhaseRequest, true, false))
	})
	b.Run("headers/serialize", func(b *testing.B) {
		benchHeadersPath(b, ctx, newBenchClient(b, PhaseRequest, true, true))
	})

	for _, size := range benchBodySizes {
		b.Run("body="+benchSizeName(size)+"/serialize", func(b *testing.B) {
			client := newBenchClient(b, PhaseRequest, true, true)
			cfg := Config{Request: &PhaseConfig{
				Headers: HeadersConfig{Mode: HeaderModeAll},
				Body:    true,
			}}
			f := benchFilter(b, cfg, client)
			st := benchStream(8)
			body := benchBody(size)
			if _, err := f.OnRequestBody(ctx, st, body); err != nil {
				b.Fatalf("OnRequestBody: %v", err)
			}
			b.SetBytes(int64(len(body.Bytes)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchAction, _ = f.OnRequestBody(ctx, st, body)
			}
		})
	}
}

// benchHeadersPath runs the body-less request callout, which dispatches from the
// headers phase (filter.go:85) and buffers nothing.
func benchHeadersPath(b *testing.B, ctx context.Context, client Client) {
	b.Helper()
	cfg := Config{Request: &PhaseConfig{Headers: HeadersConfig{Mode: HeaderModeAll}}}
	f := benchFilter(b, cfg, client)
	st := benchStream(8)
	if _, err := f.OnRequestHeaders(ctx, st); err != nil {
		b.Fatalf("OnRequestHeaders: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchAction, _ = f.OnRequestHeaders(ctx, st)
	}
}

// benchContinueDecision builds a continue decision carrying n header mutations,
// each with a distinct name so headerOps cannot benefit from repetition.
func benchContinueDecision(phase Phase, n int) Decision {
	d := Decision{
		Version:   ProtocolVersion,
		Phase:     phase,
		RequestID: benchRequestID,
		Action:    actionPtr(ActionContinue),
	}
	if n == 0 {
		return d
	}
	headers := make([]HeaderMutation, 0, n)
	for i := 0; i < n; i++ {
		value := "verdict-" + strconv.Itoa(i)
		headers = append(headers, HeaderMutation{
			Operation: HeaderSet,
			Name:      "x-callout-" + strconv.Itoa(i),
			Value:     &value,
		})
	}
	if phase == PhaseRequest {
		d.Request = &RequestMutation{Headers: headers}
	} else {
		d.Response = &ResponseMutation{Headers: headers}
	}
	return d
}

// benchSizeName labels a body-size sub-benchmark, keeping the units in the name
// so benchstat output stays readable.
func benchSizeName(n int) string {
	switch {
	case n == 0:
		return "nobody"
	case n >= 1<<20:
		return strconv.Itoa(n>>20) + "MiB"
	case n >= 1<<10:
		return strconv.Itoa(n>>10) + "KiB"
	default:
		return strconv.Itoa(n) + "B"
	}
}
