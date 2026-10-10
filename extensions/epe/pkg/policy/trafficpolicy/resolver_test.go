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

package trafficpolicy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	"github.com/openkruise/agentio/pkg/dns"
	"github.com/openkruise/agentio/pkg/model"

	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
)

type fakeStore struct {
	types     []store.Type
	resources map[store.Key]store.Resource
	changed   chan struct{}
	ready     bool
	err       error
	lookups   int
	fetch     func(store.Key)
}

func (s *fakeStore) Types() []store.Type { return s.types }

func (s *fakeStore) Status() store.Status {
	if s.changed == nil {
		s.changed = make(chan struct{})
	}
	return store.Status{Ready: s.ready, Changed: s.changed}
}

func (s *fakeStore) notify() {
	if s.changed != nil {
		close(s.changed)
	}
	s.changed = make(chan struct{})
}

func (s *fakeStore) Read() store.Batch {
	batch := store.Batch{Status: s.Status(), Snapshots: map[store.Type]store.TypeSnapshot{}}
	for _, typ := range s.types {
		resources, err := s.List(typ)
		batch.Snapshots[typ] = store.NewDefaultSnapshot(resources, err)
	}
	return batch
}

func testAggregate(stores ...store.Store) *store.Aggregate {
	a := store.NewAggregate(stores...)
	RegisterQueries(a)
	return a
}

func (s *fakeStore) Get(key store.Key) (*store.Resource, error) {
	if s.err != nil {
		return nil, s.err
	}
	r, ok := s.resources[key]
	if !ok {
		return nil, nil
	}
	return &r, nil
}

func (s *fakeStore) List(typ store.Type) ([]store.Resource, error) {
	s.lookups++
	if s.err != nil {
		return nil, s.err
	}
	var result []store.Resource
	for key, r := range s.resources {
		if key.Type == typ {
			result = append(result, r)
		}
	}
	return result, nil
}

func (s *fakeStore) Fetch(_ context.Context, key store.Key) (*store.Resource, error) {
	if s.fetch != nil {
		s.fetch(key)
	}
	return s.Get(key)
}

func (s *fakeStore) put(typ store.Type, name string, value any) {
	key := store.Key{Type: typ, Name: name}
	s.resources[key] = store.Resource{Key: key, Value: value}
	s.notify()
}

func (s *fakeStore) bind(names ...string) {
	key := store.Key{Type: store.Workload, Name: "uid"}
	w := proto.Clone(s.resources[key].Value.(*workload.Workload)).(*workload.Workload)
	ref, err := anypb.New(&ext.PolicyReference{TypeUrl: model.TrafficPolicyType, ResourceNames: names})
	if err != nil {
		panic(err)
	}
	w.Extensions = []*workload.Extension{{Name: "traffic-policy-reference", Config: ref}}
	s.put(store.Workload, "uid", w)
}

func testStore() *fakeStore {
	s := &fakeStore{
		types:     []store.Type{store.Workload, store.TrafficPolicy},
		resources: map[store.Key]store.Resource{},
		ready:     true,
	}
	s.put(store.Workload, "uid", &workload.Workload{Name: "pod", Namespace: "ns", Addresses: [][]byte{{192, 0, 2, 1}}})
	s.bind("allow")
	s.put(
		store.TrafficPolicy,
		"allow",
		&sec.TrafficPolicy{
			Egress: &sec.TrafficPolicy_RuleSet{
				Rules: []*sec.TrafficPolicy_Rule{
					{
						Match: &sec.TrafficPolicy_Match{
							DestinationIps: []*sec.TrafficPolicy_Address{address("203.0.113.0/24")},
						},
					},
				},
			},
		},
	)
	return s
}

func TestResolverCacheUpdates(t *testing.T) {
	f := testStore()
	source := testAggregate(f)
	s := &resolver{source: source}
	pod := inputs.Pod{Namespace: "ns", Name: "pod", IP: "192.0.2.1"}
	target := netip.MustParseAddrPort("203.0.113.7:443")
	cfg, err := s.config(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Evaluate(target).Action != egressauthz.Allow {
		t.Fatal("not allowed")
	}
	if _, err := s.config(t.Context(), pod); err != nil {
		t.Fatal("published index not used", err)
	}
	f.put(store.TrafficPolicy, "allow", &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}})
	source.Refresh()
	updated, err := s.config(t.Context(), pod)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Evaluate(target).Action != egressauthz.Deny {
		t.Fatal("policy update did not revoke")
	}
	if cfg.Evaluate(target).Action != egressauthz.Allow {
		t.Fatal("in-flight config mutated")
	}
	f.ready = false
	f.notify()
	source.Refresh()
	if _, err := s.config(t.Context(), pod); err == nil {
		t.Fatal("unsynchronized resources accepted")
	}
	f.ready = true
	f.notify()
	source.Refresh()
	f.err = fmt.Errorf("missing resource")
	f.notify()
	source.Refresh()
	if _, err := s.config(t.Context(), pod); err == nil {
		t.Fatal("lookup error ignored")
	}
}

func TestAuthorizerUsesWorkloadBinding(t *testing.T) {
	f := testStore()
	f.bind()
	authorize := NewAuthorizer(testAggregate(f), dns.NewClient(nil, 0))
	stream := &filter.Stream{Request: httpreq.HTTPRequest{Host: "203.0.113.7", Port: 443}}
	stream.Peer.Pod.Namespace, stream.Peer.Pod.Name = "ns", "pod"
	target, reply, err := authorize(t.Context(), stream)
	if err != nil || reply != nil || target == nil || target.Address.String() != "203.0.113.7:443" {
		t.Fatalf("empty binding should allow: target=%v reply=%v err=%v", target, reply, err)
	}
}

func TestCrossStorePoliciesAndFetchRebind(t *testing.T) {
	workloads := testStore()
	workloads.types = []store.Type{store.Workload}
	policies := testStore()
	policies.types = []store.Type{store.TrafficPolicy}
	source := testAggregate(workloads, policies)
	pod := inputs.Pod{Namespace: "ns", Name: "pod"}
	result, err := lookup(t.Context(), source, pod)
	if err != nil || len(result.TrafficPolicies) != 1 {
		t.Fatalf("cross-store lookup: %+v %v", result, err)
	}
	workloads.bind("missing")
	source.Refresh()
	if _, err := lookup(t.Context(), source, pod); err == nil {
		t.Fatal("missing policy silently skipped")
	}
	policies.fetch = func(key store.Key) {
		policies.put(key.Type, key.Name, &sec.TrafficPolicy{})
		workloads.bind("allow", "missing")
	}
	result, err = lookup(t.Context(), source, pod)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.TrafficPolicies) != 2 || result.TrafficPolicies[0].Name != "allow" ||
		result.TrafficPolicies[1].Name != "missing" {
		t.Fatalf("binding not reloaded after fetch: %+v", result)
	}
	w := proto.Clone(workloads.resources[store.Key{Type: store.Workload, Name: "uid"}].Value.(*workload.Workload)).(*workload.Workload)
	w.Extensions = nil
	workloads.put(store.Workload, "uid", w)
	source.Refresh()
	if _, err := lookup(t.Context(), source, pod); err == nil {
		t.Fatal("missing binding treated as empty")
	}
}

func TestResourcesForIndexesPrecedenceAndDependencyReuse(t *testing.T) {
	high, low := testStore(), testStore()
	high.bind()
	source := testAggregate(high, low)
	subject := store.Subject{Namespace: "ns", Name: "pod", IP: "192.0.2.1"}
	resources, err := source.ResourcesFor(store.TrafficPolicy, subject)
	if err != nil || len(resources) != 0 {
		t.Fatal("shadowed source matched", resources, err)
	}
	resources, err = source.ResourcesFor(store.Workload, subject)
	if err != nil || len(resources) != 1 {
		t.Fatal(resources, err)
	}
	high.bind("allow")
	source.Refresh()
	before := source.Snapshot()
	previous := before.Query(store.TrafficPolicy).(*queryIndex).workloads[subjectKey{"ns", "pod"}]
	high.put(store.TrafficPolicy, "unrelated", &sec.TrafficPolicy{})
	source.Refresh()
	current := source.Snapshot().Query(store.TrafficPolicy).(*queryIndex).workloads[subjectKey{"ns", "pod"}]
	if current != previous {
		t.Fatal("unrelated update invalidated compiled configuration")
	}
	high.put(store.TrafficPolicy, "allow", &sec.TrafficPolicy{Egress: &sec.TrafficPolicy_RuleSet{}})
	source.Refresh()
	current = source.Snapshot().Query(store.TrafficPolicy).(*queryIndex).workloads[subjectKey{"ns", "pod"}]
	if current == previous {
		t.Fatal("dependency update reused stale configuration")
	}
	target := netip.MustParseAddrPort("203.0.113.7:443")
	if current.compiled.config.Evaluate(target).Action != egressauthz.Deny ||
		previous.compiled.config.Evaluate(target).Action != egressauthz.Allow {
		t.Fatal("immutable configuration boundary broken")
	}
	delete(high.resources, store.Key{Type: store.TrafficPolicy, Name: "allow"})
	high.notify()
	// Remove the lower-priority copy too, to exercise referenced-resource deletion.
	delete(low.resources, store.Key{Type: store.TrafficPolicy, Name: "allow"})
	low.notify()
	source.Refresh()
	if _, err := source.ResourcesFor(store.TrafficPolicy, subject); err == nil {
		t.Fatal("removed dependency accepted")
	}
}

func TestWorkloadConfigDoesNotDependOnSourceIP(t *testing.T) {
	for _, addresses := range [][][]byte{nil, {{192, 0, 2, 1}}, {{192, 0, 2, 1}, netip.MustParseAddr("2001:db8::1").AsSlice()}} {
		f := testStore()
		w := proto.Clone(f.resources[store.Key{Type: store.Workload, Name: "uid"}].Value.(*workload.Workload)).(*workload.Workload)
		w.Addresses = addresses
		f.put(store.Workload, "uid", w)
		source := testAggregate(f)
		resolver := &resolver{source: source}
		expected, err := resolver.config(t.Context(), inputs.Pod{Namespace: "ns", Name: "pod"})
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range []string{"", "192.0.2.1", "2001:db8::1", "198.51.100.9", "not-an-ip"} {
			got, err := resolver.config(t.Context(), inputs.Pod{Namespace: "ns", Name: "pod", IP: ip})
			if err != nil {
				t.Fatalf("source IP %q affected lookup: %v", ip, err)
			}
			if &got.Policies[0] != &expected.Policies[0] ||
				got.Evaluate(netip.MustParseAddrPort("203.0.113.7:443")).Action != egressauthz.Allow {
				t.Fatalf("source IP %q did not reuse the Workload's compiled config", ip)
			}
		}
	}
}

func TestLookupFetchesAllMissingPolicies(t *testing.T) {
	f := testStore()
	names := make([]string, 9)
	for i := range names {
		names[i] = fmt.Sprintf("missing-%d", i)
	}
	f.bind(names...)
	calls := 0
	f.fetch = func(key store.Key) {
		calls++
		f.put(key.Type, key.Name, &sec.TrafficPolicy{})
	}
	result, err := lookup(t.Context(), testAggregate(f), inputs.Pod{Namespace: "ns", Name: "pod"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.TrafficPolicies) != len(names) || calls != len(names) {
		t.Fatalf("policies=%d fetches=%d, want %d", len(result.TrafficPolicies), calls, len(names))
	}
	for i, policy := range result.TrafficPolicies {
		if policy.Name != names[i] {
			t.Fatalf("binding order changed: %v", result.TrafficPolicies)
		}
	}
}

func TestLookupStopsFetchingWhenCanceled(t *testing.T) {
	f := testStore()
	f.bind("first", "second")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	f.fetch = func(key store.Key) {
		calls++
		f.put(key.Type, key.Name, &sec.TrafficPolicy{})
		cancel()
	}
	_, err := lookup(ctx, testAggregate(f), inputs.Pod{Namespace: "ns", Name: "pod"})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("error=%v fetches=%d, want cancellation after first fetch", err, calls)
	}
}

// overrideFetch leaves the published snapshot unchanged to exercise a Fetch
// result racing with publication or deletion.
type overrideFetch struct {
	Resources
	fetch func(context.Context, store.Key) (*store.Resource, error)
}

func (s overrideFetch) Fetch(ctx context.Context, key store.Key) (*store.Resource, error) {
	return s.fetch(ctx, key)
}

func TestLookupPollTermination(t *testing.T) {
	fetchErr := errors.New("fetch failed")
	for _, tc := range []struct {
		name     string
		resource *store.Resource
		fetchErr error
		want     error
	}{
		{name: "not found"},
		{name: "fetch failure", fetchErr: fetchErr, want: fetchErr},
		{name: "unchanged snapshot", resource: &store.Resource{Key: store.Key{Type: store.TrafficPolicy, Name: "missing"}}, want: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := testStore()
			f.bind("missing")
			calls := 0
			source := overrideFetch{
				Resources: testAggregate(f),
				fetch: func(context.Context, store.Key) (*store.Resource, error) {
					calls++
					return tc.resource, tc.fetchErr
				},
			}
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			_, err := lookup(ctx, source, inputs.Pod{Namespace: "ns", Name: "pod"})
			if tc.want == nil {
				if missing, ok := errors.AsType[*store.MissingResource](err); !ok || missing.Key.Name != "missing" {
					t.Fatalf("want missing resource, got %v", err)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			if tc.resource == nil && calls != 1 {
				t.Fatalf("terminal Fetch retried %d times", calls)
			}
			// Leave margin for timer scheduling while detecting the former busy loop.
			if calls > 10 {
				t.Fatalf("polling spun without waiting: %d fetches in 50ms", calls)
			}
		})
	}
}
