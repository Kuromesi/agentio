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

package policy

import (
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestBindingCompareScopeTransitionAtomic(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	opts := []krt.CollectionOption{krt.WithStop(stop)}
	p, err := NewPolicyAttachment(
		PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: "retained", Target: AttachmentTarget{Global: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	policies := krt.NewMutableCollection(nil, []PolicyAttachment{p}, opts...)
	w := model.Workload{UID: "client", Namespace: "demo", Labels: map[string]string{"app": "new"}}
	bindings := NewWorkloadPolicyBindingsCollection(
		krt.NewStaticCollection(nil, []model.Workload{w}, opts...),
		policies.AsCollection(),
		krt.NewOptionsBuilder(stop, "test", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("sync failed")
	}
	events := make(chan krt.Event[Bindings], 10)
	reg := bindings.RegisterBatch(func(es []krt.Event[Bindings]) {
		for _, e := range es {
			events <- e
		}
	}, false)
	defer reg.UnregisterHandler()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p, err = NewPolicyAttachment(
		PolicyAttachment{
			Kind: PolicyKindTrafficPolicy,
			Name: "retained",
			Target: AttachmentTarget{
				Namespaces: []string{"demo"},
				Selector:   metav1.LabelSelector{MatchLabels: map[string]string{"app": "new"}},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	p.selector = bindingGateSelector{Selector: p.selector, once: new(sync.Once), entered: entered, release: release}
	policies.ConditionalUpdateObject(p)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("matching did not start")
	}
	select {
	case e := <-events:
		t.Fatalf("retained policy changed while scope match pending: %+v", e.Latest())
	case <-time.After(200 * time.Millisecond):
	}
	if got := bindings.GetKey(w.UID).
		PolicyNames(PolicyKindTrafficPolicy); !reflect.DeepEqual(
		got,
		[]string{"retained"},
	) {
		t.Fatalf("lost binding: %v", got)
	}
	once.Do(func() { close(release) })
	select {
	case e := <-events:
		t.Fatalf("scope move should preserve binding: %+v", e.Latest())
	case <-time.After(200 * time.Millisecond):
	}
}

func TestBindingCompareRandomized(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	opts := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewMutableCollection[model.Workload](nil, nil, opts...)
	policies := krt.NewMutableCollection[PolicyAttachment](nil, nil, opts...)
	bindings := NewWorkloadPolicyBindingsCollection(
		workloads.AsCollection(),
		policies.AsCollection(),
		krt.NewOptionsBuilder(stop, "test", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("sync failed")
	}
	for round := range 100 {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(round * 2)))
			for range 8 {
				i := rng.Intn(20)
				key := fmt.Sprintf("w-%d", i)
				if rng.Intn(5) == 0 {
					workloads.DeleteObject(key)
				} else {
					workloads.ConditionalUpdateObject(
						model.Workload{
							UID:       key,
							Namespace: fmt.Sprintf("ns-%d", rng.Intn(3)),
							Labels:    map[string]string{"app": fmt.Sprint(rng.Intn(4))},
							Ready:     rng.Intn(2) == 0,
						},
					)
				}
			}
		}()
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(round*2 + 1)))
			for range 8 {
				i := rng.Intn(30)
				name := fmt.Sprintf("p-%d", i)
				kind := []PolicyKind{PolicyKindTrafficPolicy, PolicyKindSNIPolicy, PolicyKindEgressPolicy}[i%3]
				key := (model.PolicyRef{Kind: kind, Name: name}).ResourceName()
				if rng.Intn(5) == 0 {
					policies.DeleteObject(key)
				} else {
					target := AttachmentTarget{Global: rng.Intn(3) == 0}
					if !target.Global {
						target.Namespaces = []string{fmt.Sprintf("ns-%d", rng.Intn(3))}
					}
					if rng.Intn(3) != 0 {
						target.Selector = metav1.LabelSelector{
							MatchLabels: map[string]string{"app": fmt.Sprint(rng.Intn(4))},
						}
					}
					p, err := NewPolicyAttachment(
						PolicyAttachment{Kind: kind, Name: name, Priority: int32(rng.Intn(5)), Target: target},
					)
					if err != nil {
						panic(err)
					}
					policies.ConditionalUpdateObject(p)
				}
			}
		}()
		wg.Wait()
		expected := map[string]Bindings{}
		for _, w := range workloads.List() {
			matches := map[string]PolicyAttachment{}
			for _, p := range policies.List() {
				if p.Selects(w) {
					matches[p.ResourceName()] = p
				}
			}
			expected[w.UID] = *bindingsFromMatches(w.UID, matches)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			actual := bindings.List()
			ok := len(actual) == len(expected)
			for _, b := range actual {
				want, exists := expected[b.TargetUID]
				if !exists || !b.Equals(want) {
					ok = false
				}
			}
			if ok {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("round %d did not converge: got %v want %v", round, actual, expected)
			}
			time.Sleep(time.Millisecond)
		}
	}
}

func TestBindingCompareInitialSync(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	opts := []krt.CollectionOption{krt.WithStop(stop)}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p, err := NewPolicyAttachment(
		PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: "initial", Target: AttachmentTarget{Global: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	p.selector = bindingGateSelector{Selector: p.selector, once: new(sync.Once), entered: entered, release: release}
	policies := krt.NewMutableCollection(nil, []PolicyAttachment{p}, opts...)
	workloads := krt.NewStaticCollection(
		nil,
		[]model.Workload{{UID: "client", Namespace: "demo", Labels: map[string]string{"app": "new"}}},
		opts...)
	bindings := NewWorkloadPolicyBindingsCollection(
		workloads,
		policies.AsCollection(),
		krt.NewOptionsBuilder(stop, "test", nil),
	)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("initial computation did not start")
	}
	if bindings.HasSynced() {
		t.Fatal("reported ready before matching completed")
	}
	once.Do(func() { close(release) })
	timeout := make(chan struct{})
	timer := time.AfterFunc(5*time.Second, func() { close(timeout) })
	defer timer.Stop()
	if !bindings.WaitUntilSynced(timeout) {
		t.Fatal("initial computation did not complete")
	}
	if got := bindings.GetKey(
		"client",
	); got == nil ||
		!reflect.DeepEqual(got.PolicyNames(PolicyKindTrafficPolicy), []string{"initial"}) {
		t.Fatalf("incomplete initial result: %v", got)
	}
}
