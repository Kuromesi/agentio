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
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// This unmatched policy is examined once per binding recomputation, but is
// never changed itself. It detects unnecessary recomputation even when Equals
// suppresses the resulting binding events.
type bindingRecomputeSelector struct {
	labels.Selector
	calls *atomic.Int64
}

func (s bindingRecomputeSelector) Matches(values labels.Labels) bool {
	s.calls.Add(1)
	return s.Selector.Matches(values)
}

func TestPolicyBindingsSelectorDependencyFanout(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(fmt.Sprintf("global=%t", global), func(t *testing.T) {
			const count = 32
			stop := make(chan struct{})
			t.Cleanup(func() { close(stop) })
			options := []krt.CollectionOption{krt.WithStop(stop)}
			var subjects []model.Workload
			for index := range count {
				uid := fmt.Sprintf("subject-%d", index)
				values := map[string]string{"app": uid}
				subjects = append(subjects, model.Workload{UID: uid, Namespace: "demo", Labels: values})
			}
			workloades := krt.NewStaticCollection(nil, subjects, options...)
			makePolicy := func(selector metav1.LabelSelector) PolicyAttachment {
				t.Helper()
				target := AttachmentTarget{Selector: selector, Global: global}
				if !global {
					target.Namespaces = []string{"demo"}
				}
				attachment, err := NewPolicyAttachment(
					PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: "demo/selected", Target: target},
				)
				if err != nil {
					t.Fatal(err)
				}
				return attachment
			}
			selectApp := func(app string) metav1.LabelSelector {
				return metav1.LabelSelector{MatchLabels: map[string]string{"app": app}}
			}
			var recomputes atomic.Int64
			witness := makePolicy(selectApp("unmatched"))
			witness.Name = "demo/witness"
			witness.selector = bindingRecomputeSelector{Selector: witness.selector, calls: &recomputes}
			initial := makePolicy(selectApp("subject-0"))
			attachments := krt.NewStaticCollection(nil, []PolicyAttachment{initial, witness}, options...)
			bindings := NewWorkloadPolicyBindingsCollection(workloades, attachments, krt.NewOptionsBuilder(stop, "test", nil))
			if !bindings.WaitUntilSynced(stop) {
				t.Fatal("bindings did not sync")
			}
			events := make(chan krt.Event[Bindings], count*2)
			registration := bindings.RegisterBatch(func(batch []krt.Event[Bindings]) {
				for _, event := range batch {
					events <- event
				}
			}, false)
			t.Cleanup(registration.UnregisterHandler)
			check := func(eventCount, wantRecomputes int, selected func(int) bool) {
				t.Helper()
				for range eventCount {
					awaitBindingEvent(t, events)
				}
				if got := recomputes.Swap(0); got != int64(wantRecomputes) {
					t.Fatalf("recomputed %d bindings, want %d", got, wantRecomputes)
				}
				for index := range count {
					binding := bindings.GetKey(fmt.Sprintf("subject-%d", index))
					if binding == nil {
						t.Fatalf("subject-%d has no valid binding", index)
					}
					var want []string
					if selected(index) {
						want = []string{initial.Name}
					}
					if got := binding.PolicyNames(PolicyKindTrafficPolicy); !reflect.DeepEqual(got, want) {
						t.Fatalf("subject-%d policies = %v, want %v", index, got, want)
					}
				}
			}
			check(0, count, func(index int) bool { return index == 0 })
			// Both the old and new selector must invalidate their matching subject.
			attachments.ConditionalUpdateObject(
				makePolicy(metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"subject-1"},
				}}}),
			)
			check(2, 2, func(index int) bool { return index == 1 })
			// A primary label update must still detach the policy.
			updated := subjects[1]
			updated.Labels = map[string]string{"app": "disabled"}
			workloades.ConditionalUpdateObject(updated)
			check(1, 1, func(int) bool { return false })
			attachments.ConditionalUpdateObject(makePolicy(selectApp("subject-2")))
			check(1, 1, func(index int) bool { return index == 2 })
			attachments.DeleteObject(initial.ResourceName())
			check(1, 1, func(int) bool { return false })
			// Empty selectors retain namespace-wide/global semantics on recreation.
			attachments.ConditionalUpdateObject(makePolicy(metav1.LabelSelector{}))
			check(count, count, func(int) bool { return true })
		})
	}
}

func TestPolicyBindingsSelectorTargetFanout(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	subjects := make([]model.Workload, 100)
	for index := range subjects {
		subjects[index] = model.Workload{
			UID:       fmt.Sprintf("workload-%d", index),
			Namespace: "demo",
			Labels:    map[string]string{"workload": fmt.Sprintf("workload-%d", index)},
		}
	}
	attachments := krt.NewStaticCollection[PolicyAttachment](nil, nil, options...)
	bindings := NewWorkloadPolicyBindingsCollection(
		krt.NewStaticCollection(nil, subjects, options...),
		attachments,
		krt.NewOptionsBuilder(stop, "test", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("Workload policy bindings did not sync")
	}
	events := make(chan krt.Event[Bindings], 1)
	registration := bindings.RegisterBatch(func(batch []krt.Event[Bindings]) {
		for _, event := range batch {
			events <- event
		}
	}, false)
	t.Cleanup(registration.UnregisterHandler)

	selected, err := NewPolicyAttachment(PolicyAttachment{
		Kind: PolicyKindTrafficPolicy,
		Name: "demo/selected-egress",
		Target: AttachmentTarget{
			Namespaces: []string{"demo"},
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"workload": "workload-42",
			}},
		},
	})
	if err != nil {
		t.Fatalf("new selector attachment: %v", err)
	}
	attachments.ConditionalUpdateObject(selected)
	if event := awaitBindingEvent(t, events); event.Latest().TargetUID != "workload-42" {
		t.Fatalf("added binding event = %+v, want workload-42", event.Latest())
	}

	attachments.DeleteObject(selected.ResourceName())
	if event := awaitBindingEvent(t, events); event.Latest().TargetUID != "workload-42" {
		t.Fatalf("deleted binding event = %+v, want workload-42", event.Latest())
	}
}

func awaitBindingEvent(t testing.TB, events <-chan krt.Event[Bindings]) krt.Event[Bindings] {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Workload binding event")
		return krt.Event[Bindings]{}
	}
}

func TestPolicyBindings(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	builder := krt.NewOptionsBuilder(stop, "test", nil)

	demo := model.Workload{
		UID: "cluster//Pod/demo/client",
	}
	demo.Namespace = "demo"
	demo.Labels = map[string]string{"app": "client", "tier": "trusted"}
	other := model.Workload{
		UID:       "cluster//Pod/other/client",
		Namespace: "other",
		Labels:    map[string]string{"app": "client"},
	}
	attachments := []PolicyAttachment{
		{
			Kind: PolicyKindSNIPolicy,
			Name: "explicit",
			Target: AttachmentTarget{
				Namespaces: []string{"unrelated"},
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindSNIPolicy,
			Name: "global",
			Target: AttachmentTarget{
				Global: true,
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindSNIPolicy,
			Name: "demo",
			Target: AttachmentTarget{
				Namespaces: []string{"demo"},
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindSNIPolicy,
			Name: "selector",
			Target: AttachmentTarget{
				Global: true,
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{"tier": "trusted"},
				},
			},
			Priority: 20,
		},
		{
			Kind: PolicyKindEgressPolicy,
			Name: "egress",
			Target: AttachmentTarget{
				Namespaces: []string{"demo"},
			},
			Priority: 10,
		},
	}
	for index := range attachments {
		normalized, err := NewPolicyAttachment(attachments[index])
		if err != nil {
			t.Fatalf("normalize attachment %q: %v", attachments[index].Name, err)
		}
		attachments[index] = normalized
	}

	workloades := krt.NewStaticCollection(nil, []model.Workload{demo, other}, options...)
	policies := krt.NewStaticCollection(nil, attachments, options...)
	bindings := NewWorkloadPolicyBindingsCollection(workloades, policies, builder)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("workload policy bindings did not sync")
	}

	demoBinding := bindings.GetKey(demo.UID)
	if demoBinding == nil {
		t.Fatal("demo binding is missing")
	}
	if got, want := demoBinding.PolicyNames(PolicyKindEgressPolicy), []string{"egress"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("demo egress names = %v, want %v", got, want)
	}
	if got, want := demoBinding.PolicyNames(
		PolicyKindSNIPolicy,
	), []string{
		"selector",
		"demo",
		"global",
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("demo SNI names = %v, want %v", got, want)
	}
	if got, want := []PolicyKind{
		demoBinding.Groups[0].Kind,
		demoBinding.Groups[1].Kind,
	}, []PolicyKind{
		PolicyKindEgressPolicy,
		PolicyKindSNIPolicy,
	}; !reflect.DeepEqual(
		got,
		want,
	) {
		t.Fatalf("demo group order = %v, want %v", got, want)
	}

	otherBinding := bindings.GetKey(other.UID)
	if otherBinding == nil {
		t.Fatal("other binding is missing")
	}
	if got, want := otherBinding.PolicyNames(PolicyKindSNIPolicy), []string{"global"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("other SNI names = %v, want %v", got, want)
	}
	if got := otherBinding.PolicyNames(PolicyKindEgressPolicy); len(got) != 0 {
		t.Fatalf("other egress names = %v, want none", got)
	}
}
