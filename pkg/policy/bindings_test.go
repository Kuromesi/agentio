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
	"sort"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestPolicyBindingsExactTargetFanout(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	subjects := make([]model.Sandbox, 100)
	for index := range subjects {
		subjects[index] = model.Sandbox{
			UID:       fmt.Sprintf("sandbox-%d", index),
			Namespace: "demo",
			Labels:    map[string]string{"sandbox": fmt.Sprintf("sandbox-%d", index)},
		}
	}
	attachments := krt.NewStaticCollection[PolicyAttachment](nil, nil, options...)
	bindings := NewPolicyBindingsCollection(
		krt.NewStaticCollection[model.Workload](nil, nil, options...),
		krt.NewStaticCollection(nil, subjects, options...),
		attachments,
		krt.NewOptionsBuilder(stop, "test", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("Sandbox policy bindings did not sync")
	}
	events := make(chan krt.Event[Bindings], 1)
	registration := bindings.RegisterBatch(func(batch []krt.Event[Bindings]) {
		for _, event := range batch {
			events <- event
		}
	}, false)
	t.Cleanup(registration.UnregisterHandler)

	exact, err := NewPolicyAttachment(PolicyAttachment{
		Kind: PolicyKindAuthorization,
		Name: "demo/exact-egress",
		Target: AttachmentTarget{
			SandboxUID: "sandbox-42",
			Selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"sandbox": "sandbox-42",
			}},
		},
	})
	if err != nil {
		t.Fatalf("new exact attachment: %v", err)
	}
	attachments.ConditionalUpdateObject(exact)
	if event := awaitBindingEvent(t, events); event.Latest().TargetUID != "sandbox-42" {
		t.Fatalf("added binding event = %+v, want sandbox-42", event.Latest())
	}

	attachments.DeleteObject(exact.ResourceName())
	if event := awaitBindingEvent(t, events); event.Latest().TargetUID != "sandbox-42" {
		t.Fatalf("deleted binding event = %+v, want sandbox-42", event.Latest())
	}
}

func awaitBindingEvent(t testing.TB, events <-chan krt.Event[Bindings]) krt.Event[Bindings] {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Sandbox binding event")
		return krt.Event[Bindings]{}
	}
}

func TestPolicyBindings(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	builder := krt.NewOptionsBuilder(stop, "test", nil)

	demo := model.Sandbox{
		UID: "cluster//Pod/demo/client",
		PolicyRefs: []model.PolicyRef{
			{
				Kind: model.PolicyKindSNIPolicy,
				Name: "explicit",
			},
			{
				Kind: model.PolicyKindSNIPolicy,
				Name: "global",
			},
		},
	}
	demo.Namespace = "demo"
	demo.Labels = map[string]string{"app": "client", "tier": "trusted"}
	other := model.Sandbox{UID: "cluster//Pod/other/client", Namespace: "other", Labels: map[string]string{"app": "client"}}
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

	sandboxes := krt.NewStaticCollection(nil, []model.Sandbox{demo, other}, options...)
	policies := krt.NewStaticCollection(nil, attachments, options...)
	bindings := NewPolicyBindingsCollection(krt.NewStaticCollection[model.Workload](nil, nil, options...), sandboxes, policies, builder)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("sandbox policy bindings did not sync")
	}

	demoBinding := bindings.GetKey(BindingsKey(PolicyTargetSandbox, demo.UID))
	if demoBinding == nil {
		t.Fatal("demo binding is missing")
	}
	if got, want := demoBinding.PolicyNames(PolicyKindEgressPolicy), []string{"egress"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("demo egress names = %v, want %v", got, want)
	}
	if got, want := demoBinding.PolicyNames(PolicyKindSNIPolicy), []string{"explicit", "global", "selector", "demo"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("demo SNI names = %v, want %v", got, want)
	}
	if got, want := []PolicyKind{demoBinding.Groups[0].Kind, demoBinding.Groups[1].Kind}, []PolicyKind{PolicyKindEgressPolicy, PolicyKindSNIPolicy}; !reflect.DeepEqual(got, want) {
		t.Fatalf("demo group order = %v, want %v", got, want)
	}

	otherBinding := bindings.GetKey(BindingsKey(PolicyTargetSandbox, other.UID))
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

func TestPolicyBindingsRejectUnresolvedExplicitReference(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	builder := krt.NewOptionsBuilder(stop, "test", nil)
	uid := "sandbox-a"

	bindings := NewPolicyBindingsCollection(
		krt.NewStaticCollection[model.Workload](nil, nil, options...),
		krt.NewStaticCollection(nil, []model.Sandbox{{
			UID: uid,
			PolicyRefs: []model.PolicyRef{{
				Kind: model.PolicyKindSNIPolicy,
				Name: "demo/missing",
			}},
		}}, options...),
		krt.NewStaticCollection[PolicyAttachment](nil, nil, options...),
		builder,
	)
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("Sandbox policy bindings did not sync")
	}
	binding := bindings.GetKey(BindingsKey(PolicyTargetSandbox, uid))
	if binding == nil || binding.Valid() || len(binding.Unresolved) != 1 {
		t.Fatalf("binding = %+v, want one unresolved reference", binding)
	}
}

func TestPolicyBindingsSeparateWorkloadAndSandboxWithSameUID(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	workloads := krt.NewStaticCollection(nil, []model.Workload{{UID: "same", Namespace: "demo", Labels: map[string]string{"role": "pod"}}}, options...)
	sandboxes := krt.NewStaticCollection(nil, []model.Sandbox{{UID: "same", Namespace: "demo", Labels: map[string]string{"role": "sandbox"}, PolicyRefs: []model.PolicyRef{{Kind: PolicyKindSNIPolicy, Name: "explicit"}}}}, options...)
	var attachments []PolicyAttachment
	for _, source := range []PolicyAttachment{
		{Kind: PolicyKindAuthorization, Name: "legacy", Target: AttachmentTarget{Kind: PolicyTargetWorkload, Global: true}},
		{Kind: PolicyKindAuthorization, Name: "native", Target: AttachmentTarget{Kind: PolicyTargetSandbox, Global: true}},
		{Kind: PolicyKindSNIPolicy, Name: "global", Target: AttachmentTarget{Global: true}},
		{Kind: PolicyKindSNIPolicy, Name: "pod", Target: AttachmentTarget{Namespaces: []string{"demo"}, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "pod"}}}},
		{Kind: PolicyKindSNIPolicy, Name: "sandbox", Target: AttachmentTarget{Namespaces: []string{"demo"}, Selector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "sandbox"}}}},
		{Kind: PolicyKindSNIPolicy, Name: "exact", Target: AttachmentTarget{SandboxUID: "same"}},
		{Kind: PolicyKindSNIPolicy, Name: "explicit", Target: AttachmentTarget{Namespaces: []string{"elsewhere"}}},
	} {
		attachment, err := NewPolicyAttachment(source)
		if err != nil {
			t.Fatal(err)
		}
		attachments = append(attachments, attachment)
	}
	bindings := NewPolicyBindingsCollection(workloads, sandboxes, krt.NewStaticCollection(nil, attachments, options...), krt.NewOptionsBuilder(stop, "test", nil))
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("bindings did not sync")
	}
	for kind, want := range map[TargetKind][]string{
		PolicyTargetWorkload: {"global", "pod"},
		PolicyTargetSandbox:  {"exact", "explicit", "global", "sandbox"},
	} {
		got := bindings.GetKey(BindingsKey(kind, "same"))
		if got == nil || !got.Valid() {
			t.Fatalf("%s bindings = %+v", kind, got)
		}
		wantAuthorization := "legacy"
		if kind == PolicyTargetSandbox {
			wantAuthorization = "native"
		}
		if !reflect.DeepEqual(got.PolicyNames(PolicyKindAuthorization), []string{wantAuthorization}) {
			t.Fatalf("%s authorization payloads mixed: %+v", kind, got)
		}
		names := append([]string(nil), got.PolicyNames(PolicyKindSNIPolicy)...)
		sort.Strings(names)
		if !reflect.DeepEqual(names, want) {
			t.Fatalf("%s policies = %v, want %v", kind, names, want)
		}
	}
	if len(bindings.List()) != 2 {
		t.Fatal("target kinds collided")
	}
}
