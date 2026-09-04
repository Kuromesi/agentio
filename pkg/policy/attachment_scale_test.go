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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

// One Sandbox commonly owns one policy; this benchmark prevents an exact
// policy lifecycle event from restoring namespace-wide binding recomputation.
func BenchmarkSandboxPolicyBindingsExactPolicyChurn10000(b *testing.B) {
	const (
		sandboxCount = 10_000
		policyCount  = 100
		targetUID    = "sandbox-42"
	)
	stop := make(chan struct{})
	b.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	subjects := make([]SandboxSubject, sandboxCount)
	for index := range subjects {
		subjects[index] = SandboxSubject{
			SandboxUID: fmt.Sprintf("sandbox-%d", index),
			Namespace:  "demo",
			Labels:     map[string]string{"app": "sandbox"},
		}
	}
	basePolicies := make([]PolicyAttachment, policyCount)
	for index := range basePolicies {
		attachment, err := NewPolicyAttachment(PolicyAttachment{
			Kind: PolicyKindAuthorization,
			Name: fmt.Sprintf("demo/policy-%d", index),
			Target: AttachmentTarget{
				Namespaces: []string{"demo"},
				Selector:   metav1.LabelSelector{MatchLabels: map[string]string{"app": "sandbox"}},
			},
		})
		if err != nil {
			b.Fatalf("new base policy %d: %v", index, err)
		}
		basePolicies[index] = attachment
	}
	attachments := krt.NewStaticCollection(nil, basePolicies, options...)
	bindings := NewSandboxPolicyBindingsCollection(
		krt.NewStaticCollection[model.Sandbox](nil, nil, options...),
		krt.NewStaticCollection(nil, subjects, options...),
		attachments,
		krt.NewOptionsBuilder(stop, "benchmark", nil),
	)
	if !bindings.WaitUntilSynced(stop) {
		b.Fatal("Sandbox policy bindings did not sync")
	}
	events := make(chan krt.Event[SandboxPolicyBindings], 1)
	registration := bindings.RegisterBatch(func(batch []krt.Event[SandboxPolicyBindings]) {
		for _, event := range batch {
			events <- event
		}
	}, false)
	b.Cleanup(registration.UnregisterHandler)
	exact, err := NewPolicyAttachment(PolicyAttachment{
		Kind: PolicyKindAuthorization,
		Name: "demo/exact-egress",
		Target: AttachmentTarget{
			SandboxUID: targetUID,
			Selector:   metav1.LabelSelector{MatchLabels: map[string]string{"app": "sandbox"}},
		},
	})
	if err != nil {
		b.Fatalf("new exact policy: %v", err)
	}

	startRecomputes := bindingRecomputeTotal(b, bindings)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := range b.N {
		if iteration%2 == 0 {
			attachments.ConditionalUpdateObject(exact)
		} else {
			attachments.DeleteObject(exact.ResourceName())
		}
		if event := awaitBindingEvent(b, events); event.Latest().SandboxUID != targetUID {
			b.Fatalf("binding event = %+v, want %s", event.Latest(), targetUID)
		}
	}
	b.StopTimer()
	recomputes := bindingRecomputeTotal(b, bindings) - startRecomputes
	b.ReportMetric(float64(recomputes)/float64(b.N), "binding-recomputes/op")
}
