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

package agentio

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	"istio.io/istio/pkg/test"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPolicyAttachmentEqualityTracksOnlyBindingFields(t *testing.T) {
	policy := sniBindablePolicy("ns", "policy", 1, map[string]string{"app": "agent"})
	attachment := policyAttachmentFromBindablePolicy(policy)
	if attachment == nil {
		t.Fatal("expected a policy attachment")
	}

	rulesOnly := policy
	rulesOnly.Resource = &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{
		sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "changed.example.com"),
	}}
	if other := policyAttachmentFromBindablePolicy(rulesOnly); other == nil || !attachment.Equals(*other) {
		t.Fatal("resource-only policy changes must not change the attachment")
	}

	priority := policy
	priority.Priority++
	if attachment.Equals(*policyAttachmentFromBindablePolicy(priority)) {
		t.Fatal("priority changes must change the attachment")
	}

	creationTime := policy
	creationTime.CreationTime = time.Unix(1, 0)
	if attachment.Equals(*policyAttachmentFromBindablePolicy(creationTime)) {
		t.Fatal("source creation-time changes must change the attachment")
	}

	selector := policy
	selector.Selector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "other"}}
	selector.selector = nil
	if attachment.Equals(*policyAttachmentFromBindablePolicy(selector)) {
		t.Fatal("selector changes must change the attachment")
	}
}

func TestPolicyAttachmentCollectionSuppressesResourceOnlyUpdates(t *testing.T) {
	opts := krttest.Options(t)
	policy := sniBindablePolicy("ns", "policy", 1, map[string]string{"app": "agent"})
	source := krt.NewStaticCollection(nil, []BindablePolicy{policy}, opts.WithName("BindablePolicySource")...)
	attachments := newPolicyAttachmentsCollection(source, opts)
	if !attachments.WaitUntilSynced(test.NewStop(t)) {
		t.Fatal("policy attachments did not sync")
	}

	events := make(chan krt.Event[PolicyAttachment], 2)
	registration := attachments.RegisterBatch(func(batch []krt.Event[PolicyAttachment]) {
		for _, event := range batch {
			events <- event
		}
	}, false)
	t.Cleanup(registration.UnregisterHandler)

	// The source changes and emits an update, but the projected attachment is
	// equal, so KRT must stop the event before it reaches binding dependents.
	rulesOnly := policy
	rulesOnly.Resource = &extensions.SniTrafficPolicy{Rules: []*extensions.SniRule{
		sniRule(extensions.SniAction_SNI_ACTION_TLS_TERMINATION, "changed.example.com"),
	}}
	source.Reset([]BindablePolicy{rulesOnly})

	// A binding-relevant update is the barrier proving the preceding rules-only
	// update was suppressed: event ordering is preserved for each handler.
	priority := rulesOnly
	priority.Priority++
	source.Reset([]BindablePolicy{priority})

	select {
	case event := <-events:
		if event.Old == nil || event.New == nil {
			t.Fatalf("expected an attachment update, got %+v", event)
		}
		if event.Old.Priority != policy.Priority || event.New.Priority != priority.Priority {
			t.Fatalf("unexpected first attachment event: old priority %d, new priority %d",
				event.Old.Priority, event.New.Priority)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the binding-relevant attachment update")
	}
}

func TestPolicyAttachmentCollectionDebouncesBindingRecomputes(t *testing.T) {
	const (
		debounce    = 200 * time.Millisecond
		maxDebounce = 2 * time.Second
		policyCount = 5
	)
	oldDebounce, oldMaxDebounce := features.KrtEventDistributeDebounce, features.KrtEventDistributeDebounceMax
	features.KrtEventDistributeDebounce = debounce
	features.KrtEventDistributeDebounceMax = maxDebounce
	t.Cleanup(func() {
		features.KrtEventDistributeDebounce = oldDebounce
		features.KrtEventDistributeDebounceMax = oldMaxDebounce
	})

	opts := krttest.Options(t)
	initial := sniBindablePolicy("bench", "policy-0", 1, map[string]string{"app": "agent"})
	policySource := krt.NewStaticCollection(nil, []BindablePolicy{initial}, opts.WithName("BindablePolicySource")...)
	attachments := newPolicyAttachmentsCollection(policySource, opts)
	workloads := krt.NewStaticCollection(nil, []model.WorkloadInfo{
		sniTestWorkload("pod", "bench", map[string]string{"app": "agent"}),
	}, opts.WithName("Workloads")...)
	bindings := newPolicyBindingCollection(workloads, attachments, opts)
	if !bindings.WaitUntilSynced(test.NewStop(t)) {
		t.Fatal("policy bindings did not sync")
	}

	var bindingUpdates atomic.Int64
	registration := bindings.RegisterBatch(func(events []krt.Event[model.PolicyBinding]) {
		bindingUpdates.Add(int64(len(events)))
	}, false)
	t.Cleanup(registration.UnregisterHandler)

	for i := 1; i < policyCount; i++ {
		policySource.UpdateObject(sniBindablePolicy(
			"bench", fmt.Sprintf("policy-%d", i), 1, map[string]string{"app": "agent"},
		))
		// Keep the burst active inside the debounce window while giving an
		// un-debounced collection enough time to fan each event out separately.
		time.Sleep(debounce / 4)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		items := bindings.List()
		if len(items) == 1 {
			refs := items[0].Binding.GetPolicyRefs()[initial.TypeURL]
			if refs != nil && len(refs.ResourceNames) == policyCount {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d policy references", policyCount)
		}
		time.Sleep(10 * time.Millisecond)
	}

	deadline = time.Now().Add(time.Second)
	for bindingUpdates.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := bindingUpdates.Load(); got != 1 {
		t.Fatalf("binding updates = %d, want 1 merged update", got)
	}
}
