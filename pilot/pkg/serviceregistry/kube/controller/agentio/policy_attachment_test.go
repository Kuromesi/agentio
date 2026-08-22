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

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/kube/krt/krttest"
	xdsmodel "istio.io/istio/pkg/model"
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

// TestBindablePolicyCollectionDebouncesPolicyAndBindingBranches asserts the
// debounce sits upstream of the branch split, so a policy burst produces one
// merged batch on both the xDS policy branch and the PolicyBinding branch.
// Debouncing PolicyAttachments instead would only coalesce the latter.
func TestBindablePolicyCollectionDebouncesPolicyAndBindingBranches(t *testing.T) {
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
	newProfile := func(i int) *agentsv1alpha1.SecurityProfile {
		return &agentsv1alpha1.SecurityProfile{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("policy-%d", i), Namespace: "bench"},
			Spec: agentsv1alpha1.SecurityProfileSpec{
				Selector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}},
				Rules: []agentsv1alpha1.SecurityRule{{
					Match: []agentsv1alpha1.RuleMatch{{Domains: []string{fmt.Sprintf("policy-%d.example.com", i)}}},
				}},
			},
		}
	}
	profiles := krt.NewStaticCollection(nil, []*agentsv1alpha1.SecurityProfile{},
		opts.WithName("SecurityProfileSource")...)
	globalProfiles := krt.NewStaticCollection(nil, []*agentsv1alpha1.GlobalSecurityProfile{},
		opts.WithName("GlobalSecurityProfileSource")...)
	policies := newBindablePoliciesCollection(profiles, globalProfiles, opts)
	attachments := newPolicyAttachmentsCollection(policies, opts)
	workloads := krt.NewStaticCollection(nil, []model.WorkloadInfo{
		sniTestWorkload("pod", "bench", map[string]string{"app": "agent"}),
	}, opts.WithName("Workloads")...)
	bindings := newPolicyBindingCollection(workloads, attachments, opts)
	if !bindings.WaitUntilSynced(test.NewStop(t)) {
		t.Fatal("policy bindings did not sync")
	}

	var policyBatches, policyEvents, bindingUpdates atomic.Int64
	policyRegistration := policies.RegisterBatch(func(events []krt.Event[BindablePolicy]) {
		policyBatches.Add(1)
		policyEvents.Add(int64(len(events)))
	}, false)
	t.Cleanup(policyRegistration.UnregisterHandler)
	bindingRegistration := bindings.RegisterBatch(func(events []krt.Event[model.PolicyBinding]) {
		bindingUpdates.Add(int64(len(events)))
	}, false)
	t.Cleanup(bindingRegistration.UnregisterHandler)

	for i := 0; i < policyCount; i++ {
		profiles.UpdateObject(newProfile(i))
		// Keep the burst active inside the debounce window while giving an
		// un-debounced collection enough time to fan each event out separately.
		time.Sleep(debounce / 4)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		items := bindings.List()
		if len(items) == 1 {
			refs := items[0].Binding.GetPolicyRefs()[xdsmodel.SniTrafficPolicyType]
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
	for (policyEvents.Load() < policyCount || bindingUpdates.Load() == 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := policyEvents.Load(); got != policyCount {
		t.Fatalf("policy events = %d, want %d", got, policyCount)
	}
	if got := policyBatches.Load(); got != 1 {
		t.Fatalf("policy batches = %d, want 1 merged batch", got)
	}
	if got := bindingUpdates.Load(); got != 1 {
		t.Fatalf("binding updates = %d, want 1 merged update", got)
	}
}
