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

package kruise

import (
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/openkruise/agentio/pkg/krt"
)

func TestSandboxUIDHonorsDeliveryIdentity(t *testing.T) {
	for _, test := range []struct {
		name    string
		sandbox *agentsv1alpha1.Sandbox
		want    string
		found   bool
	}{
		{
			name: "delivery identity",
			sandbox: &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo",
				Name:      "sandbox",
				Labels: map[string]string{
					agentsv1alpha1.LabelSandboxID: "delivery-uid",
				},
			}},
			want:  "delivery-uid",
			found: true,
		},
		{
			name: "ordinary compatibility identity",
			sandbox: &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo",
				Name:      "sandbox",
			}},
			want:  "demo--sandbox",
			found: true,
		},
		{
			name: "pooled sandbox requires delivery identity",
			sandbox: &agentsv1alpha1.Sandbox{ObjectMeta: metav1.ObjectMeta{
				Namespace: "demo",
				Name:      "sandbox",
				Labels: map[string]string{
					agentsv1alpha1.LabelSandboxPool: "pool",
				},
			}},
		},
		{
			name: "nil",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, found := sandboxUID(test.sandbox)
			if got != test.want || found != test.found {
				t.Fatalf("sandboxUID() = %q, %v, want %q, %v", got, found, test.want, test.found)
			}
		})
	}
}

func TestKruiseSandboxProducesPodAttesterBinding(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	options := []krt.CollectionOption{krt.WithStop(stop)}
	controller := true
	futureInternalLabel := agentsv1alpha1.InternalPrefix + "future-controller-state"
	podCreatedByLabel := agentsv1alpha1.InternalPrefix + "created-by"
	sandbox := &agentsv1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "demo",
			Name:       "sandbox",
			UID:        "sandbox-object-uid",
			Generation: 3,
			Labels: map[string]string{
				agentsv1alpha1.LabelSandboxID:           "delivery-uid",
				agentsv1alpha1.LabelSandboxIsClaimed:    agentsv1alpha1.True,
				agentsv1alpha1.LabelAllowInternetAccess: agentsv1alpha1.False,
				"app":                                   "sandbox-value",
				"sandbox-only":                          "kept",
			},
		},
		Status: agentsv1alpha1.SandboxStatus{
			ObservedGeneration: 3,
			Phase:              agentsv1alpha1.SandboxRunning,
			Conditions: []metav1.Condition{
				{
					Type:   string(agentsv1alpha1.SandboxConditionReady),
					Status: metav1.ConditionTrue,
				},
			},
			PodInfo: agentsv1alpha1.PodInfo{
				PodUID: "pod-uid",
			},
		},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "demo",
			Name:      "sandbox-runtime",
			UID:       "pod-uid",
			Labels: map[string]string{
				agentsv1alpha1.LabelSandboxID:           "spoofed-delivery-uid",
				agentsv1alpha1.LabelSandboxIsClaimed:    agentsv1alpha1.False,
				agentsv1alpha1.LabelSandboxUpdateOps:    "spoofed-update",
				agentsv1alpha1.LabelSandboxName:         "sandbox",
				agentsv1alpha1.LabelAllowInternetAccess: agentsv1alpha1.True,
				agentsv1alpha1.AnnotationOwner:          "claim-uid",
				podCreatedByLabel:                       "sandbox",
				futureInternalLabel:                     "stale",
				"app":                                   "pod-value",
				"pod-only":                              "included",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: agentsv1alpha1.GroupVersion.String(),
					Kind:       "Sandbox",
					Name:       sandbox.Name,
					UID:        sandbox.UID,
					Controller: &controller,
				},
			},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			NodeName:           "node-a",
		},
		Status: corev1.PodStatus{
			Phase:  corev1.PodRunning,
			PodIP:  "10.0.0.10",
			PodIPs: []corev1.PodIP{{IP: "10.0.0.10"}},
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
	sandboxObjects := krt.NewStaticCollection(
		nil,
		[]*agentsv1alpha1.Sandbox{sandbox},
		options...,
	)
	sandboxGroups := newSandboxesByUID(sandboxObjects).AsCollection(options...)
	pods := krt.NewStaticCollection(nil, []*corev1.Pod{pod}, options...)
	podsByUID := newPodsByUID(pods)
	sandboxes := newSandboxes(sandboxGroups, pods, podsByUID, options...)
	workloads := newWorkloads(
		sandboxGroups,
		pods,
		podsByUID,
		"cluster",
		"cluster.local",
		options...,
	)
	if !sandboxes.WaitUntilSynced(stop) || !workloads.WaitUntilSynced(stop) {
		t.Fatal("Kruise runtime collections did not synchronize")
	}

	policySubject := sandboxes.GetKey("delivery-uid")
	if policySubject == nil || policySubject.UID != "delivery-uid" {
		t.Fatalf("Sandbox = %+v, want delivery identity", policySubject)
	}
	if policySubject.Namespace != "demo" {
		t.Fatalf("Sandbox namespace = %q, want demo", policySubject.Namespace)
	}
	if got := policySubject.Labels["app"]; got != "pod-value" {
		t.Fatalf("Sandbox app label = %q, want pod-value", got)
	}
	if got := policySubject.Labels["sandbox-only"]; got != "kept" {
		t.Fatalf("Sandbox-only label = %q, want kept", got)
	}
	if got := policySubject.Labels["pod-only"]; got != "included" {
		t.Fatalf("Pod-only label = %q, want included", got)
	}
	if got := policySubject.Labels[agentsv1alpha1.LabelSandboxID]; got != "delivery-uid" {
		t.Fatalf("Sandbox ID label = %q, want delivery-uid", got)
	}
	if got := policySubject.Labels[agentsv1alpha1.LabelSandboxIsClaimed]; got != agentsv1alpha1.True {
		t.Fatalf("Sandbox claimed label = %q, want true", got)
	}
	if got, found := policySubject.Labels[agentsv1alpha1.LabelSandboxUpdateOps]; found {
		t.Fatalf("Pod-only protected label leaked into Sandbox: %q", got)
	}
	if got := policySubject.Labels[agentsv1alpha1.LabelSandboxName]; got != "sandbox" {
		t.Fatalf("Sandbox name label = %q, want sandbox", got)
	}
	if got := policySubject.Labels[agentsv1alpha1.LabelAllowInternetAccess]; got != agentsv1alpha1.True {
		t.Fatalf("Allow internet label = %q, want true", got)
	}
	if got := policySubject.Labels[agentsv1alpha1.AnnotationOwner]; got != "claim-uid" {
		t.Fatalf("Owner label = %q, want claim-uid", got)
	}
	if got := policySubject.Labels[podCreatedByLabel]; got != "sandbox" {
		t.Fatalf("Created-by label = %q, want sandbox", got)
	}
	if got, found := policySubject.Labels[futureInternalLabel]; found {
		t.Fatalf("Unknown Pod-only internal label leaked into Sandbox: %q", got)
	}
	sandbox.Labels["sandbox-only"] = "mutated"
	pod.Labels["pod-only"] = "mutated"
	if got := policySubject.Labels["sandbox-only"]; got != "kept" {
		t.Fatalf("published Sandbox labels aliased Sandbox source map: sandbox-only = %q", got)
	}
	if got := policySubject.Labels["pod-only"]; got != "included" {
		t.Fatalf("published Sandbox labels aliased Pod source map: pod-only = %q", got)
	}
	workload := workloads.GetKey("cluster//Pod/demo/sandbox-runtime")
	if workload == nil {
		t.Fatal("Kruise runtime produced no Workload attester")
	}
	if workload.SourceUID != "pod-uid" || workload.Principal.String() != "spiffe://cluster.local/ns/demo/sa/default" {
		t.Fatalf("Workload attester = %+v", workload)
	}
	if len(workload.SandboxBindings) != 1 || workload.SandboxBindings[0].SandboxUID != "delivery-uid" {
		t.Fatalf("Sandbox bindings = %+v", workload.SandboxBindings)
	}
	if !workload.Ready || !OwnsPod(pod) {
		t.Fatalf("Workload ready = %v, OwnsPod = %v", workload.Ready, OwnsPod(pod))
	}
}

func TestKruiseRuntimeActivationFailsClosed(t *testing.T) {
	base := &agentsv1alpha1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:  "demo",
			Name:       "sandbox",
			UID:        types.UID("sandbox-uid"),
			Generation: 2,
		},
		Status: agentsv1alpha1.SandboxStatus{
			ObservedGeneration: 2,
			Phase:              agentsv1alpha1.SandboxRunning,
		},
	}
	stale := base.DeepCopy()
	stale.Status.ObservedGeneration = 1
	initializing := base.DeepCopy()
	initializing.Status.Conditions = []metav1.Condition{
		{
			Type:   string(agentsv1alpha1.RuntimeInitialized),
			Status: metav1.ConditionFalse,
		},
	}
	terminated := base.DeepCopy()
	terminated.Status.Phase = agentsv1alpha1.SandboxFailed

	for _, test := range []struct {
		name    string
		sandbox *agentsv1alpha1.Sandbox
		want    bool
	}{
		{name: "running", sandbox: base, want: true},
		{name: "stale observation", sandbox: stale},
		{name: "runtime initializing", sandbox: initializing},
		{name: "terminated", sandbox: terminated},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := hasServingRuntime(test.sandbox); got != test.want {
				t.Fatalf("hasServingRuntime() = %v, want %v", got, test.want)
			}
		})
	}
}
