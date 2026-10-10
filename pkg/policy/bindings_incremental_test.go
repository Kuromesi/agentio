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
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestIncrementalPrioritySkipsSelection(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	opts := []krt.CollectionOption{krt.WithStop(stop)}
	var calls atomic.Int64
	first, err := NewPolicyAttachment(PolicyAttachment{Kind: PolicyKindTrafficPolicy, Name: "first", Target: AttachmentTarget{Global: true}})
	if err != nil {
		t.Fatal(err)
	}
	first.selector = bindingRecomputeSelector{Selector: first.selector, calls: &calls}
	second := first
	second.Name = "second"
	second.Priority = 1
	policies := krt.NewMutableCollection(nil, []PolicyAttachment{first, second}, opts...)
	bindings := NewWorkloadPolicyBindingsCollection(krt.NewStaticCollection(nil, []model.Workload{{UID: "client", Namespace: "demo"}}, opts...), policies.AsCollection(), krt.NewOptionsBuilder(stop, "test", nil))
	if !bindings.WaitUntilSynced(stop) {
		t.Fatal("sync failed")
	}
	calls.Store(0)
	events := make(chan krt.Event[Bindings], 1)
	reg := bindings.RegisterBatch(func(es []krt.Event[Bindings]) {
		for _, e := range es {
			events <- e
		}
	}, false)
	defer reg.UnregisterHandler()
	second.Priority = -1
	policies.ConditionalUpdateObject(second)
	e := awaitBindingEvent(t, events)
	if names := e.Latest().PolicyNames(PolicyKindTrafficPolicy); len(names) != 2 || names[0] != "second" {
		t.Fatalf("wrong ordering: %v", names)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("priority update ran %d selector evaluations", got)
	}
}

func TestIncrementalStopsBeforeInputSync(t *testing.T) {
	stop := make(chan struct{})
	ready := make(bindingSync)
	policies := krt.NewMutableCollection[PolicyAttachment](ready, nil, krt.WithStop(stop))
	workloads := krt.NewStaticCollection[model.Workload](nil, nil, krt.WithStop(stop))
	bindings := NewWorkloadPolicyBindingsCollection(workloads, policies.AsCollection(), krt.NewOptionsBuilder(stop, "test", nil))
	if bindings.HasSynced() {
		t.Fatal("ready before inputs synced")
	}
	close(stop)
	done := make(chan bool, 1)
	go func() { done <- bindings.WaitUntilSynced(stop) }()
	select {
	case synced := <-done:
		if synced {
			t.Fatal("stopped initialization reported ready")
		}
	case <-time.After(time.Second):
		t.Fatal("sync wait did not stop")
	}
}
