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

package ambient

import (
	"testing"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/workloadapi"
)

func TestWorkloadConfigsForProxyAttachesCurrentActor(t *testing.T) {
	const (
		workerName      = "worker-0"
		workerNamespace = "substrate-system"
	)
	base := model.WorkloadConfig{
		Name:      "default",
		Namespace: "agentio-system",
		Config: &extensions.WorkloadConfig{
			Scope: extensions.WorkloadConfigScope_WORKLOAD_CONFIG_SCOPE_GLOBAL,
		},
	}
	workload := model.WorkloadInfo{
		Workload: &workloadapi.Workload{
			Uid:       "//Pod/" + workerNamespace + "/" + workerName,
			Name:      workerName,
			Namespace: workerNamespace,
		},
		Labels: map[string]string{
			agentio.LabelActorUID:             "actor-uid-1",
			agentio.LabelActorName:            "crawler",
			agentio.LabelActorAtespace:        "demo",
			agentio.LabelActorGeneration:      "7",
			agentio.ActorLabelPrefix + "role": "reader",
			agentio.LabelSandboxProxyType:     "ztunnel",
		},
	}
	a := &index{
		SystemNamespace: "agentio-system",
		workloads: workloadsCollection{Collection: krt.NewStaticCollection(
			nil,
			[]model.WorkloadInfo{workload},
		)},
		workloadConfigs: krt.NewStaticCollection(nil, []model.WorkloadConfig{base}),
	}
	proxy := &model.Proxy{
		ID: workerName + "." + workerNamespace,
		Metadata: &model.NodeMetadata{
			Namespace: workerNamespace,
		},
		Labels: map[string]string{agentio.LabelSandboxProxyType: "ztunnel"},
	}

	got := a.WorkloadConfigsForProxy(proxy, nil)
	if len(got) != 1 {
		t.Fatalf("WorkloadConfigsForProxy() returned %d configs, want 1", len(got))
	}
	actor := got[0].Config.GetActorContext()
	if actor == nil {
		t.Fatal("WorkloadConfigsForProxy() did not attach ActorContext")
	}
	if actor.GetActorUid() != "actor-uid-1" || actor.GetGeneration() != 7 {
		t.Fatalf("unexpected ActorContext: %+v", actor)
	}
	if actor.GetLabels()["role"] != "reader" {
		t.Fatalf("actor labels = %v, want role=reader", actor.GetLabels())
	}
	if base.Config.GetActorContext() != nil {
		t.Fatal("WorkloadConfigsForProxy() mutated the shared WorkloadConfig")
	}
}

func TestWorkloadConfigsForProxyOmitsIncompleteActor(t *testing.T) {
	const (
		workerName      = "worker-0"
		workerNamespace = "substrate-system"
	)
	base := model.WorkloadConfig{
		Name:      "default",
		Namespace: "agentio-system",
		Config:    &extensions.WorkloadConfig{},
	}
	workload := model.WorkloadInfo{
		Workload: &workloadapi.Workload{
			Uid:       "//Pod/" + workerNamespace + "/" + workerName,
			Name:      workerName,
			Namespace: workerNamespace,
		},
		Labels: map[string]string{
			agentio.LabelActorUID:         "actor-uid-1",
			agentio.LabelSandboxProxyType: "ztunnel",
		},
	}
	a := &index{
		SystemNamespace: "agentio-system",
		workloads: workloadsCollection{Collection: krt.NewStaticCollection(
			nil,
			[]model.WorkloadInfo{workload},
		)},
		workloadConfigs: krt.NewStaticCollection(nil, []model.WorkloadConfig{base}),
	}
	proxy := &model.Proxy{
		ID:       workerName + "." + workerNamespace,
		Metadata: &model.NodeMetadata{Namespace: workerNamespace},
		Labels:   map[string]string{agentio.LabelSandboxProxyType: "ztunnel"},
	}

	got := a.WorkloadConfigsForProxy(proxy, nil)
	if len(got) != 1 {
		t.Fatalf("WorkloadConfigsForProxy() returned %d configs, want 1", len(got))
	}
	if got[0].Config.GetActorContext() != nil {
		t.Fatalf("ActorContext = %+v, want nil", got[0].Config.GetActorContext())
	}
}
