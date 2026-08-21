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

type mappedActorContextSource struct {
	actors        map[string]*extensions.ActorContext
	authoritative bool
}

func (f *mappedActorContextSource) ActorContextForWorker(namespace, podName, podUID string) (*extensions.ActorContext, bool) {
	return f.actors[namespace+"/"+podName+"/"+podUID], f.authoritative
}

type fakeActorContextSource struct {
	actor         *extensions.ActorContext
	authoritative bool
	namespace     string
	podName       string
	podUID        string
}

func (f *fakeActorContextSource) ActorContextForWorker(namespace, podName, podUID string) (*extensions.ActorContext, bool) {
	f.namespace = namespace
	f.podName = podName
	f.podUID = podUID
	return f.actor, f.authoritative
}

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

func TestWorkloadConfigsForProxyPrefersAuthoritativeListWorkersBinding(t *testing.T) {
	const (
		workerName      = "worker-0"
		workerNamespace = "workers"
		workerPodUID    = "pod-uid-1"
	)
	source := &fakeActorContextSource{
		authoritative: true,
		actor: &extensions.ActorContext{
			ActorUid:   "api-actor-uid",
			ActorName:  "api-actor",
			Atespace:   "tenant-a",
			Generation: 12,
		},
	}
	a := actorWorkloadConfigTestIndex(source, workerNamespace, workerName, workerPodUID)

	got := a.WorkloadConfigsForProxy(actorWorkloadConfigTestProxy(workerNamespace, workerName), nil)
	actor := got[0].Config.GetActorContext()
	if actor == nil || actor.GetActorUid() != "api-actor-uid" || actor.GetGeneration() != 12 {
		t.Fatalf("ActorContext = %+v, want authoritative ListWorkers Actor", actor)
	}
	if source.namespace != workerNamespace || source.podName != workerName || source.podUID != workerPodUID {
		t.Fatalf("ActorContextForWorker() called with %q/%q uid=%q", source.namespace, source.podName, source.podUID)
	}
}

func TestWorkloadConfigsForProxyDoesNotFallBackToLabelsWhenListWorkersIsAuthoritative(t *testing.T) {
	source := &fakeActorContextSource{authoritative: true}
	a := actorWorkloadConfigTestIndex(source, "workers", "worker-0", "pod-uid-1")

	got := a.WorkloadConfigsForProxy(actorWorkloadConfigTestProxy("workers", "worker-0"), nil)
	if actor := got[0].Config.GetActorContext(); actor != nil {
		t.Fatalf("ActorContext = %+v, want nil for unassigned authoritative Worker", actor)
	}
}

func actorWorkloadConfigTestIndex(source actorContextSource, namespace, podName, podUID string) *index {
	workload := model.WorkloadInfo{
		Workload: &workloadapi.Workload{
			Uid:       "//Pod/" + namespace + "/" + podName,
			Name:      podName,
			Namespace: namespace,
		},
		NativeUID: podUID,
		Labels: map[string]string{
			agentio.LabelActorUID:         "spoofed-label-uid",
			agentio.LabelActorName:        "spoofed-label-actor",
			agentio.LabelActorAtespace:    "spoofed-tenant",
			agentio.LabelActorGeneration:  "99",
			agentio.LabelSandboxProxyType: "ztunnel",
		},
	}
	return &index{
		SystemNamespace:    "agentio-system",
		actorContextSource: source,
		workloads:          workloadsCollection{Collection: krt.NewStaticCollection(nil, []model.WorkloadInfo{workload})},
		workloadConfigs: krt.NewStaticCollection(nil, []model.WorkloadConfig{{
			Name:      "default",
			Namespace: "agentio-system",
			Config: &extensions.WorkloadConfig{
				Scope: extensions.WorkloadConfigScope_WORKLOAD_CONFIG_SCOPE_GLOBAL,
			},
		}}),
	}
}

func actorWorkloadConfigTestProxy(namespace, podName string) *model.Proxy {
	return &model.Proxy{
		ID:       podName + "." + namespace,
		Metadata: &model.NodeMetadata{Namespace: namespace},
		Labels:   map[string]string{agentio.LabelSandboxProxyType: "ztunnel"},
	}
}

func TestAddressInformationForNodeZtunnelAttachesActorOnlyToLocalWorker(t *testing.T) {
	local := actorAddressTestWorkload("workers", "worker-a", "pod-uid-a", "node-a")
	remote := actorAddressTestWorkload("workers", "worker-b", "pod-uid-b", "node-b")
	source := &mappedActorContextSource{
		authoritative: true,
		actors: map[string]*extensions.ActorContext{
			"workers/worker-a/pod-uid-a": {
				ActorUid: "actor-a", ActorName: "a", Atespace: "tenant", Generation: 3,
			},
			"workers/worker-b/pod-uid-b": {
				ActorUid: "actor-b", ActorName: "b", Atespace: "tenant", Generation: 4,
			},
		},
	}
	a := &index{
		actorContextSource: source,
		workloads: workloadsCollection{Collection: krt.NewStaticCollection(
			nil,
			[]model.WorkloadInfo{local, remote},
		)},
		services: servicesCollection{Collection: krt.NewStaticCollection(nil, []model.ServiceInfo{})},
	}
	proxy := &model.Proxy{
		Type: model.Ztunnel,
		Metadata: &model.NodeMetadata{
			NodeName:  "node-a",
			ClusterID: "cluster-a",
		},
	}

	got, removed := a.AddressInformationForProxy(proxy, nil)
	if len(removed) != 0 || len(got) != 2 {
		t.Fatalf("AddressInformationForProxy() = %d addresses, %d removed; want 2, 0", len(got), len(removed))
	}
	if actor := actorContextFromAddress(t, got, local.ResourceName()); actor == nil || actor.GetActorUid() != "actor-a" {
		t.Fatalf("local Worker ActorContext = %+v, want actor-a", actor)
	}
	if actor := actorContextFromAddress(t, got, remote.ResourceName()); actor != nil {
		t.Fatalf("remote Worker ActorContext = %+v, want nil", actor)
	}
	if len(local.Workload.GetExtensions()) != 0 || len(remote.Workload.GetExtensions()) != 0 {
		t.Fatal("AddressInformationForProxy() mutated shared Workload extensions")
	}
}

func TestAddressInformationForDedicatedZtunnelAttachesOnlyItsOwnActor(t *testing.T) {
	self := actorAddressTestWorkload("workers", "worker-a", "pod-uid-a", "node-a")
	peer := actorAddressTestWorkload("workers", "worker-b", "pod-uid-b", "node-a")
	source := &mappedActorContextSource{
		authoritative: true,
		actors: map[string]*extensions.ActorContext{
			"workers/worker-a/pod-uid-a": {
				ActorUid: "actor-a", ActorName: "a", Atespace: "tenant", Generation: 3,
			},
			"workers/worker-b/pod-uid-b": {
				ActorUid: "actor-b", ActorName: "b", Atespace: "tenant", Generation: 4,
			},
		},
	}
	a := &index{
		actorContextSource: source,
		workloads: workloadsCollection{Collection: krt.NewStaticCollection(
			nil,
			[]model.WorkloadInfo{self, peer},
		)},
		services: servicesCollection{Collection: krt.NewStaticCollection(nil, []model.ServiceInfo{})},
	}
	proxy := &model.Proxy{
		ID:   "worker-a.workers",
		Type: model.Ztunnel,
		Metadata: &model.NodeMetadata{
			Namespace: "workers",
			NodeName:  "node-a",
			ClusterID: "cluster-a",
		},
		Labels: map[string]string{agentio.LabelSandboxProxyType: "ztunnel"},
	}

	got, _ := a.AddressInformationForProxy(proxy, nil)
	if actor := actorContextFromAddress(t, got, self.ResourceName()); actor == nil || actor.GetActorUid() != "actor-a" {
		t.Fatalf("self ActorContext = %+v, want actor-a", actor)
	}
	if actor := actorContextFromAddress(t, got, peer.ResourceName()); actor != nil {
		t.Fatalf("peer ActorContext = %+v, want nil", actor)
	}
}

func actorAddressTestWorkload(namespace, name, podUID, node string) model.WorkloadInfo {
	workload := &workloadapi.Workload{
		Uid:       "cluster-a//Pod/" + namespace + "/" + name,
		Name:      name,
		Namespace: namespace,
		Node:      node,
	}
	address := &workloadapi.Address{Type: &workloadapi.Address_Workload{Workload: workload}}
	return model.WorkloadInfo{
		Workload:  workload,
		NativeUID: podUID,
		AsAddress: model.AddressInfo{Address: address},
	}
}

func actorContextFromAddress(t *testing.T, addresses []model.AddressInfo, resourceName string) *extensions.ActorContext {
	t.Helper()
	for _, address := range addresses {
		if address.ResourceName() != resourceName || address.GetWorkload() == nil {
			continue
		}
		for _, extension := range address.GetWorkload().GetExtensions() {
			if extension.GetName() != "actor-context" {
				continue
			}
			actor := &extensions.ActorContext{}
			if err := extension.GetConfig().UnmarshalTo(actor); err != nil {
				t.Fatal(err)
			}
			return actor
		}
		return nil
	}
	t.Fatalf("Workload %q not found", resourceName)
	return nil
}
