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

// Package kruise adapts Kruise Agents Sandbox resources into the shared
// Sandbox and Workload domain collections.
package kruise

import (
	"context"
	"maps"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	"github.com/openkruise/agentio/pkg/model"
)

var sandboxResource = schema.GroupVersionResource{
	Group:    "agents.kruise.io",
	Version:  "v1alpha1",
	Resource: "sandboxes",
}

// Options contains only the Kubernetes source settings needed by the Kruise
// runtime adapter.
type Options struct {
	ClusterID     string
	TrustDomain   string
	DebounceAfter time.Duration
	DebounceMax   time.Duration
}

// Source holds the Sandbox and Workload collections produced by the Kruise adapter.
type Source struct {
	Sandboxes krt.Collection[model.Sandbox]
	Workloads krt.Collection[model.Workload]
}

// NewSource constructs the optional, delayed-informer-backed Kruise source.
// If the Sandbox CRD is absent, the source remains empty and becomes synced.
func NewSource(
	client kube.Client,
	pods krt.Collection[*corev1.Pod],
	options Options,
	stop <-chan struct{},
) Source {
	sourceOptions := func(name string) []krt.CollectionOption {
		return []krt.CollectionOption{
			krt.WithName(name),
			krt.WithStop(stop),
			krt.WithDebounce(options.DebounceAfter, options.DebounceMax),
		}
	}
	derivedOptions := func(name string) []krt.CollectionOption {
		return []krt.CollectionOption{
			krt.WithName(name),
			krt.WithStop(stop),
		}
	}

	objects := newSandboxObjects(
		client,
		stop,
		sourceOptions("kruise-sandbox-objects")...,
	)
	sandboxesByUID := newSandboxesByUID(objects)
	sandboxGroups := sandboxesByUID.AsCollection(
		derivedOptions("kruise-sandboxes-by-uid")...,
	)
	podsByUID := newPodsByUID(pods)
	return Source{
		Sandboxes: newSandboxes(
			sandboxGroups,
			pods,
			podsByUID,
			derivedOptions("kruise-sandboxes")...,
		),
		Workloads: newWorkloads(
			sandboxGroups,
			pods,
			podsByUID,
			options.ClusterID,
			options.TrustDomain,
			derivedOptions("kruise-sandbox-workloads")...,
		),
	}
}

func newSandboxObjects(
	client kube.Client,
	stop <-chan struct{},
	options ...krt.CollectionOption,
) krt.Collection[*agentsv1alpha1.Sandbox] {
	informer := kclient.NewDelayedInformerFor[*agentsv1alpha1.Sandbox](
		client,
		kube.InformerRegistration{
			Resource: sandboxResource,
			Object:   &agentsv1alpha1.Sandbox{},
			List: func(ctx context.Context, namespace string, options metav1.ListOptions) (runtime.Object, error) {
				return client.AgentsAPI().AgentsV1alpha1().Sandboxes(namespace).List(ctx, options)
			},
			Watch: func(ctx context.Context, namespace string, options metav1.ListOptions) (watch.Interface, error) {
				return client.AgentsAPI().AgentsV1alpha1().Sandboxes(namespace).Watch(ctx, options)
			},
		},
		kclient.Filter{
			ObjectTransform: stripSandbox,
		},
	)
	informer.Start(stop)
	return krt.WrapClient(informer, options...)
}

// stripSandbox keeps the selector labels, conditions, and Pod UID needed for projection.
func stripSandbox(obj any) (any, error) {
	sandbox, ok := obj.(*agentsv1alpha1.Sandbox)
	if !ok || sandbox == nil {
		return obj, nil
	}
	conditions := make([]metav1.Condition, 0, 2)
	for _, condition := range sandbox.Status.Conditions {
		if condition.Type == string(agentsv1alpha1.SandboxConditionReady) ||
			condition.Type == string(agentsv1alpha1.RuntimeInitialized) {
			conditions = append(conditions, condition)
		}
	}
	return &agentsv1alpha1.Sandbox{
		TypeMeta: sandbox.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{
			Name:              sandbox.Name,
			Namespace:         sandbox.Namespace,
			UID:               sandbox.UID,
			ResourceVersion:   sandbox.ResourceVersion,
			Generation:        sandbox.Generation,
			DeletionTimestamp: sandbox.DeletionTimestamp.DeepCopy(),
			Labels:            maps.Clone(sandbox.Labels),
		},
		Status: agentsv1alpha1.SandboxStatus{
			ObservedGeneration: sandbox.Status.ObservedGeneration,
			Phase:              sandbox.Status.Phase,
			Conditions:         conditions,
			PodInfo: agentsv1alpha1.PodInfo{
				PodUID: sandbox.Status.PodInfo.PodUID,
			},
		},
	}, nil
}
