// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package krt_test

import (
	"fmt"
	"strings"

	"istio.io/istio/pkg/config"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/openkruise/agentio/pkg/kube/controllers"
	"github.com/openkruise/agentio/pkg/kube/kclient"

	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
)

func CompareUnordered(wants ...string) func(s string) bool {
	want := sets.New(wants...)
	return func(s string) bool {
		got := sets.New(strings.Split(s, ",")...)
		return want.Equals(got)
	}
}

func testOptions(t test.Failer) krt.OptionsBuilder {
	return krt.NewOptionsBuilder(test.NewStop(t), "test", krt.GlobalDebugHandler)
}

type Named struct {
	Namespace string
	Name      string
}

func (s Named) GetNamespace() string {
	return s.Namespace
}

func (s Named) GetName() string {
	return s.Name
}

func (s Named) ResourceName() string {
	return s.Namespace + "/" + s.Name
}

func TrackerHandler[T any](tracker *assert.Tracker[string]) func(krt.Event[T]) {
	return func(o krt.Event[T]) {
		tracker.Record(fmt.Sprintf("%v/%v", o.Event, krt.GetKey(o.Latest())))
	}
}

func BatchedTrackerHandler[T any](tracker *assert.Tracker[string]) func([]krt.Event[T]) {
	return func(o []krt.Event[T]) {
		tracker.Record(slices.Join(",", slices.Map(o, func(o krt.Event[T]) string {
			return fmt.Sprintf("%v/%v", o.Event, krt.GetKey(o.Latest()))
		})...))
	}
}

type SimpleSizedPod struct {
	SimplePod
	Size string
}

type SimplePod struct {
	Named
	Labeled
	IP string
}

func SimplePodCollection(pods krt.Collection[*corev1.Pod], opts krt.OptionsBuilder) krt.Collection[SimplePod] {
	return NamedSimplePodCollection(pods, opts, "SimplePods")
}

func NamedSimplePodCollection(
	pods krt.Collection[*corev1.Pod],
	opts krt.OptionsBuilder,
	name string,
) krt.Collection[SimplePod] {
	return krt.NewCollection(pods, func(ctx krt.HandlerContext, i *corev1.Pod) *SimplePod {
		if i.Status.PodIP == "" {
			return nil
		}
		return &SimplePod{
			Named:   NewNamed(i),
			Labeled: NewLabeled(i.Labels),
			IP:      i.Status.PodIP,
		}
	}, opts.WithName(name)...)
}

func NewNamed(n config.Namer) Named {
	return Named{
		Namespace: n.GetNamespace(),
		Name:      n.GetName(),
	}
}

func NewLabeled(n map[string]string) Labeled {
	return Labeled{n}
}

type Labeled struct {
	Labels map[string]string
}

func (l Labeled) GetLabels() map[string]string {
	return l.Labels
}

type SimpleService struct {
	Named
	Selector map[string]string
	IP       string
}

type NamespaceIPs struct {
	Namespace string
	IPs       []string
}

func (n NamespaceIPs) ResourceName() string {
	return n.Namespace
}

type testWriter[T controllers.Object] struct {
	c kclient.Writer[T]
	t test.Failer
}

func (t testWriter[T]) Create(object T) T {
	t.t.Helper()
	res, err := t.c.Create(object)
	if err != nil {
		t.t.Fatalf("create %v/%v: %v", object.GetNamespace(), object.GetName(), err)
	}
	return res
}

func (t testWriter[T]) Update(object T) T {
	t.t.Helper()
	res, err := t.c.Update(object)
	if err != nil {
		t.t.Fatalf("update %v/%v: %v", object.GetNamespace(), object.GetName(), err)
	}
	return res
}

func (t testWriter[T]) UpdateStatus(object T) T {
	t.t.Helper()
	res, err := t.c.UpdateStatus(object)
	if err != nil {
		t.t.Fatalf("update status %v/%v: %v", object.GetNamespace(), object.GetName(), err)
	}
	return res
}

func (t testWriter[T]) CreateOrUpdateStatus(object T) T {
	t.t.Helper()
	_, err := t.c.Create(object)
	if apierrors.IsAlreadyExists(err) {
		_, err = t.c.Update(object)
	}
	if err != nil {
		t.t.Fatalf("createOrUpdate %v/%v: %v", object.GetNamespace(), object.GetName(), err)
	}
	return t.UpdateStatus(object)
}

func (t testWriter[T]) Delete(name, namespace string) {
	t.t.Helper()
	err := t.c.Delete(name, namespace)
	if err != nil {
		t.t.Fatalf("delete %v/%v: %v", namespace, name, err)
	}
}
