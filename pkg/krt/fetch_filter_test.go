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

package krt

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/test/util/assert"
)

type augmentedFetchCollection struct {
	internalCollection[dependencyMatchObject]
}

func (c augmentedFetchCollection) augment(value any) any {
	item := value.(dependencyMatchObject)
	item.Labels = map[string]string{"app": "augmented"}
	return item
}

func TestFetchAppliesResidualFilters(t *testing.T) {
	source := NewStaticCollection(nil, []dependencyMatchObject{
		{Name: "a", Namespace: "ns", Labels: map[string]string{"app": "selected"}},
		{Name: "b", Namespace: "ns", Labels: map[string]string{"app": "other"}},
	}, WithStop(t.Context().Done()))
	byNamespace := NewIndex(
		source,
		"namespace",
		func(item dependencyMatchObject) []string { return []string{item.Namespace} },
	)
	for _, prefilter := range [][]FetchOption{
		nil,
		{FilterKeys("ns/a", "ns/b")},
		{FilterIndex(byNamespace, "ns")},
	} {
		for _, residual := range []FetchOption{
			FilterLabel(map[string]string{"app": "selected"}),
			FilterGeneric(func(value any) bool { return value.(dependencyMatchObject).Name == "a" }),
		} {
			opts := append(append([]FetchOption(nil), prefilter...), residual)
			got := Fetch(TestingDummyContext{}, source, opts...)
			assert.Equal(t, len(got), 1)
			assert.Equal(t, got[0].Name, "a")
		}
	}
	augmented := augmentedFetchCollection{internalCollection: source}
	got := Fetch(TestingDummyContext{}, augmented, FilterLabel(map[string]string{"app": "augmented"}))
	assert.Equal(t, len(got), 2)
	assert.Equal(t, len(Fetch(TestingDummyContext{}, source, FilterKeys([]string{}...))), 0)
}

func TestFetchSelectsEmptyLabels(t *testing.T) {
	empty := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "empty"}}
	selected := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "selected"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "selected"}},
	}
	source := NewStaticCollection(nil, []*corev1.Service{empty, selected}, WithStop(t.Context().Done()))
	for _, labels := range []map[string]string{nil, {}} {
		assert.Equal(t, Fetch(TestingDummyContext{}, source, FilterSelects(labels)), []*corev1.Service{empty})
		assert.Equal(t, len(Fetch(TestingDummyContext{}, source, FilterSelectsNonEmpty(labels))), 0)
	}
	assert.Equal(
		t,
		Fetch(TestingDummyContext{}, source, FilterSelectsNonEmpty(map[string]string{"app": "selected"})),
		[]*corev1.Service{selected},
	)
}
