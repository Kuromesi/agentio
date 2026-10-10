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
	"testing"

	"istio.io/istio/pkg/test/util/assert"

	"github.com/openkruise/agentio/pkg/krt"
)

func TestFetchSorted(t *testing.T) {
	opts := testOptions(t)
	source := krt.NewStaticCollection(nil, []Named{
		{Namespace: "ns", Name: "c"},
		{Namespace: "ns", Name: "a"},
		{Namespace: "ns", Name: "b"},
		{Namespace: "other", Name: "a"},
	}, opts.WithName("Source")...)
	byNamespace := krt.NewIndex(source, "namespace", func(n Named) []string { return []string{n.Namespace} })
	result := krt.NewSingleton(func(ctx krt.HandlerContext) *Static {
		return &Static{Value: fmt.Sprint(krt.FetchSorted(ctx, source, krt.FilterIndex(byNamespace, "ns")))}
	}, opts.WithName("Result")...)
	events := assert.NewTracker[string](t)
	result.Register(func(e krt.Event[Static]) { events.Record(e.Latest().Value) })
	events.WaitOrdered("[{ns a} {ns b} {ns c}]")

	source.UpdateObject(Named{Namespace: "ns", Name: "aa"})
	events.WaitOrdered("[{ns a} {ns aa} {ns b} {ns c}]")
	source.DeleteObject("ns/b")
	events.WaitOrdered("[{ns a} {ns aa} {ns c}]")
	for _, name := range []string{"a", "aa", "c"} {
		source.DeleteObject("ns/" + name)
	}
	assert.EventuallyEqual(t, func() string { return result.Get().Value }, "[]")
}
