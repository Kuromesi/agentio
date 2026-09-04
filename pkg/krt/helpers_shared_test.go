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
