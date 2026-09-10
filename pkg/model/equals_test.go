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

package model

import (
	"reflect"
	"testing"
)

func TestModelEqualsPreservesDeepEqualSemantics(t *testing.T) {
	checkEqualityFields(t, Workload{}, Workload.Equals)
	checkEqualityFields(t, Sandbox{}, Sandbox.Equals)
	checkEqualityFields(t, Service{}, Service.Equals)
	checkEqualityPairs(t, Workload.Equals, [][2]Workload{
		{{}, {Addresses: []string{}}},
		{{}, {Labels: map[string]string{}}},
		{{Addresses: []string{"a", "b"}}, {Addresses: []string{"b", "a"}}},
		{{Labels: map[string]string{"a": "1", "b": "2"}}, {Labels: map[string]string{"b": "2", "a": "1"}}},
	})
	checkEqualityPairs(t, Sandbox.Equals, [][2]Sandbox{
		{{}, {Attester: &Attester{}}},
		{{Attester: &Attester{WorkloadUID: "a"}}, {Attester: &Attester{WorkloadUID: "a"}}},
		{{Attester: &Attester{WorkloadUID: "a"}}, {Attester: &Attester{WorkloadUID: "b"}}},
		{{}, {Labels: map[string]string{}}},
		{{}, {PolicyRefs: []PolicyRef{}}},
	})
	checkEqualityPairs(t, Service.Equals, [][2]Service{
		{{}, {Addresses: []string{}}},
		{{}, {Ports: []ServicePort{}}},
		{{Ports: []ServicePort{{Name: "http", Port: 80}}}, {Ports: []ServicePort{{Name: "http", Port: 81}}}},
	})
}

// Exercise every field so adding a model field without updating Equals fails.
func checkEqualityFields[T any](t *testing.T, zero T, equal func(T, T) bool) {
	t.Helper()
	value := reflect.ValueOf(zero)
	for i := 0; i < value.NumField(); i++ {
		changed := reflect.New(value.Type()).Elem()
		field := changed.Field(i)
		setEqualityTestValue(field)
		other := changed.Interface().(T)
		if reflect.DeepEqual(zero, other) {
			t.Fatalf("field %s was not changed", value.Type().Field(i).Name)
		}
		if equal(zero, other) || equal(other, zero) {
			t.Errorf("%s ignores %s", value.Type(), value.Type().Field(i).Name)
		}
		if !equal(other, other) {
			t.Errorf("%s is not reflexive", value.Type())
		}
	}
}

func setEqualityTestValue(value reflect.Value) {
	switch value.Kind() {
	case reflect.String:
		value.SetString("changed")
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Int, reflect.Int32:
		value.SetInt(1)
	case reflect.Struct:
		setEqualityTestValue(value.Field(0))
	case reflect.Pointer:
		value.Set(reflect.New(value.Type().Elem()))
	case reflect.Map:
		value.Set(reflect.MakeMap(value.Type()))
	case reflect.Slice:
		value.Set(reflect.MakeSlice(value.Type(), 1, 1))
	default:
		panic("add a fixture for " + value.Kind().String())
	}
}

func checkEqualityPairs[T any](t *testing.T, equal func(T, T) bool, pairs [][2]T) {
	t.Helper()
	for _, pair := range pairs {
		if got, want := equal(pair[0], pair[1]), reflect.DeepEqual(pair[0], pair[1]); got != want {
			t.Errorf("Equals(%#v, %#v)=%v, want %v", pair[0], pair[1], got, want)
		}
	}
}
