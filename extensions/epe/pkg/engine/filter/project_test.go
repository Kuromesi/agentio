// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package filter

import (
	"encoding/json"
	"errors"
	"testing"
)

// A payload key that no registration claims is not an error and not a
// config: the unit simply does not mount that filter. Absence is expressed
// by the map, not by a sentinel error.
func TestProjectSkipsMissingKeys(t *testing.T) {
	regs := []Registration{
		{Name: "a", Parse: func(json.RawMessage) (any, error) { return "A", nil }},
		{Name: "b", Parse: func(json.RawMessage) (any, error) { return "B", nil }},
	}
	cfgs, errs := Project(regs, map[string]json.RawMessage{"b": []byte(`{}`)})
	if cfgs[0] != nil {
		t.Errorf("cfgs[0] = %v, want nil for the unclaimed filter", cfgs[0])
	}
	if cfgs[1] != "B" {
		t.Errorf("cfgs[1] = %v, want B", cfgs[1])
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("errs[%d] = %v, want nil", i, err)
		}
	}
}

// A parse failure on a key that IS present is a malformed unit and must
// surface, so the binder can fail the request closed.
func TestProjectReportsParseErrors(t *testing.T) {
	boom := errors.New("boom")
	regs := []Registration{
		{Name: "a", Parse: func(json.RawMessage) (any, error) { return nil, boom }},
	}
	cfgs, errs := Project(regs, map[string]json.RawMessage{"a": []byte(`{}`)})
	if cfgs[0] != nil {
		t.Errorf("cfgs[0] = %v, want nil on error", cfgs[0])
	}
	if !errors.Is(errs[0], boom) {
		t.Errorf("errs[0] = %v, want boom", errs[0])
	}
}

// Project must hand each registration exactly its own key's bytes.
func TestProjectRoutesPayloadsByName(t *testing.T) {
	var gotA, gotB string
	regs := []Registration{
		{Name: "a", Parse: func(raw json.RawMessage) (any, error) { gotA = string(raw); return nil, nil }},
		{Name: "b", Parse: func(raw json.RawMessage) (any, error) { gotB = string(raw); return nil, nil }},
	}
	Project(regs, map[string]json.RawMessage{"a": []byte(`{"x":1}`), "b": []byte(`{"y":2}`)})
	if gotA != `{"x":1}` || gotB != `{"y":2}` {
		t.Errorf("routing wrong: a=%q b=%q", gotA, gotB)
	}
}
