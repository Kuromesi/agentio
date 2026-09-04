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
package block

import (
	"context"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

func run(t *testing.T, cfg Config) filter.Action {
	t.Helper()
	f := New(filter.RuleConfig[Config]{Cfg: cfg})
	act, err := f.OnRequestHeaders(context.Background(), &filter.Stream{})
	if err != nil {
		t.Fatalf("OnRequestHeaders: %v", err)
	}
	return act
}

func TestBlockStopsWithConfiguredReply(t *testing.T) {
	act := run(t, Config{Status: 451, Body: "denied", HasBody: true})
	if act.Kind() != filter.KindStop {
		t.Fatalf("Kind = %v, want KindStop", act.Kind())
	}
	r, _ := act.Reply()
	if r.Status != 451 || string(r.Body) != "denied" {
		t.Errorf("Reply = %+v", r)
	}
}

func TestBlockDefaultStatus403(t *testing.T) {
	r, _ := run(t, Config{}).Reply()
	if r.Status != 403 {
		t.Errorf("Status = %d, want 403", r.Status)
	}
	if r.Body != nil {
		t.Errorf("Body = %q, want none when HasBody is false", r.Body)
	}
}
