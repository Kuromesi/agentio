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
package bypass

import (
	"context"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

func TestBypassSkipsFollowingRules(t *testing.T) {
	f := New(filter.RuleConfig[Config]{})
	act, err := f.OnRequestHeaders(context.Background(), &filter.Stream{})
	if err != nil {
		t.Fatalf("OnRequestHeaders: %v", err)
	}
	if act.Kind() != filter.KindBypass {
		t.Fatalf("Kind = %v, want KindBypass", act.Kind())
	}
	if _, ok := act.Reply(); ok {
		t.Error("bypass unexpectedly carried a local reply")
	}
}
