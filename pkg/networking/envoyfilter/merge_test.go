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

package envoyfilter

import (
	"testing"
	"time"

	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestMergeAppendsListsAndReplacesDuration(t *testing.T) {
	destination := &hcmv3.HttpConnectionManager{
		RequestTimeout: durationpb.New(30 * time.Second),
		HttpFilters:    []*hcmv3.HttpFilter{{Name: "existing"}},
	}
	patch := &hcmv3.HttpConnectionManager{
		RequestTimeout: durationpb.New(5 * time.Second),
		HttpFilters:    []*hcmv3.HttpFilter{{Name: "added"}},
	}

	Merge(destination, patch)
	if got := destination.GetRequestTimeout().AsDuration(); got != 5*time.Second {
		t.Fatalf("request timeout = %v, want 5s", got)
	}
	if len(destination.HttpFilters) != 2 || destination.HttpFilters[0].Name != "existing" || destination.HttpFilters[1].Name != "added" {
		t.Fatalf("HTTP filters = %+v", destination.HttpFilters)
	}
}
