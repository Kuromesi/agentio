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

package xdsclient

import (
	"errors"
	"testing"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestTransformPublicationAndFailure(t *testing.T) {
	type projection struct{ Text string }
	calls, deletes := 0, 0
	failure := errors.New("invalid projected value")
	watch := Watch{
		TypeURL:  testType,
		Wildcard: true,
		OnDelete: func(string) DeleteAction {
			deletes++
			return ReleaseSubscription
		},
		Transform: func(wire *anypb.Any) (any, error) {
			calls++
			value := &wrapperspb.StringValue{}
			if err := wire.UnmarshalTo(value); err != nil {
				return nil, err
			}
			if value.Value == "bad" {
				return nil, failure
			}
			return &projection{Text: value.Value}, nil
		},
	}
	withSubscriptionClient(t, watch, func(t *testing.T, client *Client) {
		publishString(t, client, "a", "one")
		before := client.Snapshot()
		first := before.Resources[testType]["a"]
		if _, ok := first.Value.(*projection); !ok {
			t.Fatalf("raw payload cached: %T", first.Value)
		}
		for range 3 {
			value, err := client.Demand(t.Context(), testType, "a")
			if err != nil || value != first {
				t.Fatal(value, err)
			}
		}
		if calls != 1 {
			t.Fatal("transform ran during demand")
		}
		publishString(t, client, "a", "two")
		if first.Value.(*projection).Text != "one" {
			t.Fatal("prior publication mutated")
		}
		good, err := anypb.New(wrapperspb.String("new"))
		if err != nil {
			t.Fatal(err)
		}
		bad, err := anypb.New(wrapperspb.String("bad"))
		if err != nil {
			t.Fatal(err)
		}
		if err := client.apply(&discovery.DeltaDiscoveryResponse{TypeUrl: testType,
			Resources:        []*discovery.Resource{{Name: "b", Resource: good}, {Name: "c", Resource: bad}},
			RemovedResources: []string{"a"},
		}); !errors.Is(err, failure) {
			t.Fatal(err)
		}
		after := client.Snapshot()
		if !after.Synced[testType] || len(after.Resources[testType]) != 1 ||
			after.Resources[testType]["a"].Value.(*projection).Text != "two" ||
			deletes != 0 {
			t.Fatal("failed transform partially published or released subscription")
		}
		publishString(t, client, "a", "recovered")
		if _, ready := client.Observe(testType); !ready {
			t.Fatal("valid update did not recover")
		}
	})
}
