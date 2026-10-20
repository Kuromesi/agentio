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
	"testing/synctest"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestDemandNotificationsStayWithResource(t *testing.T) {
	withSubscriptionClient(
		t,
		Watch{TypeURL: testType, OnDelete: func(string) DeleteAction { return ReleaseSubscription }},
		func(t *testing.T, c *Client) {
			a := beginDemand(t.Context(), c, "a")
			b := beginDemand(t.Context(), c, "alias-b")
			unrelated := c.types[testType].names["alias-b"].changed
			publishString(t, c, "a", "ready")
			if err := <-a; err != nil {
				t.Fatal(err)
			}
			select {
			case <-unrelated:
				t.Fatal("unrelated resource woke its waiter")
			default:
			}
			publishString(t, c, "b", "ready", "alias-b")
			if err := <-b; err != nil {
				t.Fatal(err)
			}
		},
	)
}

func TestDecodeDoesNotBlockDemandOrRetainReleasedInterest(t *testing.T) {
	entered, proceed := make(chan struct{}), make(chan struct{})
	watch := Watch{
		TypeURL: testType,
		Transform: func(a *anypb.Any) (any, error) {
			v := &wrapperspb.StringValue{}
			if err := a.UnmarshalTo(v); err != nil {
				return nil, err
			}
			if v.Value == "blocked" {
				close(entered)
				<-proceed
			}
			return v, nil
		},
	}
	withSubscriptionClient(t, watch, func(t *testing.T, c *Client) {
		hot := acquire(t, c, "hot")
		defer hot.Release()
		cold := acquire(t, c, "cold")
		publishString(t, c, "hot", "ready")
		blocked, err := anypb.New(wrapperspb.String("blocked"))
		if err != nil {
			t.Fatal(err)
		}
		unsolicited, err := anypb.New(wrapperspb.String("later"))
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			done <- c.apply(&discovery.DeltaDiscoveryResponse{
				TypeUrl: testType,
				Resources: []*discovery.Resource{
					{Name: "cold", Resource: blocked}, {Name: "new", Resource: unsolicited},
				},
			})
		}()
		<-entered
		// These calls must complete while Transform is blocked. synctest reports a
		// deadlock if the implementation still holds the global client mutex.
		if _, err := hot.Demand(t.Context()); err != nil {
			t.Fatal(err)
		}
		cold.Release()
		late := acquire(t, c, "new")
		defer late.Release()
		close(proceed)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		snapshot := c.Snapshot()
		if snapshot.Resources[testType]["cold"] != nil || snapshot.Resources[testType]["new"] != nil {
			t.Fatal("released or untransformed resource published")
		}
		if _, err := cold.Demand(t.Context()); !errors.Is(err, ErrReleased) {
			t.Fatal(err)
		}
		publishString(t, c, "new", "fresh")
		if _, err := late.Demand(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDemandNotificationsSurviveResetAndAliasReplacement(t *testing.T) {
	withSubscriptionClient(
		t,
		Watch{TypeURL: testType, OnDelete: func(string) DeleteAction { return ReleaseSubscription }},
		func(t *testing.T, c *Client) {
			lease := acquire(t, c, "alias")
			publishString(t, c, "old", "old", "alias")
			c.reset()
			done := make(chan error, 1)
			go func() {
				_, err := lease.Demand(t.Context())
				done <- err
			}()
			synctest.Wait()
			publishString(t, c, "unrelated", "unrelated")
			synctest.Wait()
			select {
			case err := <-done:
				t.Fatalf("old value served after partial resync: %v", err)
			default:
			}
			publishString(t, c, "replacement", "new", "alias")
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			value, err := lease.Demand(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			raw := &wrapperspb.StringValue{}
			if err := value.Value.(*anypb.Any).UnmarshalTo(raw); err != nil {
				t.Fatal(err)
			}
			if raw.Value != "new" {
				t.Fatal(raw.Value)
			}
			lease.Release()
		},
	)
}
