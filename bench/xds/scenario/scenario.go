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

package scenario

import (
	"encoding/json"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/openkruise/agentio/bench/xds/loadapi"
)

// Subscription identifies a resource type and its initial subscribed names.
type Subscription struct {
	TypeURL string
	Names   []string
}

// Reply selects how the client responds to an ADS update.
type Reply uint8

// Reply actions include acknowledgment, rejection, and no response.
const (
	ACK Reply = iota
	NACK
	None
)

// Observation reports readiness, a reply, and an optional measurement for an update.
type Observation struct {
	Ready      bool
	Reply      Reply
	NACKReason string
	// A sample records successful ACK submission; the framework fills ID and timestamps.
	Sample *loadapi.Sample
}

// Client tracks one stream. Observe is called sequentially on that stream.
// expected is the immutable value produced by ClientFactory.PrepareRound, or nil initially.
type Client interface {
	Subscriptions() []Subscription
	Observe(*discovery.DeltaDiscoveryResponse, any) (Observation, error)
}

// ClientFactory holds immutable configuration. New must return a fresh client.
// PrepareRound runs once per process/round; its result is shared read-only by clients.
// A nil PrepareRound means this scenario has no managed update rounds.
type ClientFactory struct {
	New          func() Client
	PrepareRound func(json.RawMessage) (any, error)
}
