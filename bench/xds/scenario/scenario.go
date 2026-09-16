// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package scenario

import (
	"encoding/json"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/openkruise/agentio/bench/xds/loadapi"
)

type Subscription struct {
	TypeURL string
	Names   []string
}
type Reply uint8

const (
	ACK Reply = iota
	NACK
	None
)

type Observation struct {
	Ready      bool
	Reply      Reply
	NACKReason string
	// A sample records successful ACK submission; the framework fills ID and timestamps.
	Sample *loadapi.Sample
}

// Each stream has its own Client. Observe is called sequentially on that stream.
// expected is the immutable value produced by ClientFactory.PrepareRound, or nil initially.
type Client interface {
	Subscriptions() []Subscription
	Observe(*discovery.DeltaDiscoveryResponse, any) (Observation, error)
}

// Factories hold only immutable configuration. New must return a fresh client.
// PrepareRound runs once per process/round; its result is shared read-only by clients.
// A nil PrepareRound means this scenario has no managed update rounds.
type ClientFactory struct {
	New          func() Client
	PrepareRound func(json.RawMessage) (any, error)
}

var clients = NewRegistry[ClientFactory]()

// Register is called by a scenario package's init function. Invalid or duplicate
// registrations panic at startup; only factories are stored, never client state.
func Register(name string, factory Factory[ClientFactory]) {
	if err := clients.Register(name, factory); err != nil {
		panic(err)
	}
}

// New constructs a client factory for an imported, registered scenario.
func New(name string, config json.RawMessage) (ClientFactory, error) {
	return clients.New(name, config)
}
