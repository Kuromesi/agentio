// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"encoding/json"
	"errors"
	"strings"

	ads "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/openkruise/agentio/bench/xds/scenario"
)

const Name = "discovery"

func init() {
	scenario.Register(Name, New)
}

type Options struct {
	Types []string `json:"types"`
}

func Parse(raw json.RawMessage) (Options, error) {
	cfg := Options{Types: []string{"type.googleapis.com/istio.workload.Address"}}
	if err := scenario.Decode(raw, &cfg); err != nil {
		return cfg, err
	}
	if len(cfg.Types) == 0 {
		return cfg, errors.New("types must not be empty")
	}
	seen := map[string]bool{}
	for _, typ := range cfg.Types {
		if strings.TrimSpace(typ) == "" || seen[typ] {
			return cfg, errors.New("type URLs must be nonempty and unique")
		}
		seen[typ] = true
	}
	return cfg, nil
}
func New(raw json.RawMessage) (scenario.ClientFactory, error) {
	cfg, err := Parse(raw)
	if err != nil {
		return scenario.ClientFactory{}, err
	}
	return scenario.ClientFactory{New: func() scenario.Client {
		c := &client{seen: map[string]bool{}}
		for _, typ := range cfg.Types {
			c.subscriptions = append(c.subscriptions, scenario.Subscription{TypeURL: typ})
			c.seen[typ] = false
		}
		return c
	}}, nil
}

type client struct {
	subscriptions []scenario.Subscription
	seen          map[string]bool
}

func (c *client) Subscriptions() []scenario.Subscription { return c.subscriptions }
func (c *client) Observe(response *ads.DeltaDiscoveryResponse, _ any) (scenario.Observation, error) {
	if _, ok := c.seen[response.TypeUrl]; ok {
		c.seen[response.TypeUrl] = true
	}
	ready := true
	for _, seen := range c.seen {
		ready = ready && seen
	}
	return scenario.Observation{Ready: ready}, nil
}
