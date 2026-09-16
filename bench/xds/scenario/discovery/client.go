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

package discovery

import (
	"encoding/json"
	"errors"
	"strings"

	ads "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	"github.com/openkruise/agentio/bench/xds/scenario"
)

// Options selects the resource types to subscribe to.
type Options struct {
	Types []string `json:"types"`
}

// Parse decodes options and validates resource type URLs.
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

// New creates clients that wait for an initial response for every subscribed type.
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
