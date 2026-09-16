// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"

	"github.com/openkruise/agentio/bench/xds/scenario"
	"github.com/openkruise/agentio/bench/xds/scenario/discovery"
	"github.com/openkruise/agentio/bench/xds/scenario/trafficpolicy"
)

func newScenario(name string, config json.RawMessage) (scenario.ClientFactory, error) {
	switch name {
	case "discovery":
		return discovery.New(config)
	case "trafficpolicy":
		return trafficpolicy.New(config)
	default:
		return scenario.ClientFactory{}, fmt.Errorf("unknown scenario %q (available: discovery, trafficpolicy)", name)
	}
}
