// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"

	discovery "github.com/openkruise/agentio/bench/xds/scenario/discovery/driver"
	"github.com/openkruise/agentio/bench/xds/scenario/driver"
	trafficpolicy "github.com/openkruise/agentio/bench/xds/scenario/trafficpolicy/driver"
)

func newScenario(name string, config json.RawMessage) (driver.Driver, error) {
	switch name {
	case "discovery":
		return discovery.New(config)
	case "trafficpolicy":
		return trafficpolicy.New(config)
	default:
		return nil, fmt.Errorf("unknown scenario %q (available: discovery, trafficpolicy)", name)
	}
}

func (r *runner) environment() driver.Environment {
	return driver.Environment{Namespace: r.id, Pods: r.pods, Kube: r.kube, Dynamic: r.dynamic, Track: func(resource driver.Resource) { r.resources = append(r.resources, resource) }}
}
