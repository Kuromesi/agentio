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
	return driver.Environment{
		Namespace: r.id,
		Pods:      r.pods,
		Kube:      r.kube,
		Dynamic:   r.dynamic,
		Track:     func(resource driver.Resource) { r.resources = append(r.resources, resource) },
	}
}
