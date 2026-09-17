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

package driver

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/openkruise/agentio/bench/xds/loadapi"
	"github.com/openkruise/agentio/bench/xds/scenario/discovery"
	"github.com/openkruise/agentio/bench/xds/scenario/driver"
)

type discoveryDriver struct{ options discovery.Options }

// New creates a discovery driver without managed update rounds.
func New(raw json.RawMessage) (driver.Driver, error) {
	cfg, err := discovery.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &discoveryDriver{options: cfg}, nil
}
func (d *discoveryDriver) ClientConfig(_, _ string) (json.RawMessage, error) {
	return json.Marshal(d.options)
}
func (d *discoveryDriver) Prepare(context.Context, driver.Environment) error { return nil }
func (d *discoveryDriver) Rounds(int) ([]json.RawMessage, error)             { return nil, nil }
func (d *discoveryDriver) Trigger(context.Context, driver.Environment, json.RawMessage) error {
	return errors.New("discovery has no update rounds")
}
func (d *discoveryDriver) Check(json.RawMessage, []loadapi.Status, []loadapi.Status) (map[string]any, error) {
	return nil, nil
}
