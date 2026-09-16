// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

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
