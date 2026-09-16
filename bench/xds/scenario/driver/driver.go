// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

// Package driver defines the Kubernetes orchestration side of a scenario.
// Load processes do not import this package or concrete scenario driver packages.
package driver

import (
	"context"
	"encoding/json"

	"github.com/openkruise/agentio/bench/xds/loadapi"
	"github.com/openkruise/agentio/bench/xds/scenario"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const RunLabel = "bench.agentio.io/run"

type Resource struct {
	GVR       schema.GroupVersionResource `json:"gvr"`
	Namespace string                      `json:"namespace,omitempty"`
	Name      string                      `json:"name"`
}
type Environment struct {
	Namespace string
	Pods      []string
	Kube      kubernetes.Interface
	Dynamic   dynamic.Interface
	// Track BEFORE attempting creation of cluster resources. Cleanup verifies RunLabel.
	// Resources inside Namespace are already covered by namespace deletion.
	Track func(Resource)
}

// Each run gets a separate Driver; its methods are called sequentially.
// Scenario parameters are opaque to the runner.
type Driver interface {
	// ClientConfig turns run options into the configuration for one load Pod.
	ClientConfig(namespace, pod string) (json.RawMessage, error)
	// Prepare runs after load Pods are ready, before any ADS streams are opened.
	Prepare(context.Context, Environment) error
	// Rounds enumerates updates for the current connection stage; nil skips updates.
	Rounds(repetitions int) ([]json.RawMessage, error)
	// Trigger runs after all clients have armed the round.
	Trigger(context.Context, Environment, json.RawMessage) error
	// Check compares statuses before and after an update and returns report fields.
	Check(parameters json.RawMessage, before, after []loadapi.Status) (map[string]any, error)
}

var drivers = scenario.NewRegistry[Driver]()

// Register is called by a driver package's init function. Invalid or duplicate
// registrations panic at startup; each New call still creates a fresh driver.
func Register(name string, factory scenario.Factory[Driver]) {
	if err := drivers.Register(name, factory); err != nil {
		panic(err)
	}
}

// New constructs an imported, registered driver for one run.
func New(name string, config json.RawMessage) (Driver, error) {
	return drivers.New(name, config)
}
