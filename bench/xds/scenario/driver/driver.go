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

// Package driver defines the Kubernetes orchestration side of a scenario.
// Load processes do not import this package or concrete scenario driver packages.
package driver

import (
	"context"
	"encoding/json"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/openkruise/agentio/bench/xds/loadapi"
)

// RunLabel identifies Kubernetes resources owned by a benchmark run.
const RunLabel = "bench.agentio.io/run"

// Resource identifies a Kubernetes object tracked for cleanup.
type Resource struct {
	GVR       schema.GroupVersionResource `json:"gvr"`
	Namespace string                      `json:"namespace,omitempty"`
	Name      string                      `json:"name"`
}

// Environment provides the clients and resource ownership of a benchmark run.
type Environment struct {
	Namespace string
	Pods      []string
	Kube      kubernetes.Interface
	Dynamic   dynamic.Interface
	// Track BEFORE attempting creation of cluster resources. Cleanup verifies RunLabel.
	// Resources inside Namespace are already covered by namespace deletion.
	Track func(Resource)
}

// Driver orchestrates one run; its methods are called sequentially.
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
