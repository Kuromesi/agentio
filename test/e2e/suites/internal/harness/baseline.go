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

package harness

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/kube"
)

// ConfigMapName is the Agentio primary configuration ConfigMap every suite
// owns as its policy baseline.
const ConfigMapName = "agentio-config-primary"

// SetupBaseline installs the passthrough baseline ConfigMap and removes it on
// cleanup unless the run retains resources.
func SetupBaseline(controlPlaneNamespace string) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		if _, err := environment.Kube.Apply(ctx, BaselineObject(controlPlaneNamespace), kube.CreateOnly); err != nil {
			return nil, fmt.Errorf("apply Agentio baseline: %w", err)
		}
		return func(cleanupCtx context.Context) error {
			if environment.Retaining() {
				return nil
			}
			gvr := schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
			record, found := environment.Kube.Ledger().Find(gvr, controlPlaneNamespace, ConfigMapName)
			if !found {
				return fmt.Errorf("clean Agentio baseline: ownership ledger entry not found")
			}
			return environment.Kube.DeleteOwned(cleanupCtx, record)
		}, nil
	}
}

// BaselineObject is the passthrough egress baseline with the shared egress
// gateway registration.
func BaselineObject(controlPlaneNamespace string) *unstructured.Unstructured {
	config := "egressGateways:\n- namespace: " + controlPlaneNamespace + "\n  name: egress-gateway\negressPolicies:\n- policy: PASSTHROUGH\n"
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name": ConfigMapName, "namespace": controlPlaneNamespace,
		},
		"data": map[string]any{"config": config},
	}}
}

// RestoreBaseline reconciles the baseline ConfigMap back to its passthrough
// content after a scenario mutated it.
func (h *Harness) RestoreBaseline(ctx context.Context, environment *e2e.Environment) error {
	if environment == nil || environment.Kube == nil {
		return fmt.Errorf("restore Agentio baseline requires a Kubernetes environment")
	}
	namespaceName := h.Config.Namespace
	gvr := schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
	mode := kube.ReconcileOwned
	if _, err := environment.Kube.Get(ctx, gvr, namespaceName, ConfigMapName); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("read Agentio baseline before restore: %w", err)
		}
		mode = kube.CreateOnly
	}
	if _, err := environment.Kube.Apply(ctx, BaselineObject(namespaceName), mode); err != nil {
		return fmt.Errorf("restore Agentio baseline: %w", err)
	}
	return nil
}
