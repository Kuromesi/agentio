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

package extproc

import (
	"context"
	"fmt"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func Objects(controlPlaneNamespace, image string) []*unstructured.Unstructured {
	serviceLabels := map[string]any{"app": "ext-proc", "service": "ext-proc"}
	podLabels := map[string]any{"app": "ext-proc"}
	service := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Service",
		"metadata": map[string]any{"name": "ext-proc", "namespace": controlPlaneNamespace, "labels": serviceLabels},
		"spec": map[string]any{
			"selector": map[string]any{"app": "ext-proc"},
			"ports": []any{map[string]any{
				"name": "grpc", "port": int64(9002), "targetPort": int64(9002), "protocol": "TCP",
			}},
		},
	}}
	deployment := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": "ext-proc", "namespace": controlPlaneNamespace, "labels": podLabels},
		"spec": map[string]any{
			"replicas": int64(1),
			"selector": map[string]any{"matchLabels": map[string]any{"app": "ext-proc"}},
			"template": map[string]any{
				"metadata": map[string]any{"labels": podLabels},
				"spec": map[string]any{"containers": []any{map[string]any{
					"name": "ext-proc", "image": image, "imagePullPolicy": "IfNotPresent",
					"env": []any{
						map[string]any{"name": "REQUEST_HEADERS_TO_ADD", "value": "x-hello-to-ext-proc=true"},
						map[string]any{"name": "RESPONSE_HEADERS_TO_ADD", "value": "x-hello-from-ext-proc=true"},
					},
					"resources": map[string]any{
						"requests": map[string]any{"cpu": "50m", "memory": "64Mi"},
						"limits":   map[string]any{"cpu": "500m", "memory": "256Mi"},
					},
					"ports": []any{map[string]any{"name": "grpc", "containerPort": int64(9002), "protocol": "TCP"}},
				}}},
			},
		},
	}}
	return []*unstructured.Unstructured{service, deployment}
}

func Setup(controlPlaneNamespace, image string) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		scope := kube.NewResourceScope(environment.Kube)
		var deployment kube.ResourceRecord
		for _, object := range Objects(controlPlaneNamespace, image) {
			record, err := scope.Apply(ctx, object, kube.CreateOnly)
			if err != nil {
				return nil, fmt.Errorf("apply ext-proc %s: %w", object.GetKind(), err)
			}
			if object.GetKind() == "Deployment" {
				deployment = record
			}
		}
		waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if err := environment.Kube.Wait(waitCtx, deployment.GVR, controlPlaneNamespace, "ext-proc", func(live *unstructured.Unstructured) (bool, error) {
			available, found, err := unstructured.NestedInt64(live.Object, "status", "availableReplicas")
			return found && available >= 1, err
		}); err != nil {
			return nil, fmt.Errorf("wait for ext-proc Deployment: %w", err)
		}
		return func(cleanupCtx context.Context) error {
			if environment.Retaining() {
				return nil
			}
			return scope.DeleteReverse(cleanupCtx)
		}, nil
	}
}
