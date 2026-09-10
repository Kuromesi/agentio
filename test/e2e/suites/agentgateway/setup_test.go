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

package agentgateway

import (
	"context"
	"fmt"
	"github.com/openkruise/agentio/test/e2e"
	native "github.com/openkruise/agentio/test/e2e/components/agentgateway"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const gatewayName = "egress-gateway"
const marker = native.Marker

var gateways = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}
var configmaps = schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
var deployments = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}

func requireGatewayAPI(ctx context.Context, env *e2e.Environment) (e2e.CleanupFunc, error) {
	_, err := env.Cluster.Dynamic.Resource(gateways).Namespace(config.Namespace).List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return nil, fmt.Errorf("install Gateway API v1.4.1 standard CRDs before running this suite: %w", err)
	}
	return nil, nil
}
func gateway(name string) *unstructured.Unstructured { return native.Gateway(config.Namespace, name) }
func configuration(name, content string) *unstructured.Unstructured {
	return native.Configuration(config.Namespace, name, content)
}
func nativeConfig(version string, ext bool) string {
	var p map[string]any
	if ext {
		p = native.ExtProc("ext-proc."+config.Namespace+".svc.cluster.local:9002", nil)
	}
	return native.NativeConfig(version, p)
}
func setupGateway(ctx context.Context, env *e2e.Environment) (e2e.CleanupFunc, error) {
	cleanup, err := native.Setup(config.Namespace, nativeConfig("baseline", false))(ctx, env)
	if err != nil {
		return cleanup, err
	}
	return cleanup, rig.VerifyTrafficFixture(ctx, env, &traffic)
}
func waitGateway(ctx context.Context, env *e2e.Environment, name, accepted, programmed string) error {
	return native.WaitGateway(ctx, env, config.Namespace, name, accepted, programmed)
}
