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
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/components/namespace"
	"github.com/openkruise/agentio/test/e2e/retry"
)

const (
	DataplaneModeLabel = agentiocomponent.DataplaneModeLabel
	WorkloadClassLabel = "e2e.agentio.io/workload-class"

	GatewayPodSelector = "gateway.networking.k8s.io/gateway-name=egress-gateway"
	EPEPodSelector     = "app.kubernetes.io/name=agentio-epe"
	ZtunnelPodSelector = "app.kubernetes.io/name=ztunnel"
)

// DataplaneNamespaceConfig enrolls a namespace in the selected Agentio
// dataplane. Workloads in the namespace do not need profile-specific metadata.
func DataplaneNamespaceConfig(profile, prefix string) (namespace.Config, error) {
	switch profile {
	case agentiocomponent.ProfileSidecar, agentiocomponent.ProfileAmbient:
		return namespace.Config{
			Prefix: prefix,
			Labels: map[string]string{DataplaneModeLabel: profile},
		}, nil
	default:
		return namespace.Config{}, fmt.Errorf("unsupported Agentio dataplane profile %q", profile)
	}
}

func selectZtunnelPod(workload corev1.Pod, candidates []corev1.Pod) (corev1.Pod, error) {
	if workload.Spec.NodeName == "" {
		return corev1.Pod{}, fmt.Errorf("workload Pod %s/%s is not assigned to a node", workload.Namespace, workload.Name)
	}
	for _, candidate := range candidates {
		if candidate.Spec.NodeName == workload.Spec.NodeName {
			return candidate, nil
		}
	}
	return corev1.Pod{}, fmt.Errorf("no ready ztunnel found on workload node %q", workload.Spec.NodeName)
}

// ClientCapabilities are the Pod capabilities client-side fixtures need for
// raw-socket protocol scenarios.
func ClientCapabilities() []corev1.Capability {
	return []corev1.Capability{"NET_ADMIN", "NET_RAW"}
}

// TrafficFixture is the shared echo layout used by the sandbox traffic
// domains. Its namespace, rather than each Pod, owns dataplane enrollment.
type TrafficFixture struct {
	Namespace      namespace.Instance
	Client         echo.Instance
	Server         echo.Instance
	AnotherServer  echo.Instance
	WorkloadTarget echo.Instance
}

func (f *TrafficFixture) SetupNamespace(profile string) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		config, err := DataplaneNamespaceConfig(profile, "sandbox")
		if err != nil {
			return nil, err
		}
		instance, cleanup, err := namespace.Apply(ctx, environment, config)
		if err != nil {
			return nil, err
		}
		f.Namespace = instance
		return cleanup, nil
	}
}

func (f *TrafficFixture) SetupEcho(name string, replicas int, capabilities []corev1.Capability) e2e.SetupFunc {
	return func(ctx context.Context, environment *e2e.Environment) (e2e.CleanupFunc, error) {
		config := echo.Config{
			Name: name, Namespace: f.Namespace.Name(), Replicas: replicas,
			Image: echo.DefaultImage, Ports: echo.DefaultPorts(), CallTimeout: 90 * time.Second, Converge: 3,
			Labels:       map[string]string{"app": name, WorkloadClassLabel: name},
			Capabilities: capabilities,
		}
		instance, cleanup, err := echo.Apply(ctx, environment, config)
		if err != nil {
			return nil, err
		}
		switch name {
		case "client":
			f.Client = instance
		case "server":
			f.Server = instance
		case "another-server":
			f.AnotherServer = instance
		case "workload-target":
			f.WorkloadTarget = instance
		default:
			return nil, fmt.Errorf("unknown shared echo fixture %q", name)
		}
		return cleanup, nil
	}
}

// VerifyTrafficFixture exercises the client-to-server baseline call and the
// serving ztunnel's admin surface so scenarios start from a proven-good fixture.
func (h *Harness) VerifyTrafficFixture(ctx context.Context, environment *e2e.Environment, fixture *TrafficFixture) error {
	if err := agentiocomponent.VerifyFirewallBackend(ctx, environment, h.Config); err != nil {
		return fmt.Errorf("verify firewall backend: %w", err)
	}
	options, err := fixture.Server.CallOptions("http")
	if err != nil {
		return err
	}
	options.Check = check.OK()
	if _, err := fixture.Client.Call(ctx, options); err != nil {
		return fmt.Errorf("shared echo baseline: %w", err)
	}
	if h.Config.Profile == agentiocomponent.ProfileAmbient {
		for _, instance := range []echo.Instance{fixture.Client, fixture.Server, fixture.AnotherServer, fixture.WorkloadTarget} {
			if err := verifyAmbientRedirection(ctx, environment, instance); err != nil {
				return err
			}
		}
	}
	if _, err := configDump(ctx, environment, h.Config, fixture.Client); err != nil {
		return fmt.Errorf("shared ztunnel config dump: %w", err)
	}
	return nil
}

// ConfigDump fetches the ztunnel Envoy config dump serving an echo workload.
// Sidecar mode reaches the in-Pod admin port; ambient mode executes the admin
// request in the node-level ztunnel scheduled beside the workload.
func (h *Harness) ConfigDump(ctx context.Context, environment *e2e.Environment, instance echo.Instance) (string, error) {
	return configDump(ctx, environment, h.Config, instance)
}

func configDump(ctx context.Context, environment *e2e.Environment, config agentiocomponent.Config, instance echo.Instance) (string, error) {
	switch config.Profile {
	case agentiocomponent.ProfileSidecar:
		return sidecarConfigDump(ctx, instance)
	case agentiocomponent.ProfileAmbient:
		return ambientConfigDump(ctx, environment, config.Namespace, instance)
	default:
		return "", fmt.Errorf("unsupported Agentio dataplane profile %q", config.Profile)
	}
}

func sidecarConfigDump(ctx context.Context, instance echo.Instance) (string, error) {
	result, err := instance.Call(ctx, echo.CallOptions{
		Protocol: echo.HTTP, Address: "localhost", Port: 15000, Path: "/config_dump",
		Count: 1, Timeout: 5 * time.Second, Check: check.OK(),
		Retry: retry.Policy{
			Timeout: 5 * time.Second, Delay: 100 * time.Millisecond,
			Backoff: 1.5, MaxDelay: time.Second, Converge: 1,
		},
	})
	if err != nil {
		return "", fmt.Errorf("request ztunnel config dump: %w; attempts: %+v", err, result.Attempts)
	}
	if len(result.Responses) != 1 {
		return "", fmt.Errorf("config dump returned %d responses", len(result.Responses))
	}
	return result.Responses[0].RawContent, nil
}

func ambientConfigDump(ctx context.Context, environment *e2e.Environment, controlPlaneNamespace string, instance echo.Instance) (string, error) {
	if environment == nil || environment.Cluster == nil || environment.Cluster.Kube == nil || environment.Kube == nil {
		return "", fmt.Errorf("ambient config dump requires an E2E Kubernetes environment")
	}
	pods := instance.Pods()
	if len(pods) == 0 {
		return "", fmt.Errorf("echo instance %s has no ready workload Pod", instance.Name())
	}
	workload, err := environment.Cluster.Kube.CoreV1().Pods(instance.Namespace()).Get(ctx, pods[0], metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get workload Pod %s/%s: %w", instance.Namespace(), pods[0], err)
	}
	candidates, err := environment.Kube.ReadyPods(ctx, controlPlaneNamespace, ZtunnelPodSelector)
	if err != nil {
		return "", fmt.Errorf("list ambient ztunnel Pods: %w", err)
	}
	ztunnel, err := selectZtunnelPod(*workload, candidates)
	if err != nil {
		return "", err
	}
	stdout, stderr, err := environment.Kube.Exec(ctx, controlPlaneNamespace, ztunnel.Name, "ztunnel",
		[]string{"curl", "-sS", "localhost:15000/config_dump"}, nil)
	if err != nil {
		return "", fmt.Errorf("request config dump from ambient ztunnel %s/%s: %w; stderr: %s",
			controlPlaneNamespace, ztunnel.Name, err, stderr)
	}
	projected, err := projectAmbientConfigDump([]byte(stdout), workload.Namespace, workload.Name)
	if err != nil {
		return "", fmt.Errorf("project ambient ztunnel config dump for %s/%s: %w", workload.Namespace, workload.Name, err)
	}
	return projected, nil
}

func projectAmbientConfigDump(raw []byte, workloadNamespace, workloadName string) (string, error) {
	var dump struct {
		Policies  []json.RawMessage `json:"policies"`
		Workloads []json.RawMessage `json:"workloads"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		return "", fmt.Errorf("decode ambient ztunnel config dump: %w", err)
	}

	var selected json.RawMessage
	policyReferences := map[string]struct{}{}
	for _, rawWorkload := range dump.Workloads {
		var workload struct {
			Name                  string   `json:"name"`
			Namespace             string   `json:"namespace"`
			AuthorizationPolicies []string `json:"authorizationPolicies"`
		}
		if err := json.Unmarshal(rawWorkload, &workload); err != nil {
			return "", fmt.Errorf("decode ambient workload: %w", err)
		}
		if workload.Namespace != workloadNamespace || workload.Name != workloadName {
			continue
		}
		selected = rawWorkload
		for _, reference := range workload.AuthorizationPolicies {
			policyReferences[reference] = struct{}{}
		}
		break
	}
	if selected == nil {
		return "", fmt.Errorf("workload %s/%s is absent from ambient ztunnel config dump", workloadNamespace, workloadName)
	}

	policies := make([]json.RawMessage, 0, len(policyReferences))
	for _, rawPolicy := range dump.Policies {
		var policy struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			Scope     string `json:"scope"`
		}
		if err := json.Unmarshal(rawPolicy, &policy); err != nil {
			return "", fmt.Errorf("decode ambient policy: %w", err)
		}
		_, referenced := policyReferences[policy.Namespace+"/"+policy.Name]
		if referenced || policy.Scope == "Global" {
			policies = append(policies, rawPolicy)
		}
	}

	projected, err := json.Marshal(struct {
		Workload json.RawMessage   `json:"workload"`
		Policies []json.RawMessage `json:"policies"`
	}{Workload: selected, Policies: policies})
	if err != nil {
		return "", fmt.Errorf("encode workload-scoped ambient config dump: %w", err)
	}
	return string(projected), nil
}

func verifyAmbientRedirection(ctx context.Context, environment *e2e.Environment, instance echo.Instance) error {
	if environment == nil || environment.Cluster == nil || environment.Cluster.Kube == nil {
		return fmt.Errorf("ambient redirection verification requires a typed Kubernetes client")
	}
	for _, podName := range instance.Pods() {
		pod, err := environment.Cluster.Kube.CoreV1().Pods(instance.Namespace()).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("get ambient workload Pod %s/%s: %w", instance.Namespace(), podName, err)
		}
		if got := pod.Annotations["ambient.istio.io/redirection"]; got != "enabled" {
			return fmt.Errorf("ambient workload Pod %s/%s redirection annotation = %q, want enabled", instance.Namespace(), podName, got)
		}
	}
	return nil
}
