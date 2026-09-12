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

package gatewaydeployer

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

const agentgatewayConfigKey = "config.yaml"

type agentgatewayAvailability struct {
	Autoscaling      autoscalingv2.HorizontalPodAutoscalerSpec
	DisruptionBudget policyv1.PodDisruptionBudgetSpec
}

// AgentgatewayAvailability validates values before any generated child is applied.
// A data method keeps the template parseable by both deployer and injector.
func (in derivedInput) AgentgatewayAvailability() (agentgatewayAvailability, error) {
	var result agentgatewayAvailability
	config := struct {
		ReplicaCount int32 `json:"replicaCount"`
		Autoscaling  struct {
			MinReplicas                    *int32 `json:"minReplicas"`
			MaxReplicas                    *int32 `json:"maxReplicas"`
			TargetCPUUtilizationPercentage int32  `json:"targetCPUUtilizationPercentage"`
		} `json:"autoscaling"`
		PodDisruptionBudget struct {
			MaxUnavailable intstr.IntOrString `json:"maxUnavailable"`
		} `json:"podDisruptionBudget"`
	}{ReplicaCount: 1}
	config.Autoscaling.TargetCPUUtilizationPercentage = 80
	config.PodDisruptionBudget.MaxUnavailable = intstr.FromInt32(1)
	global, _ := in.Values["global"].(map[string]any)
	data, err := json.Marshal(global["agentgateway"])
	if err != nil {
		return result, fmt.Errorf("invalid agentgateway availability values: %w", err)
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return result, fmt.Errorf("invalid agentgateway availability values: %w", err)
	}
	minReplicas := ptr.Deref(config.Autoscaling.MinReplicas, config.ReplicaCount)
	maxReplicas := ptr.Deref(config.Autoscaling.MaxReplicas, config.ReplicaCount)
	if config.ReplicaCount < 1 || minReplicas < 1 || maxReplicas < minReplicas {
		return result, fmt.Errorf("agentgateway requires replicaCount >= 1 and 1 <= autoscaling.minReplicas <= autoscaling.maxReplicas (unset bounds use replicaCount)")
	}
	if config.Autoscaling.TargetCPUUtilizationPercentage < 1 {
		return result, fmt.Errorf("agentgateway autoscaling.targetCPUUtilizationPercentage must be positive")
	}
	budget := config.PodDisruptionBudget.MaxUnavailable
	if (budget.Type == intstr.Int && budget.IntVal < 0) ||
		(budget.Type == intstr.String && !regexp.MustCompile(`^(100|[0-9]{1,2})%$`).MatchString(budget.StrVal)) {
		return result, fmt.Errorf("agentgateway podDisruptionBudget.maxUnavailable must be a non-negative integer or a percentage from 0%% to 100%%")
	}
	result.Autoscaling = autoscalingv2.HorizontalPodAutoscalerSpec{
		ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Name: in.DeploymentName},
		MinReplicas:    &minReplicas, MaxReplicas: maxReplicas,
		Metrics: []autoscalingv2.MetricSpec{{
			Type: autoscalingv2.ResourceMetricSourceType,
			Resource: &autoscalingv2.ResourceMetricSource{
				Name:   corev1.ResourceCPU,
				Target: autoscalingv2.MetricTarget{Type: autoscalingv2.UtilizationMetricType, AverageUtilization: &config.Autoscaling.TargetCPUUtilizationPercentage},
			},
		}},
	}
	result.DisruptionBudget = policyv1.PodDisruptionBudgetSpec{
		MaxUnavailable: &budget,
		Selector:       &metav1.LabelSelector{MatchLabels: map[string]string{in.GatewayNameLabel: in.Name}},
	}
	return result, nil
}

// An Available old ReplicaSet does not mean a newly supplied config is ready.
func agentgatewayRolloutReady(deployment *appsv1.Deployment, hash string) bool {
	replicas := int32(1)
	if deployment.Spec.Replicas != nil {
		replicas = *deployment.Spec.Replicas
	}
	return deployment.Spec.Template.Annotations["gateway.agentio.kruise.io/config-hash"] == hash &&
		deployment.Status.ObservedGeneration >= deployment.Generation &&
		deployment.Status.UpdatedReplicas == replicas && deployment.Status.Replicas == replicas &&
		deployment.Status.AvailableReplicas == replicas
}

// agentgatewayInput deliberately does not interpret Envoy's EgressGateway
// config. The new class uses native agentgateway file configuration, not xDS.
func (d *DeploymentController) agentgatewayInput(input *TemplateInput) error {
	if input.Spec.Infrastructure == nil || input.Spec.Infrastructure.ParametersRef == nil {
		return fmt.Errorf("agentgateway requires spec.infrastructure.parametersRef to a ConfigMap containing %s", agentgatewayConfigKey)
	}
	ref := input.Spec.Infrastructure.ParametersRef
	if ref.Group != "" || ref.Kind != "ConfigMap" {
		return fmt.Errorf("agentgateway parametersRef must reference a core ConfigMap in the Gateway namespace")
	}
	cm := d.clients.ConfigMaps.Get(string(ref.Name), input.Namespace)
	if cm == nil {
		return fmt.Errorf("agentgateway ConfigMap %s/%s not found", input.Namespace, ref.Name)
	}
	content := cm.Data[agentgatewayConfigKey]
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("agentgateway ConfigMap %s/%s must contain non-empty data[%q]", input.Namespace, ref.Name, agentgatewayConfigKey)
	}
	// Syntax checking catches broken YAML before rollout. Schema validation is
	// performed by the pinned agentgateway binary when the new Pod starts.
	var config map[string]any
	if err := yaml.UnmarshalStrict([]byte(content), &config); err != nil {
		return fmt.Errorf("agentgateway config must be a YAML object: %w", err)
	}
	if config == nil {
		return fmt.Errorf("agentgateway config must be a YAML object")
	}
	input.AgentgatewayConfigName = cm.Name
	input.AgentgatewayConfigHash = fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	return nil
}

func (d *DeploymentController) setGatewayConfigError(gw gatewayv1.Gateway, configErr error) error {
	patch := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Conditions []metav1.Condition `json:"conditions"`
		} `json:"status"`
	}{APIVersion: gatewayv1.GroupVersion.String(), Kind: "Gateway"}
	patch.Status.Conditions = []metav1.Condition{
		gatewayCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionAccepted), metav1.ConditionFalse,
			gw.Generation, string(gatewayv1.GatewayReasonInvalidParameters), configErr.Error()),
		gatewayCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), metav1.ConditionFalse,
			gw.Generation, string(gatewayv1.GatewayReasonInvalid), configErr.Error()),
	}
	data, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	return d.clients.Patcher(gatewayGVR, gw.Name, gw.Namespace, data, "status")
}

// AgentgatewayCAAddress resolves CA bootstrap on demand. Using a template data
// method keeps this shared template parseable by the sidecar injector as well.
func (in derivedInput) AgentgatewayCAAddress() (string, error) {
	return agentgatewayCAAddress(nestedString(in.Values, "global", "caAddress"))
}

// agentgatewayCAAddress follows Istio's CA_ADDRESS bootstrap convention while
// requiring TLS for the bearer credential sent to Agentiod.
func agentgatewayCAAddress(address string) (string, error) {
	if address == "" {
		return "", fmt.Errorf("agentgateway CA requires global.caAddress")
	}
	if !strings.Contains(address, "://") {
		address = "https://" + address
	}
	u, err := url.Parse(address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("agentgateway CA address must be an HTTPS endpoint without credentials, query or path")
	}
	return strings.TrimSuffix(address, "/"), nil
}
