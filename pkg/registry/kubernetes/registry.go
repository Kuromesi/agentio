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

package kubernetes

import (
	"fmt"
	"strings"
	"time"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/registry/kubernetes/kruise"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
)

const defaultClusterDomain = "cluster.local"

type Options struct {
	ClusterID             string
	TrustDomain           string
	RootNamespace         string
	ZTunnelServiceAccount string
	// AgentioConfigMaps selects the base and primary Agentio configuration
	// ConfigMaps. Nil uses the Agentio-compatible defaults; an empty primary
	// name explicitly disables the primary overlay.
	AgentioConfigMaps *AgentioConfigMapOptions
	// ClusterDomain is the DNS suffix used to build service hostnames (default cluster.local).
	ClusterDomain string
	DebounceAfter time.Duration
	DebounceMax   time.Duration
}

// Registry turns Kubernetes and Agentio state into the model collections the
// compiler consumes.
type Registry struct {
	options Options

	// Pods supports authorization lookups by pod name and by node.
	Pods                          krt.Collection[*corev1.Pod]
	KubernetesServices            krt.Collection[*corev1.Service]
	EndpointSlices                krt.Collection[*discoveryv1.EndpointSlice]
	podsByNode                    krt.Index[string, *corev1.Pod]
	delegationPodsByNodePrincipal krt.Index[string, *corev1.Pod]

	Sandboxes                  krt.Collection[model.Sandbox]
	Workloads                  krt.Collection[model.Workload]
	Services                   krt.Collection[model.Service]
	Endpoints                  krt.Collection[model.Endpoint]
	Gateways                   krt.Collection[model.Gateway]
	TrafficPolicies            krt.Collection[model.TrafficPolicy]
	SecurityProfiles           krt.Collection[model.SecurityProfile]
	GatewayPatches             krt.Collection[model.GatewayPatch]
	Telemetry                  krt.Collection[model.Telemetry]
	TelemetryProviderOverrides krt.Singleton[model.TelemetryProviderOverrides]
	AgentioConfig              krt.Collection[model.AgentioConfiguration]

	collections []krt.Syncer
}

func New(
	kubeClient kube.Client,
	options Options,
	stop <-chan struct{},
) (*Registry, error) {
	if kubeClient == nil {
		return nil, fmt.Errorf("CRD watcher-enabled Kubernetes client is required")
	}
	if kubeClient.Kube() == nil || kubeClient.AgentsAPI() == nil ||
		kubeClient.GatewayAPI() == nil || kubeClient.CrdWatcher() == nil {
		return nil, fmt.Errorf("Kubernetes client is missing a required typed client or CRD watcher")
	}
	if strings.TrimSpace(options.ClusterID) == "" || strings.TrimSpace(options.TrustDomain) == "" {
		return nil, fmt.Errorf("cluster ID and trust domain are required")
	}
	if options.ZTunnelServiceAccount == "" {
		options.ZTunnelServiceAccount = "ztunnel"
	}
	if options.ClusterDomain == "" {
		options.ClusterDomain = defaultClusterDomain
	}

	// Debounce applies at the informer sources; derived collections inherit the batching.
	sourceOptions := func(name string) []krt.CollectionOption {
		return []krt.CollectionOption{
			krt.WithName(name),
			krt.WithStop(stop),
			krt.WithDebounce(options.DebounceAfter, options.DebounceMax),
		}
	}
	derivedOptions := func(name string) []krt.CollectionOption {
		return []krt.CollectionOption{krt.WithName(name), krt.WithStop(stop)}
	}

	gatewayInformer := kclient.NewDelayedInformer[*gatewayv1.Gateway](
		kubeClient,
		gatewayResource,
		kclient.Filter{},
	)
	gatewayClassInformer := kclient.NewDelayedInformer[*gatewayv1.GatewayClass](
		kubeClient,
		gatewayClassResource,
		kclient.Filter{},
	)

	r := &Registry{options: options}

	pods := krt.NewInformer[*corev1.Pod](kubeClient, sourceOptions("pods")...)
	services := krt.NewInformer[*corev1.Service](kubeClient, sourceOptions("kubernetes-services")...)
	slices := krt.NewInformer[*discoveryv1.EndpointSlice](kubeClient, sourceOptions("endpoint-slices")...)
	configMaps := krt.NewInformer[*corev1.ConfigMap](kubeClient, sourceOptions("config-maps")...)
	trafficPolicyObjects := newTrafficPoliciesCollection(
		kubeClient,
		stop,
		sourceOptions("traffic-policy-objects")...,
	)
	globalTrafficObjects := newGlobalTrafficPoliciesCollection(
		kubeClient,
		stop,
		sourceOptions("global-traffic-policy-objects")...,
	)
	securityProfileObjects := newSecurityProfilesCollection(
		kubeClient,
		stop,
		sourceOptions("security-profile-objects")...,
	)
	globalSecurityObjects := newGlobalSecurityProfilesCollection(
		kubeClient,
		stop,
		sourceOptions("global-security-profile-objects")...,
	)
	gatewayInformer.Start(stop)
	gatewayClassInformer.Start(stop)
	gatewayObjects := krt.WrapClient(gatewayInformer, sourceOptions("gateway-api-gateways")...)
	gatewayClassObjects := krt.WrapClient(gatewayClassInformer, sourceOptions("gateway-api-classes")...)

	r.Pods = pods
	r.KubernetesServices = services
	r.EndpointSlices = slices
	r.podsByNode = krt.NewIndex(pods, "podsByNode", func(pod *corev1.Pod) []string {
		if pod.Spec.NodeName == "" {
			return nil
		}
		return []string{pod.Spec.NodeName}
	})
	r.delegationPodsByNodePrincipal = newDelegationTargetIndex(pods, options.TrustDomain)
	kruiseSource := kruise.NewSource(
		kubeClient,
		pods,
		kruise.Options{
			ClusterID:     options.ClusterID,
			TrustDomain:   options.TrustDomain,
			DebounceAfter: options.DebounceAfter,
			DebounceMax:   options.DebounceMax,
		},
		stop,
	)
	r.Sandboxes = kruiseSource.Sandboxes
	podWorkloads := podsource.NewWorkloads(
		pods,
		options.ClusterID,
		options.TrustDomain,
		kruise.OwnsPod,
		derivedOptions("pod-workloads")...,
	)
	r.Workloads = krt.JoinCollection(
		[]krt.Collection[model.Workload]{podWorkloads, kruiseSource.Workloads},
		derivedOptions("workloads")...,
	)

	r.Services, r.Endpoints = newServiceCollections(services, slices, options.ClusterDomain, derivedOptions)

	rootNamespace := options.RootNamespace
	agentioConfigMaps := defaultAgentioConfigMapOptions()
	if options.AgentioConfigMaps != nil {
		agentioConfigMaps = *options.AgentioConfigMaps
	}
	r.AgentioConfig = krt.NewSingleton(func(ctx krt.HandlerContext) *model.AgentioConfiguration {
		return effectiveAgentioConfiguration(ctx, configMaps, rootNamespace, agentioConfigMaps)
	}, derivedOptions("agentio-config")...).AsCollection()
	r.GatewayPatches = newEnvoyFiltersCollection(
		configMaps,
		rootNamespace,
		derivedOptions("config-map-envoy-filters")...,
	)
	r.Telemetry = newTelemetriesCollection(
		configMaps,
		rootNamespace,
		derivedOptions("config-map-telemetries")...,
	)
	r.TelemetryProviderOverrides = krt.NewStatic[model.TelemetryProviderOverrides](
		nil,
		true,
		derivedOptions("telemetry-provider-overrides")...,
	)

	agentioConfigGateways := newAgentioConfigGateways(r.AgentioConfig, derivedOptions("agentio-config-gateways")...)
	gatewayAPIConfigurations := newGatewayAPIConfigurations(
		gatewayObjects,
		gatewayClassObjects,
		configMaps,
		derivedOptions("gateway-api-configurations")...,
	)
	r.Gateways = krt.JoinWithMergeCollection(
		[]krt.Collection[model.Gateway]{agentioConfigGateways, gatewayAPIConfigurations},
		model.MergeGatewaySources,
		derivedOptions("egress-gateway-configurations")...,
	)

	namespacedTraffic := krt.NewCollection(trafficPolicyObjects,
		func(_ krt.HandlerContext, policy *agentsv1alpha1.TrafficPolicy) *model.TrafficPolicy {
			return &model.TrafficPolicy{
				Name:         policy.Name,
				Namespace:    policy.Namespace,
				SandboxUID:   policy.Annotations[agentsv1alpha1.AnnotationSandboxID],
				CreationTime: policy.CreationTimestamp.Time,
				Spec:         *policy.Spec.DeepCopy(),
			}
		}, derivedOptions("namespaced-traffic-policies")...)
	globalTraffic := krt.NewCollection(globalTrafficObjects,
		func(_ krt.HandlerContext, policy *agentsv1alpha1.GlobalTrafficPolicy) *model.TrafficPolicy {
			return &model.TrafficPolicy{
				Name:         policy.Name,
				SandboxUID:   policy.Annotations[agentsv1alpha1.AnnotationSandboxID],
				Global:       true,
				CreationTime: policy.CreationTimestamp.Time,
				Spec:         *policy.Spec.DeepCopy(),
			}
		}, derivedOptions("global-traffic-policies")...)
	// TrafficPolicy.ResourceName prefixes namespaced and global policies
	// differently, so the two key spaces cannot collide in the join.
	r.TrafficPolicies = krt.JoinCollection(
		[]krt.Collection[model.TrafficPolicy]{namespacedTraffic, globalTraffic},
		derivedOptions("traffic-policies")...)

	namespacedSecurity := krt.NewCollection(securityProfileObjects,
		func(_ krt.HandlerContext, profile *agentsv1alpha1.SecurityProfile) *model.SecurityProfile {
			return &model.SecurityProfile{
				Name:         profile.Name,
				Namespace:    profile.Namespace,
				SandboxUID:   profile.Annotations[agentsv1alpha1.AnnotationSandboxID],
				CreationTime: profile.CreationTimestamp.Time,
				Spec:         *profile.Spec.DeepCopy(),
			}
		}, derivedOptions("namespaced-security-profiles")...)
	globalSecurity := krt.NewCollection(globalSecurityObjects,
		func(_ krt.HandlerContext, profile *agentsv1alpha1.GlobalSecurityProfile) *model.SecurityProfile {
			return &model.SecurityProfile{
				Name:         profile.Name,
				SandboxUID:   profile.Annotations[agentsv1alpha1.AnnotationSandboxID],
				Global:       true,
				CreationTime: profile.CreationTimestamp.Time,
				Spec:         *profile.Spec.DeepCopy(),
			}
		}, derivedOptions("global-security-profiles")...)
	r.SecurityProfiles = krt.JoinCollection(
		[]krt.Collection[model.SecurityProfile]{namespacedSecurity, globalSecurity},
		derivedOptions("security-profiles")...)

	r.collections = []krt.Syncer{
		r.Sandboxes, r.Workloads, r.Services, r.Endpoints, r.Gateways,
		r.TrafficPolicies, r.SecurityProfiles, r.GatewayPatches, r.AgentioConfig,
		r.Telemetry, r.TelemetryProviderOverrides.AsCollection(),
	}
	return r, nil
}

func (r *Registry) HasSynced() bool {
	for _, collection := range r.collections {
		if !collection.HasSynced() {
			return false
		}
	}
	return true
}
