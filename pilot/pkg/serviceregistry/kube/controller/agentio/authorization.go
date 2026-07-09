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

package agentio

import (
	"strconv"
	"strings"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/api/security/v1beta1"
	typev1beta1 "istio.io/api/type/v1beta1"
	securityclient "istio.io/client-go/pkg/apis/security/v1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/workloadapi/security"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type authorizationController struct {
	services                    krt.Collection[*corev1.Service]
	servicesByNamespace         krt.Index[string, *corev1.Service]
	endpointSlices              krt.Collection[*discovery.EndpointSlice]
	endpointSlicesByServiceName krt.Index[string, *discovery.EndpointSlice]
	pods                        krt.Collection[*corev1.Pod]
	podsByNamespace             krt.Index[string, *corev1.Pod]
	col                         krt.Collection[model.WorkloadAuthorization]
}

type resolveExternalName func(krt.HandlerContext, string) []string

func newAuthorizationController(
	TrafficPolicies krt.Collection[*agentsv1alpha1.TrafficPolicy],
	GlobalTrafficPolicies krt.Collection[*agentsv1alpha1.GlobalTrafficPolicy],
	services krt.Collection[*corev1.Service],
	endpointSlices krt.Collection[*discovery.EndpointSlice],
	resolver resolveExternalName,
	pods krt.Collection[*corev1.Pod],
	toAuthorizationPolicy func(*securityclient.AuthorizationPolicy) (*security.Authorization, *model.StatusMessage),
	rootNamespace string,
) *authorizationController {
	endpointSlicesByServiceName := krt.NewIndex(endpointSlices, "byServiceName", func(es *discovery.EndpointSlice) []string {
		serviceName, ok := es.Labels[discovery.LabelServiceName]
		if !ok {
			return nil
		}
		return []string{es.Namespace + "/" + serviceName}
	})
	c := &authorizationController{
		services:                    services,
		servicesByNamespace:         krt.NewNamespaceIndex(services),
		endpointSlices:              endpointSlices,
		endpointSlicesByServiceName: endpointSlicesByServiceName,
		pods:                        pods,
		podsByNamespace:             krt.NewNamespaceIndex(pods),
	}

	toWorkloadPolicy := func(ctx krt.HandlerContext,
		objectMeta metav1.ObjectMeta,
		policySpec *agentsv1alpha1.TrafficPolicySpec,
		authz *securityclient.AuthorizationPolicy,
	) *model.WorkloadAuthorization {
		pol, status := toAuthorizationPolicy(authz)
		if pol == nil && status == nil {
			return nil
		}

		// pol can be nil when convertAuthorizationPolicy returns only a status
		// (e.g. dry-run annotation present but EnableWdsDryRunAuthzPol disabled).
		// Mirror ambient/policies.go: surface the status via Binding and skip any
		// pol mutation in that case.
		if pol != nil && len(policySpec.Selector.MatchExpressions) > 0 {
			pol.Scope = security.Scope_WORKLOAD_SELECTOR
		}

		selector, err := metav1.LabelSelectorAsSelector(&policySpec.Selector)
		if err != nil {
			log.Warnf("Failed to convert label selector: %v, will match all", err)
		}

		return &model.WorkloadAuthorization{
			Authorization: pol,
			Selector:      selector,
			LabelSelector: model.NewSelector(policySpec.Selector.MatchLabels),
			Source:        model.MakeSource(authz),
			Binding: model.PolicyBindingStatus{
				ObservedGeneration: objectMeta.GetGeneration(),
				Ancestor:           string(model.Ztunnel),
				Status:             status,
				Bound:              pol != nil,
			},
		}
	}

	trafficPolicyAuthz := krt.NewManyCollection(TrafficPolicies, func(ctx krt.HandlerContext, i *agentsv1alpha1.TrafficPolicy) []model.WorkloadAuthorization {
		meta := metav1.ObjectMeta{Name: i.Name, Namespace: i.Namespace, Annotations: i.Annotations, Generation: i.Generation}
		return c.convertTrafficPolicyToWorkloadPolicies(ctx, meta, &i.Spec, i.Name, i.Namespace, resolver, toWorkloadPolicy)
	})

	globalTrafficPolicyAuthz := krt.NewManyCollection(GlobalTrafficPolicies, func(ctx krt.HandlerContext, i *agentsv1alpha1.GlobalTrafficPolicy) []model.WorkloadAuthorization {
		meta := metav1.ObjectMeta{Name: i.Name, Annotations: i.Annotations, Generation: i.Generation}
		return c.convertTrafficPolicyToWorkloadPolicies(ctx, meta, &i.Spec, i.Name, rootNamespace, resolver, toWorkloadPolicy)
	})

	c.col = krt.JoinCollection([]krt.Collection[model.WorkloadAuthorization]{
		trafficPolicyAuthz, globalTrafficPolicyAuthz,
	}, krt.WithDebounce(features.KrtEventDistributeDebounce, features.KrtEventDistributeDebounceMax))
	return c
}

func (c *authorizationController) AsCollection() krt.Collection[model.WorkloadAuthorization] {
	return c.col
}

func (c *authorizationController) convertTrafficPolicyToWorkloadPolicies(
	ctx krt.HandlerContext,
	objectMeta metav1.ObjectMeta,
	tp *agentsv1alpha1.TrafficPolicySpec,
	name,
	namespace string,
	resolver resolveExternalName,
	transform func(
		krt.HandlerContext,
		metav1.ObjectMeta,
		*agentsv1alpha1.TrafficPolicySpec,
		*securityclient.AuthorizationPolicy,
	) *model.WorkloadAuthorization,
) []model.WorkloadAuthorization {
	policies := []model.WorkloadAuthorization{}

	var selector *typev1beta1.WorkloadSelector
	if len(tp.Selector.MatchLabels) > 0 {
		selector = &typev1beta1.WorkloadSelector{
			MatchLabels: tp.Selector.MatchLabels,
		}
	}

	if tp.Egress != nil {
		rules := []*v1beta1.Rule{}
		for _, rule := range tp.Egress.Rules {
			rules = append(rules, c.convertRule(ctx, rule, resolver))
		}

		ap := &securityclient.AuthorizationPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name + "-egress",
				Namespace:   namespace,
				Annotations: objectMeta.Annotations,
				Labels:      objectMeta.Labels,
			},
			Spec: v1beta1.AuthorizationPolicy{
				Action:   v1beta1.AuthorizationPolicy_ALLOW,
				Selector: selector,
				Rules:    rules,
			},
		}

		wp := transform(ctx, objectMeta, tp, ap)
		if wp != nil && wp.Authorization != nil {
			wp.Authorization.AuthExtensions = append(wp.Authorization.AuthExtensions,
				NewTrafficPolicyExtension(int64(tp.Priority), extensions.TrafficPolicyMode_CLIENT))
			policies = append(policies, *wp)
		}
	}

	if tp.Ingress != nil {
		rules := []*v1beta1.Rule{}
		for _, rule := range tp.Ingress.Rules {
			rules = append(rules, c.convertRule(ctx, rule, resolver))
		}

		ap := &securityclient.AuthorizationPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:        name + "-ingress",
				Namespace:   namespace,
				Annotations: objectMeta.Annotations,
				Labels:      objectMeta.Labels,
			},
			Spec: v1beta1.AuthorizationPolicy{
				Action:   v1beta1.AuthorizationPolicy_ALLOW,
				Selector: selector,
				Rules:    rules,
			},
		}

		wp := transform(ctx, objectMeta, tp, ap)
		if wp != nil && wp.Authorization != nil {
			wp.Authorization.AuthExtensions = append(wp.Authorization.AuthExtensions,
				NewTrafficPolicyExtension(int64(tp.Priority), extensions.TrafficPolicyMode_SERVER))
			policies = append(policies, *wp)
		}
	}

	return policies
}

// formatPortRange encodes a TrafficPolicyPort as "start-end/PROTO".
// Examples: "80/TCP", "53-100/UDP", "/ICMP", "80-90", "".
func formatPortRange(port agentsv1alpha1.TrafficPolicyPort) string {
	hasPort := port.Port != nil || port.EndPort != nil
	hasProto := port.Protocol != ""
	if !hasPort && !hasProto {
		return ""
	}

	var s string
	if hasPort {
		s = "-"
		if port.Port != nil {
			s = strconv.Itoa(int(*port.Port)) + s
		}
		if port.EndPort != nil {
			s = s + strconv.Itoa(int(*port.EndPort))
		}
	}
	if hasProto {
		s = s + "/" + strings.ToUpper(port.Protocol)
	}
	return s
}

func (c *authorizationController) convertRule(ctx krt.HandlerContext, rule agentsv1alpha1.TrafficPolicyRule, resolver resolveExternalName) *v1beta1.Rule {
	apRule := &v1beta1.Rule{}

	fetchIps := func(peer agentsv1alpha1.TrafficPolicyPeer) []string {
		ips := []string{}
		if peer.CIDR != "" {
			ips = append(ips, peer.CIDR)
		} else if peer.Service != nil {
			var svcs []*corev1.Service
			if peer.Service.Name == "" || peer.Service.Name == "*" {
				svcs = krt.Fetch(ctx, c.services, krt.FilterIndex(c.servicesByNamespace, peer.Service.Namespace))
			} else {
				key := peer.Service.Namespace + "/" + peer.Service.Name
				if svc := ptr.Flatten(krt.FetchOne(ctx, c.services, krt.FilterKey(key))); svc != nil {
					svcs = []*corev1.Service{svc}
				} else {
					log.Warnf("Failed to fetch service defined in TrafficPolicy, key: %s", key)
				}
			}
			for _, svc := range svcs {
				if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
					ips = append(ips, svc.Spec.ClusterIP)
				}
				esKey := svc.Namespace + "/" + svc.Name
				epSlices := krt.Fetch(ctx, c.endpointSlices, krt.FilterIndex(c.endpointSlicesByServiceName, esKey))
				for _, es := range epSlices {
					if es.AddressType == discovery.AddressTypeFQDN {
						continue
					}
					for _, ep := range es.Endpoints {
						ips = append(ips, ep.Addresses...)
					}
				}
			}
		} else if peer.FQDN != "" {
			ips = append(ips, resolver(ctx, peer.FQDN)...)
		} else if peer.Workload != nil {
			pods := krt.Fetch(ctx, c.pods,
				krt.FilterLabel(peer.Workload.Selector),
				krt.FilterIndex(c.podsByNamespace, peer.Workload.Namespace),
				krt.FilterGeneric(func(a any) bool {
					p := a.(*corev1.Pod)
					return IsPodReady(p) && p.DeletionTimestamp == nil
				}),
			)
			for _, pod := range pods {
				if len(pod.Status.PodIPs) > 0 {
					ips = append(ips, slices.Map(pod.Status.PodIPs, func(ip corev1.PodIP) string { return ip.IP })...)
				} else if pod.Status.PodIP != "" {
					ips = append(ips, pod.Status.PodIP)
				}
			}
		}
		return ips
	}

	srcIps := []string{}
	dstIps := []string{}
	dstPortRanges := []string{}

	for _, from := range rule.From {
		srcIps = append(srcIps, fetchIps(from)...)
	}

	for _, to := range rule.To {
		dstIps = append(dstIps, fetchIps(to)...)
	}

	for _, port := range rule.Ports {
		if s := formatPortRange(port); s != "" {
			dstPortRanges = append(dstPortRanges, s)
		}
	}

	appendCondition := func(key string, values []string) {
		if len(values) == 0 {
			return
		}
		if rule.Action == agentsv1alpha1.RuleActionAllow {
			apRule.When = append(apRule.When, &v1beta1.Condition{Key: key, Values: values})
		} else {
			apRule.When = append(apRule.When, &v1beta1.Condition{Key: key, NotValues: values})
		}
	}

	appendCondition("source.ip", srcIps)
	appendCondition("destination.ip", dstIps)
	appendCondition("destination.portRange", dstPortRanges)

	return apRule
}
