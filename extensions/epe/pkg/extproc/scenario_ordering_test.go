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

// Full-chain multi-profile ordering scenarios (priority, creation time,
// name, and global/namespace interleaving) driven through the enginetest
// harness. Typed v1alpha1 profiles are seeded through Fixture.ApplyProfile /
// ApplyGlobalProfile so CRD defaulting (e.g. spec.priority=1000) applies
// exactly as a real apiserver would.
package extproc_test

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"istio.io/istio/extensions/epe/pkg/testing/enginetest"
)

// securityProfile builds a namespace-scoped SecurityProfile. priority may be
// nil to exercise the CRD default (1000).
func securityProfile(name, namespace string, priority *int32, selector map[string]string, rules []v1alpha1.SecurityRule) *v1alpha1.SecurityProfile {
	return &v1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: v1alpha1.SecurityProfileSpec{
			Priority: priority,
			Selector: metav1.LabelSelector{MatchLabels: selector},
			Rules:    rules,
		},
	}
}

// globalSecurityProfile builds a cluster-scoped GlobalSecurityProfile.
func globalSecurityProfile(name string, priority int32, selector map[string]string, rules []v1alpha1.SecurityRule) *v1alpha1.GlobalSecurityProfile {
	return &v1alpha1.GlobalSecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.SecurityProfileSpec{
			Priority: ptr.To(priority),
			Selector: metav1.LabelSelector{MatchLabels: selector},
			Rules:    rules,
		},
	}
}

// blockAdminRule matches any domain on the /admin path prefix and blocks
// with the given status.
func blockAdminRule(name string, statusCode int32) v1alpha1.SecurityRule {
	return v1alpha1.SecurityRule{
		Name: name,
		Match: []v1alpha1.RuleMatch{{
			Domains: []string{"*"},
			Paths:   []v1alpha1.PathMatch{{Type: v1alpha1.PathMatchTypePrefix, Value: "/admin"}},
		}},
		Actions: v1alpha1.SecurityRuleActions{
			Block: &v1alpha1.BlockAction{StatusCode: statusCode},
		},
	}
}

// bypassAdminRule matches any domain on the /admin path prefix and bypasses.
func bypassAdminRule(name string) v1alpha1.SecurityRule {
	return v1alpha1.SecurityRule{
		Name: name,
		Match: []v1alpha1.RuleMatch{{
			Domains: []string{"*"},
			Paths:   []v1alpha1.PathMatch{{Type: v1alpha1.PathMatchTypePrefix, Value: "/admin"}},
		}},
		Actions: v1alpha1.SecurityRuleActions{Bypass: true},
	}
}

// sleepPeerRequest builds a request from a pod carrying the app=sleep label.
func sleepPeerRequest(namespace, pod, host, path string) *enginetest.RequestBuilder {
	return enginetest.NewRequest("GET", host, path).
		Peer(namespace, pod, map[string]string{"app": "sleep"})
}

// TestHandleRequestHeaders_MultipleProfiles_AlphabeticalOrder verifies that
// when multiple profiles match the same pod with equal priority and equal
// creationTimestamp, profile-name sort order determines which Block fires.
func TestHandleRequestHeaders_MultipleProfiles_AlphabeticalOrder(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})

	// Pin identical creationTimestamps so the name tie-breaker (not the
	// fixture's synthesized creation order) decides. Both profiles omit
	// priority and receive the CRD default (1000).
	ts := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	alpha := securityProfile("alpha", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{{
		Name:  "block-401",
		Match: []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
		Actions: v1alpha1.SecurityRuleActions{
			Block: &v1alpha1.BlockAction{StatusCode: 401},
		},
	}})
	alpha.CreationTimestamp = ts
	beta := securityProfile("beta", "default", nil, map[string]string{"app": "blocked"}, []v1alpha1.SecurityRule{{
		Name:  "block-403",
		Match: []v1alpha1.RuleMatch{{Domains: []string{"*"}}},
		Actions: v1alpha1.SecurityRuleActions{
			Block: &v1alpha1.BlockAction{StatusCode: 403},
		},
	}})
	beta.CreationTimestamp = ts

	// Apply "beta" first so an insertion-order bug cannot masquerade as
	// alphabetical ordering.
	h.Fixture.ApplyProfile(beta).ApplyProfile(alpha)

	// "alpha" sorts before "beta" — its 401 must win.
	h.Run(t, blockedPeerRequest("GET", "api.example.com", "/x")).
		RequireBlocked(t, 401)
}

func TestHandleRequestHeaders_PriorityControlsEvaluationOrder(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})

	// Low-priority (10) block rule.
	h.Fixture.ApplyProfile(securityProfile("sp-block", "default", ptr.To[int32](10),
		map[string]string{"app": "sleep"}, []v1alpha1.SecurityRule{blockAdminRule("block-admin", 403)}))
	// High-priority (1) bypass rule — evaluated first, short-circuits the chain.
	h.Fixture.ApplyProfile(securityProfile("sp-bypass", "default", ptr.To[int32](1),
		map[string]string{"app": "sleep"}, []v1alpha1.SecurityRule{bypassAdminRule("bypass-admin")}))

	// Bypass (priority 1) wins over block (priority 10) — request passes through.
	h.Run(t, sleepPeerRequest("default", "pod-x", "example.com", "/admin/keys")).
		RequireBypassed(t)
}

func TestHandleRequestHeaders_GlobalProfileMatchesAllNamespaces(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})
	h.Fixture.ApplyGlobalProfile(globalSecurityProfile("gsp-block", 1,
		map[string]string{"app": "sleep"}, []v1alpha1.SecurityRule{blockAdminRule("block-admin", 403)}))

	// Pod in "ns-a" should be blocked by the global profile.
	h.Run(t, sleepPeerRequest("ns-a", "pod-1", "example.com", "/admin/keys")).
		RequireBlocked(t, 403)

	// Pod in "ns-b" should also be blocked by the same global profile.
	h.Run(t, sleepPeerRequest("ns-b", "pod-2", "example.com", "/admin/keys")).
		RequireBlocked(t, 403)
}

func TestHandleRequestHeaders_GlobalAndNamespaceInterleaveByPriority(t *testing.T) {
	h := enginetest.New(t, enginetest.Options{})

	// Global profile with low priority (10).
	h.Fixture.ApplyGlobalProfile(globalSecurityProfile("gsp-block", 10,
		map[string]string{"app": "sleep"}, []v1alpha1.SecurityRule{blockAdminRule("block-admin", 403)}))
	// Namespace profile with high priority (1) — evaluated first.
	h.Fixture.ApplyProfile(securityProfile("sp-bypass", "default", ptr.To[int32](1),
		map[string]string{"app": "sleep"}, []v1alpha1.SecurityRule{bypassAdminRule("bypass-admin")}))

	// Namespace bypass (priority 1) wins over global block (priority 10).
	h.Run(t, sleepPeerRequest("default", "pod-x", "example.com", "/admin/keys")).
		RequireBypassed(t)
}

// TestHandleRequestHeaders_EqualPriorityUsesCreationTimestamp verifies the
// tie-break between equal-priority profiles: the earlier creationTimestamp
// evaluates first, even when the newer profile sorts earlier by name.
func TestHandleRequestHeaders_EqualPriorityUsesCreationTimestamp(t *testing.T) {
	older := securityProfile("z-older-block", "default", ptr.To[int32](500),
		map[string]string{"app": "sleep"}, []v1alpha1.SecurityRule{blockAdminRule("block-admin", 425)})
	older.CreationTimestamp = metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	newer := securityProfile("a-newer-bypass", "default", ptr.To[int32](500),
		map[string]string{"app": "sleep"}, []v1alpha1.SecurityRule{bypassAdminRule("bypass-admin")})
	newer.CreationTimestamp = metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))

	// The block was created first, so it wins the tie despite sorting later
	// alphabetically. Apply the newer profile first so insertion order
	// cannot masquerade as the timestamp tie-break.
	h := enginetest.New(t, enginetest.Options{})
	h.Fixture.ApplyProfile(newer).ApplyProfile(older)
	h.Run(t, sleepPeerRequest("default", "pod-x", "example.com", "/admin/keys")).
		RequireBlocked(t, 425)

	// Swapping the timestamps exposes the bypass.
	older.CreationTimestamp, newer.CreationTimestamp = newer.CreationTimestamp, older.CreationTimestamp
	reversed := enginetest.New(t, enginetest.Options{})
	reversed.Fixture.ApplyProfile(newer).ApplyProfile(older)
	reversed.Run(t, sleepPeerRequest("default", "pod-x", "example.com", "/admin/keys")).
		RequireBypassed(t)
}
