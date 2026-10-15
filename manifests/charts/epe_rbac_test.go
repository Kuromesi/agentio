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

package charts_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

func TestEPESecretRBACIsNamespaced(t *testing.T) {
	for _, namespace := range []string{"agentio-system", "custom-system"} {
		t.Run(namespace, func(t *testing.T) {
			manifest := renderAgentio(t, "--namespace", namespace,
				"--set", "epe.mode=managed,epe.serviceAccount.name=custom-epe",
				"--show-only", "templates/epe/rbac.yaml")
			foundRole, foundBinding, foundClusterRole := false, false, false
			for document := range strings.SplitSeq(manifest, "\n---") {
				var object renderedObject
				if err := yaml.Unmarshal([]byte(document), &object); err != nil {
					t.Fatal(err)
				}
				switch object.Kind {
				case "ClusterRole":
					var role rbacv1.ClusterRole
					if err := yaml.Unmarshal([]byte(document), &role); err != nil {
						t.Fatal(err)
					}
					foundClusterRole = true
					for _, rule := range role.Rules {
						if slices.Contains(rule.Resources, "secrets") || slices.Contains(rule.Resources, "*") {
							t.Fatalf("EPE received cluster-wide Secret permissions: %+v", rule)
						}
					}
				case "Role":
					var role rbacv1.Role
					if err := yaml.Unmarshal([]byte(document), &role); err != nil {
						t.Fatal(err)
					}
					want := []rbacv1.PolicyRule{{
						APIGroups: []string{""},
						Resources: []string{"secrets"},
						Verbs:     []string{"get", "list", "watch"},
					}}
					if role.Name != "agentio-epe" || role.Namespace != namespace ||
						!reflect.DeepEqual(role.Rules, want) {
						t.Fatalf("unexpected Secret Role: %+v", role)
					}
					foundRole = true
				case "RoleBinding":
					var binding rbacv1.RoleBinding
					if err := yaml.Unmarshal([]byte(document), &binding); err != nil {
						t.Fatal(err)
					}
					wantRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "agentio-epe"}
					wantSubjects := []rbacv1.Subject{{
						Kind:      "ServiceAccount",
						Name:      "custom-epe",
						Namespace: namespace,
					}}
					if binding.Namespace != namespace || binding.RoleRef != wantRef ||
						!reflect.DeepEqual(binding.Subjects, wantSubjects) {
						t.Fatalf("unexpected Secret RoleBinding: %+v", binding)
					}
					foundBinding = true
				}
			}
			if !foundRole || !foundBinding || !foundClusterRole {
				t.Fatal("missing EPE RBAC resources")
			}
		})
	}
}

func TestEPESecretSourceAllowsExplicitNamespace(t *testing.T) {
	const source = "epe.mode=managed,epe.credentialProvider.mtls.source=secret,epe.credentialProvider.mtls.secret.name=material"
	for _, namespace := range []string{"sandbox-traffic-system", "ack-agent-identity"} {
		t.Run(namespace, func(t *testing.T) {
			manifest := renderAgentio(t, "--namespace", "sandbox-traffic-system",
				"--set", source+",epe.credentialProvider.mtls.secret.namespace="+namespace,
				"--show-only", "templates/epe/deployment.yaml")
			var deployment appsv1.Deployment
			if err := yaml.Unmarshal([]byte(manifest), &deployment); err != nil {
				t.Fatal(err)
			}
			container := deployment.Spec.Template.Spec.Containers[0]
			if !slices.Contains(container.Args, "-epe-config-namespace=sandbox-traffic-system") {
				t.Fatalf("configuration namespace lost: %v", container.Args)
			}
			for _, env := range container.Env {
				if env.Name == "CREDENTIAL_PROVIDER_SECRET_NAMESPACE" {
					if env.Value != namespace {
						t.Fatalf("Secret namespace = %q, want %q", env.Value, namespace)
					}
					return
				}
			}
			t.Fatal("missing Secret namespace environment variable")
		})
	}
}
