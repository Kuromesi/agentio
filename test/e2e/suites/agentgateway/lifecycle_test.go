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
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	native "github.com/openkruise/agentio/test/e2e/components/agentgateway"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func waitConfigReady(ctx context.Context, env *e2e.Environment, name, content string) error {
	return native.WaitReady(ctx, env, config.Namespace, name, content)
}

func TestAgentgatewayDeploymentLifecycle(t *testing.T) {
	env, _ := rig.BeginScenario(t)
	ctx, cancel := e2e.Context(t, 8*time.Minute)
	defer cancel()
	const name = "lifecycle"
	// Use the run-wide ledger because deleting and recreating the same name
	// deliberately changes its UID. A short-lived scope retains the obsolete UID.
	apply := func(t *testing.T, u *unstructured.Unstructured) kube.ResourceRecord {
		t.Helper()
		mode := kube.ReconcileOwned
		if _, found := env.Kube.Ledger().Find(uGVR(u), u.GetNamespace(), u.GetName()); !found {
			mode = kube.CreateOnly
		} else if _, err := env.Kube.Get(ctx, uGVR(u), u.GetNamespace(), u.GetName()); apierrors.IsNotFound(err) {
			mode = kube.CreateOnly
		}
		r, err := env.Kube.Apply(ctx, u, mode)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	status := func(t *testing.T, a, p string) {
		t.Helper()
		if err := waitGateway(ctx, env, name, a, p); err != nil {
			t.Fatal(err)
		}
	}
	probe := func(t *testing.T, body string) {
		t.Helper()
		traffic.Client.CallOrFail(t, echo.CallOptions{
			Protocol: echo.HTTP,
			Address:  name + "." + config.Namespace + ".svc.cluster.local",
			Port:     8080,
			Count:    1,
			Check: check.And(check.OK(), check.Each(func(r echo.Response) error {
				if !strings.Contains(r.RawContent, body) {
					return fmt.Errorf("expected %q in response: %s", body, r.RawContent)
				}
				return nil
			})),
			Retry: harness.FixedRetry(time.Minute, time.Second),
		})
	}
	step := func(name string, body func(*testing.T)) {
		t.Helper()
		if !t.Run(name, body) {
			t.FailNow()
		}
	}
	step("gatewayclass created and accepted", func(t *testing.T) {
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			g, err := env.Kube.Get(ctx, schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gatewayclasses"}, "", "agentio-agentgateway")
			if err != nil {
				return err
			}
			controller, _, _ := unstructured.NestedString(g.Object, "spec", "controllerName")
			if controller != "agentio.kruise.io/agentgateway-controller" {
				return fmt.Errorf("unexpected controller %s", controller)
			}
			cs, _, _ := unstructured.NestedSlice(g.Object, "status", "conditions")
			for _, c := range cs {
				m := c.(map[string]any)
				if m["type"] == "Accepted" && m["status"] == "True" {
					return nil
				}
			}
			return fmt.Errorf("class not accepted: %v", cs)
		})
	})
	var gwRecord kube.ResourceRecord
	step("missing config rejected", func(t *testing.T) { gwRecord = apply(t, gateway(name)); status(t, "False", "False") })
	step("gateway provisioned and serving", func(t *testing.T) {
		apply(t, configuration(name, nativeConfig("version-one", false)))
		if err := waitConfigReady(ctx, env, name, nativeConfig("version-one", false)); err != nil {
			t.Fatal(err)
		}
		probe(t, "version-one")
	})
	step("config update rolls out and changes traffic", func(t *testing.T) {
		applyNative(t, env, name, nativeConfig("version-two", false))
		probe(t, "version-two")
	})
	step("invalid YAML preserves running config", func(t *testing.T) {
		apply(t, configuration(name, "binds: ["))
		status(t, "False", "False")
		probe(t, "version-two")
	})
	step("invalid native schema stays unprogrammed with old replica serving", func(t *testing.T) {
		apply(t, configuration(name, strings.Replace(nativeConfig("bad", false), `"protocol":"HTTP"`, `"protocol":"INVALID_PROTOCOL"`, 1)))
		status(t, "True", "False")
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			pods, err := env.Cluster.Kube.CoreV1().Pods(config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "gateway.networking.k8s.io/gateway-name=" + name})
			if err != nil {
				return err
			}
			for _, p := range pods.Items {
				for _, c := range p.Status.ContainerStatuses {
					if c.RestartCount > 0 || c.State.Terminated != nil {
						return nil
					}
				}
			}
			return fmt.Errorf("waiting for native config rejection")
		})
		probe(t, "version-two")
	})
	step("fixed config recovers", func(t *testing.T) {
		applyNative(t, env, name, nativeConfig("version-three", false))
		probe(t, "version-three")
	})
	step("deleted service reconciled", func(t *testing.T) {
		svc, err := env.Cluster.Kube.CoreV1().Services(config.Namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		owned := false
		for _, o := range svc.OwnerReferences {
			if o.UID == gwRecord.UID && o.Kind == "Gateway" && o.Name == name {
				owned = true
			}
		}
		if !owned {
			t.Fatal("service is not controlled by the fixture Gateway")
		}
		if err := env.Cluster.Kube.CoreV1().Services(config.Namespace).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &svc.UID}}); err != nil {
			t.Fatal(err)
		}
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			s, err := env.Cluster.Kube.CoreV1().Services(config.Namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return err
			}
			if s.UID == svc.UID {
				return fmt.Errorf("service not recreated")
			}
			return nil
		})
		probe(t, "version-three")
	})
	availabilityResources := []schema.GroupVersionResource{
		{Group: "autoscaling", Version: "v2", Resource: "horizontalpodautoscalers"},
		{Group: "policy", Version: "v1", Resource: "poddisruptionbudgets"},
	}
	for _, resource := range availabilityResources {
		step("deleted "+resource.Resource+" reconciled", func(t *testing.T) {
			child, err := env.Kube.Get(ctx, resource, config.Namespace, name)
			if err != nil {
				t.Fatal(err)
			}
			owners := child.GetOwnerReferences()
			if len(owners) != 1 || owners[0].UID != gwRecord.UID || owners[0].Kind != "Gateway" || owners[0].Name != name {
				t.Fatal("availability resource is not owned by the fixture Gateway")
			}
			uid := child.GetUID()
			if err := env.Cluster.Dynamic.Resource(resource).Namespace(config.Namespace).Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil {
				t.Fatal(err)
			}
			harness.RetryAssertion(t, time.Minute, time.Second, func() error {
				current, err := env.Kube.Get(ctx, resource, config.Namespace, name)
				if err != nil {
					return err
				}
				if current.GetUID() == uid {
					return fmt.Errorf("%s not recreated", resource.Resource)
				}
				return nil
			})
			probe(t, "version-three")
		})
	}
	step("gateway deletion collects children and preserves config", func(t *testing.T) {
		if err := env.Kube.DeleteOwned(ctx, gwRecord); err != nil {
			t.Fatal(err)
		}
		harness.RetryAssertion(t, time.Minute, time.Second, func() error {
			children := append([]schema.GroupVersionResource{deployments, {Version: "v1", Resource: "services"}, {Version: "v1", Resource: "serviceaccounts"}}, availabilityResources...)
			for _, r := range children {
				_, err := env.Kube.Get(ctx, r, config.Namespace, name)
				if !apierrors.IsNotFound(err) {
					return fmt.Errorf("child %s still exists: %v", r.Resource, err)
				}
			}
			return nil
		})
		if _, err := env.Kube.Get(ctx, configmaps, config.Namespace, name+"-config"); err != nil {
			t.Fatal(err)
		}
	})
	step("gateway recreated", func(t *testing.T) {
		apply(t, gateway(name))
		if err := waitConfigReady(ctx, env, name, nativeConfig("version-three", false)); err != nil {
			t.Fatal(err)
		}
		probe(t, "version-three")
	})
}

func uGVR(u *unstructured.Unstructured) schema.GroupVersionResource {
	if u.GetKind() == "Gateway" {
		return gateways
	}
	return configmaps
}
