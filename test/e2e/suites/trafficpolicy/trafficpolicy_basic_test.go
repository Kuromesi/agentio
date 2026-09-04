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

package trafficpolicy

import (
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	"github.com/openkruise/agentio/test/e2e/components/namespace"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/network"
	"github.com/openkruise/agentio/test/e2e/retry"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestSandboxTrafficPolicy(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	anotherDst := trafficFixture.AnotherServer
	serviceIPBlock, err := network.PrefixCIDR(src.ServiceIPOrFail(t), 16)
	if err != nil {
		t.Fatal(err)
	}

	rig.RunScenario(t, "egress allow with cidr", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "Dst": serviceIPBlock}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-cidr
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-egress-cidr")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "egress deny with cidr", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "Dst": dst.ServiceIPOrFail(t)}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-deny
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: {{ .Dst }}
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-egress-deny")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "ingress allow with service ref", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": dst.Name(), "SrcApp": src.Name(), "SrcAppNamespace": src.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-svc
spec:
  priority: 200
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - service:
              name: "{{ .SrcApp }}"
              namespace: "{{ .SrcAppNamespace }}"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, dst, "tp-ingress-svc")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		anotherDst.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
	})

	rig.RunScenario(t, "ingress deny with cidr fallback", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": dst.Name(), "SrcApp": src.Name(), "SrcAppNamespace": src.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-deny-fallback
spec:
  priority: 200
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - service:
              name: "{{ .SrcApp }}"
              namespace: "{{ .SrcAppNamespace }}"
      - action: reject
        from:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, dst, "tp-ingress-deny-fallback")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		anotherDst.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
	})

	rig.RunScenario(t, "egress with port range", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "Dst": serviceIPBlock}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-port-range
spec:
  priority: 50
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
        ports:
          - port: 80
            endPort: 81
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-port-range")
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dst.Address(), 80).WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, anotherDst.Address(), 81).WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTPS, dst.Address(), 9443).WithCheck(check.Error()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, anotherDst.Address(), 82).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "egress with fqdn", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(), "Dst": dst.Name(), "DstNamespace": dst.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-fqdn
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: allow
        to:
          - fqdn: "www.example.com"
          - fqdn: "example.com"
      - action: allow
        to:
          - service:
              namespace: {{ .DstNamespace }}
              name: {{ .Dst }}
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-egress-fqdn")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.NoError()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTPS, "example.com", 443).WithCheck(check.NoError()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.org", 80).WithCheck(check.Error()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTPS, "example.org", 443).WithCheck(check.Error()))
	})
}

func TestSandboxGlobalTrafficPolicy(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	anotherDst := trafficFixture.AnotherServer
	serviceIPBlock, err := network.PrefixCIDR(src.ServiceIPOrFail(t), 16)
	if err != nil {
		t.Fatal(err)
	}

	rig.RunScenario(t, "global egress allow", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "Dst": serviceIPBlock}, `
apiVersion: agents.kruise.io/v1alpha1
kind: GlobalTrafficPolicy
metadata:
  name: gtp-egress
spec:
  priority: 10
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "gtp-egress")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "global ingress deny baseline", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), nil, `
apiVersion: agents.kruise.io/v1alpha1
kind: GlobalTrafficPolicy
metadata:
  name: gtp-egress-baseline
spec:
  priority: 1000
  selector: {}
  egress:
    rules:
      - action: reject
        to:
          - fqdn: "example.com"
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": anotherDst.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-example-org
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - fqdn: "example.org"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, dst, "gtp-egress-baseline")
		waitForPolicyPresent(t, src, "gtp-egress-baseline")
		waitForPolicyPresent(t, anotherDst, "gtp-egress-baseline")
		waitForPolicyPresent(t, anotherDst, "tp-egress-example-org")
		for _, source := range []echo.Instance{src, dst, anotherDst} {
			source.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.Error()))
		}
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.org", 80).WithCheck(check.NoError()))
		dst.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.org", 80).WithCheck(check.NoError()))
		anotherDst.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.org", 80).WithCheck(check.Error()))
	})
}

func TestSandboxPriorityMatching(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	anotherDst := trafficFixture.AnotherServer
	serviceIPBlock, err := network.PrefixCIDR(src.ServiceIPOrFail(t), 16)
	if err != nil {
		t.Fatal(err)
	}

	rig.RunScenario(t, "high priority deny overrides low priority allow", func(t *testing.T, scope *kube.ResourceScope) {
		values := map[string]any{"App": src.Name(), "Dst": serviceIPBlock}
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), values, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-high-priority-deny
spec:
  priority: 10
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(t, kube.CreateOnly)
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), values, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-low-priority-allow
spec:
  priority: 500
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-high-priority-deny")
		waitForPolicyPresent(t, src, "tp-low-priority-allow")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "priority layering infra business internet", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-infra-policy
spec:
  priority: 10
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
`).ApplyOrFail(t, kube.CreateOnly)
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(), "Dst": dst.ServiceIPOrFail(t), "AnotherDst": anotherDst.ServiceIPOrFail(t),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-business-policy
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
      - action: reject
        to:
          - cidr: "{{ .AnotherDst }}"
`).ApplyOrFail(t, kube.CreateOnly)
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-internet-policy
spec:
  priority: 500
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-infra-policy")
		waitForPolicyPresent(t, src, "tp-business-policy")
		waitForPolicyPresent(t, src, "tp-internet-policy")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "kube-dns.kube-system", 9153).WithCheck(check.NoError()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.NoError()))
	})

	rig.RunScenario(t, "same priority rule order matching", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(), "Dst": dst.ServiceIPOrFail(t), "AnotherDst": anotherDst.ServiceIPOrFail(t),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-rule-order-test
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - service:
              namespace: kube-system
              name: kube-dns
      - action: reject
        to:
          - cidr: "{{ .AnotherDst }}"
      - action: allow
        to:
          - cidr: "{{ .Dst }}"
      - action: allow
        to:
          - fqdn: "example.com"
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-rule-order-test")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.org", 80).WithCheck(check.Error()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.NoError()))
	})
}

func TestTrafficPolicyLifecycle(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	environment := suite.Environment(t)
	ns := namespace.Create(t, environment, namespace.Config{Prefix: "agentio-policy"})

	// This first scenario deliberately exercises Agentio's ordinary-Pod
	// compatibility projection. A later scenario must cover a real Sandbox UID and
	// validate the Workload-to-Sandbox binding separately.
	server := echo.Deploy(t, environment, injectedEchoConfig("server", ns.Name()))
	client := echo.Deploy(t, environment, injectedEchoConfig("client", ns.Name()))

	ctx, cancel := e2e.Context(t, 10*time.Minute)
	defer cancel()
	targetCIDR, err := network.PrefixCIDR(server.ServiceIPOrFail(t), 32)
	if err != nil {
		t.Fatalf("derive policy CIDR from echo Service %s/%s: %v", ns.Name(), server.Name(), err)
	}
	call := server.CallOptionsOrFail(t, "http")
	call.Count = 1
	call.Timeout = 2 * time.Second
	call.Retry = retry.Policy{
		Timeout: 90 * time.Second, Delay: 300 * time.Millisecond,
		Backoff: 1.5, MaxDelay: 2 * time.Second, Converge: 3,
	}
	client.CallOrFail(t, call.WithCheck(check.And(check.OK(), check.ReachedWorkloads(1))))

	policyName := "lifecycle"
	selector := map[string]string{"app": client.Name()}
	record, err := environment.Kube.Apply(ctx,
		trafficPolicy(policyName, ns.Name(), selector, "reject", targetCIDR), kube.CreateOnly)
	if err != nil {
		t.Fatalf("create reject TrafficPolicy: %v", err)
	}
	client.CallOrFail(t, call.WithCheck(check.Error()))

	if _, err := environment.Kube.Apply(ctx,
		trafficPolicy(policyName, ns.Name(), selector, "allow", targetCIDR), kube.ReconcileOwned); err != nil {
		t.Fatalf("update TrafficPolicy to allow: %v", err)
	}
	client.CallOrFail(t, call.WithCheck(check.And(check.OK(), check.ReachedWorkloads(1))))

	if _, err := environment.Kube.Apply(ctx,
		trafficPolicy(policyName, ns.Name(), selector, "reject", targetCIDR), kube.ReconcileOwned); err != nil {
		t.Fatalf("update TrafficPolicy back to reject: %v", err)
	}
	client.CallOrFail(t, call.WithCheck(check.Error()))

	if err := environment.Kube.DeleteOwned(ctx, record); err != nil {
		t.Fatalf("delete TrafficPolicy: %v", err)
	}
	client.CallOrFail(t, call.WithCheck(check.And(check.OK(), check.ReachedWorkloads(1))))
}

func injectedEchoConfig(name, namespace string) echo.Config {
	return echo.Config{
		Name: name, Namespace: namespace,
		// Kubernetes admission objectSelector and the injector both evaluate
		// the Pod label.
		Labels:      map[string]string{harness.DataplaneModeLabel: harness.DataplaneModeSidecar},
		CallTimeout: 90 * time.Second,
		Converge:    3,
	}
}
