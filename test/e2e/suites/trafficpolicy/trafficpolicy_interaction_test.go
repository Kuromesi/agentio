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

	"github.com/openkruise/agentio/test/e2e/components/echo"
	"github.com/openkruise/agentio/test/e2e/components/echo/check"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/network"
)

func TestPolicyInteraction(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	anotherDst := trafficFixture.AnotherServer
	serviceIPBlock, err := network.PrefixCIDR(src.ServiceIPOrFail(t), 16)
	if err != nil {
		t.Fatal(err)
	}

	rig.RunScenario(t, "multiple policies on same pod", func(t *testing.T, scope *kube.ResourceScope) {
		anotherBlock, err := network.PrefixCIDR(anotherDst.WorkloadsOrFail(t)[0].Address, 24)
		if err != nil {
			t.Fatal(err)
		}
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "Dst": serviceIPBlock}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-multi-pol-a
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
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "CidrBlock": anotherBlock}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-multi-pol-b
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "{{ .CidrBlock }}"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-multi-pol-a")
		waitForPolicyPresent(t, src, "tp-multi-pol-b")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "egress and ingress in single policy", func(t *testing.T, scope *kube.ResourceScope) {
		srcBlock, err := network.PrefixCIDR(src.WorkloadsOrFail(t)[0].Address, 24)
		if err != nil {
			t.Fatal(err)
		}
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"DstApp": dst.Name(), "SrcBlock": srcBlock}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-combined-egress-ingress
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .DstApp }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: "198.51.100.0/24"
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
  ingress:
    rules:
      - action: allow
        from:
          - cidr: "{{ .SrcBlock }}"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, dst, "tp-combined-egress-ingress")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		dst.CallOrFail(t, src.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "new high-priority policy overrides existing", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "Dst": serviceIPBlock}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-override-allow
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
		waitForPolicyPresent(t, src, "tp-override-allow")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))

		overridePlan := e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(), "Dst": dst.ServiceIPOrFail(t),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-override-deny
spec:
  priority: 10
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: {{ .Dst }}
`)
		records := overridePlan.ApplyOrFail(t, kube.CreateOnly)
		if len(records) != 1 {
			t.Fatalf("override deny records = %d, want 1", len(records))
		}
		waitForPolicyPresent(t, src, "tp-override-deny")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		overridePlan.DeleteOrFail(t)
		waitForPolicyGone(t, src, "tp-override-deny")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})
}

func TestSandboxTrafficPolicyComplexRules(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	anotherDst := trafficFixture.AnotherServer

	rig.RunScenario(t, "egress multi service multi port cartesian", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(), "Namespace": src.Namespace(), "DstService": dst.Name(), "AltService": anotherDst.Name(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-multi-svc-port
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
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .DstService }}"
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .AltService }}"
        ports:
          - protocol: TCP
            port: 80
          - protocol: TCP
            port: 9090
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-egress-multi-svc-port")
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dst.Address(), 80).WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.TCP, anotherDst.Address(), 9090).WithCheck(check.NoError()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTPS, dst.Address(), 9443).WithCheck(check.Error()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "ingress multi source port range cartesian", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": dst.Name(), "Namespace": dst.Namespace(), "SrcService": src.Name(), "AltService": anotherDst.Name(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-multi-src-port-range
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .SrcService }}"
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .AltService }}"
        ports:
          - protocol: TCP
            port: 18080
            endPort: 18081
      - action: reject
        from:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, dst, "tp-ingress-multi-src-port-range")
		dstIP := dst.WorkloadsOrFail(t)[0].Address
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dstIP, 18080).WithCheck(check.OK()))
		anotherDst.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dstIP, 18080).WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTPS, dstIP, 19443).WithCheck(check.Error()))
	})
}
