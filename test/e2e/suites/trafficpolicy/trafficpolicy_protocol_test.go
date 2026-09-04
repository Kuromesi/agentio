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

func TestSandboxTrafficPolicyProtocol(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	serviceIPBlock, err := network.PrefixCIDR(src.ServiceIPOrFail(t), 16)
	if err != nil {
		t.Fatal(err)
	}

	rig.RunScenario(t, "allow all TCP only", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "Dst": serviceIPBlock}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-allow-all-tcp
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
          - cidr: "{{ .Dst }}"
        ports:
          - protocol: TCP
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-allow-all-tcp")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.TCP, dst.Address(), 9090).WithCheck(check.NoError()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, "example.com", 80).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "allow specific port with protocol", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "Dst": serviceIPBlock}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-port-with-proto
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
          - cidr: "{{ .Dst }}"
        ports:
          - protocol: TCP
            port: 80
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-port-with-proto")
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dst.Address(), 80).WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTPS, dst.Address(), 9443).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "deny UDP blocks DNS", func(t *testing.T, scope *kube.ResourceScope) {
		requireFirewallRules(t)
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-deny-udp-dns
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        ports:
          - protocol: UDP
            port: 53
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-deny-udp-dns")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dst.WorkloadsOrFail(t)[0].Address, 18080).WithCheck(check.OK()))
	})

	rig.RunScenario(t, "mixed protocol rules", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "Dst": serviceIPBlock}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-mixed-proto
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
          - cidr: "{{ .Dst }}"
        ports:
          - protocol: TCP
            port: 80
          - protocol: TCP
            port: 9090
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-mixed-proto")
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dst.Address(), 80).WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.TCP, dst.Address(), 9090).WithCheck(check.NoError()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTPS, dst.Address(), 9443).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "ingress allow specific port with protocol", func(t *testing.T, scope *kube.ResourceScope) {
		srcIP := src.WorkloadsOrFail(t)[0].Address
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": dst.Name(), "Src": srcIP}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-port-with-proto
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - cidr: "{{ .Src }}"
        ports:
          - protocol: TCP
            port: 18080
      - action: reject
        from:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, dst, "tp-ingress-port-with-proto")
		dstIP := dst.WorkloadsOrFail(t)[0].Address
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dstIP, 18080).WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTPS, dstIP, 19443).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "deny TCP does not block ICMP", func(t *testing.T, scope *kube.ResourceScope) {
		requireFirewallRules(t)
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(), "Namespace": src.Namespace(), "DstService": dst.Name(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-deny-tcp-not-icmp
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        ports:
          - protocol: UDP
      - action: reject
        ports:
          - protocol: TCP
        to:
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .DstService }}"
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-deny-tcp-not-icmp")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
		requirePingState(t, src, dst.WorkloadsOrFail(t)[0].Address, true)
	})

	rig.RunScenario(t, "deny ICMP does not block TCP", func(t *testing.T, scope *kube.ResourceScope) {
		requireFirewallRules(t)
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(), "Namespace": src.Namespace(), "DstService": dst.Name(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-deny-icmp-not-tcp
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        ports:
          - protocol: UDP
      - action: reject
        ports:
          - protocol: ICMP
        to:
          - service:
              namespace: "{{ .Namespace }}"
              name: "{{ .DstService }}"
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-deny-icmp-not-tcp")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		requirePingState(t, src, dst.WorkloadsOrFail(t)[0].Address, false)
	})
}
