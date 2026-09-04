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
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func TestSandboxTrafficPolicyMatchExpressions(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	anotherDst := trafficFixture.AnotherServer

	rig.RunScenario(t, "matchExpressions In", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-in
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: In
        values:
          - "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-matchexpr-in")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		src.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "matchExpressions NotIn", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-notin-allow
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: In
        values:
          - "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"SrcApp": src.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-notin-deny
spec:
  priority: 50
  selector:
    matchExpressions:
      - key: app
        operator: NotIn
        values:
          - "{{ .SrcApp }}"
  egress:
    rules:
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-matchexpr-notin-allow")
		waitForPolicyPresent(t, dst, "tp-matchexpr-notin-deny")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		dst.CallOrFail(t, src.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
	})

	rig.RunScenario(t, "matchExpressions Exists", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-exists
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: Exists
  egress:
    rules:
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-matchexpr-exists")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		dst.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "matchExpressions DoesNotExist", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"SrcApp": src.Name()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-doesnotexist
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: DoesNotExist
  egress:
    rules:
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyGone(t, src, "tp-matchexpr-doesnotexist")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "matchExpressions multiple expressions", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"SrcApp": src.Name(), "LabelSandboxProxy": harness.DataplaneModeLabel}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-multi
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: In
        values:
          - "{{ .SrcApp }}"
      - key: "{{ .LabelSandboxProxy }}"
        operator: Exists
  egress:
    rules:
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-matchexpr-multi")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		dst.CallOrFail(t, anotherDst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
	})

	rig.RunScenario(t, "matchExpressions with ingress", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"DstApp": dst.Name(), "SrcApp": src.Name(), "SrcAppNamespace": src.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-matchexpr-ingress
spec:
  priority: 100
  selector:
    matchExpressions:
      - key: app
        operator: In
        values:
          - "{{ .DstApp }}"
  ingress:
    rules:
      - action: allow
        from:
          - service:
              name: "{{ .SrcApp }}"
              namespace: "{{ .SrcAppNamespace }}"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, dst, "tp-matchexpr-ingress")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		anotherDst.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
	})
}

func TestSandboxTrafficPolicyWorkloadPeer(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	anotherDst := trafficFixture.AnotherServer

	rig.RunScenario(t, "egress deny with workload peer", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(), "DstApp": dst.Name(), "DstNamespace": dst.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-deny-workload
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: reject
        to:
          - workload:
              namespace: "{{ .DstNamespace }}"
              selector:
                app: "{{ .DstApp }}"
      - action: allow
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-egress-deny-workload")
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dst.WorkloadsOrFail(t)[0].Address, 18080).WithCheck(check.Error()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, anotherDst.WorkloadsOrFail(t)[0].Address, 18080).WithCheck(check.OK()))
	})

	rig.RunScenario(t, "egress allow with workload peer", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(), "DstApp": dst.Name(), "DstNamespace": dst.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-allow-workload
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - workload:
              namespace: "{{ .DstNamespace }}"
              selector:
                app: "{{ .DstApp }}"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-egress-allow-workload")
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dst.WorkloadsOrFail(t)[0].Address, 18080).WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, anotherDst.WorkloadsOrFail(t)[0].Address, 18080).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "ingress allow with workload peer", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": dst.Name(), "SrcApp": src.Name(), "SrcNamespace": src.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-allow-workload
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: allow
        from:
          - workload:
              namespace: "{{ .SrcNamespace }}"
              selector:
                app: "{{ .SrcApp }}"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, dst, "tp-ingress-allow-workload")
		dstIP := dst.WorkloadsOrFail(t)[0].Address
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dstIP, 18080).WithCheck(check.OK()))
		anotherDst.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dstIP, 18080).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "egress allow workload with port restriction", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": src.Name(), "DstApp": dst.Name(), "DstNamespace": dst.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-egress-workload-port
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  egress:
    rules:
      - action: allow
        to:
          - workload:
              namespace: "{{ .DstNamespace }}"
              selector:
                app: "{{ .DstApp }}"
        ports:
          - port: 18080
            endPort: 18081
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-egress-workload-port")
		dstIP := dst.WorkloadsOrFail(t)[0].Address
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dstIP, 18080).WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTPS, dstIP, 19443).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "ingress deny workload then allow all", func(t *testing.T, scope *kube.ResourceScope) {
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
			"App": dst.Name(), "AnotherDstApp": anotherDst.Name(), "AnotherDstNs": anotherDst.Namespace(),
		}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-ingress-deny-workload-allow-all
spec:
  priority: 100
  selector:
    matchLabels:
      app: "{{ .App }}"
  ingress:
    rules:
      - action: reject
        from:
          - workload:
              namespace: "{{ .AnotherDstNs }}"
              selector:
                app: "{{ .AnotherDstApp }}"
      - action: allow
        from:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, dst, "tp-ingress-deny-workload-allow-all")
		dstIP := dst.WorkloadsOrFail(t)[0].Address
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dstIP, 18080).WithCheck(check.OK()))
		anotherDst.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dstIP, 18080).WithCheck(check.Error()))
	})
}

func TestSandboxTrafficPolicyManualEndpoints(t *testing.T) {
	rig.RequireLive(t)
	rig.RequireUncontaminated(t)
	src := trafficFixture.Client
	dst := trafficFixture.Server
	anotherDst := trafficFixture.AnotherServer

	rig.RunScenario(t, "egress allow with selectorless service and manual endpointslice", func(t *testing.T, scope *kube.ResourceScope) {
		dstIP := dst.WorkloadsOrFail(t)[0].Address
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"DstIP": dstIP}, `
apiVersion: v1
kind: Service
metadata:
  name: manual-svc
spec:
  clusterIP: None
  ports:
    - name: http
      port: 80
      targetPort: 18080
      protocol: TCP
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: manual-svc-slice
  labels:
    kubernetes.io/service-name: manual-svc
addressType: IPv4
ports:
  - name: http
    port: 18080
    protocol: TCP
endpoints:
  - addresses:
      - "{{ .DstIP }}"
`).ApplyOrFail(t, kube.CreateOnly)
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": src.Name(), "Namespace": src.Namespace()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-manual-ep
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
              name: manual-svc
      - action: reject
        to:
          - cidr: "0.0.0.0/0"
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, src, "tp-manual-ep")
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, dstIP, 18080).WithCheck(check.OK()))
		src.CallOrFail(t, echo.CallOptionsForAddress(echo.HTTP, anotherDst.WorkloadsOrFail(t)[0].Address, 18080).WithCheck(check.Error()))
	})

	rig.RunScenario(t, "ingress allow with selectorless service and manual endpointslice", func(t *testing.T, scope *kube.ResourceScope) {
		srcIP := src.WorkloadsOrFail(t)[0].Address
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"SrcIP": srcIP}, `
apiVersion: v1
kind: Service
metadata:
  name: manual-src-svc
spec:
  clusterIP: None
  ports:
    - name: http
      port: 80
      targetPort: 18080
      protocol: TCP
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: manual-src-svc-slice
  labels:
    kubernetes.io/service-name: manual-src-svc
addressType: IPv4
ports:
  - name: http
    port: 18080
    protocol: TCP
endpoints:
  - addresses:
      - "{{ .SrcIP }}"
`).ApplyOrFail(t, kube.CreateOnly)
		e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{"App": dst.Name(), "Namespace": dst.Namespace()}, `
apiVersion: agents.kruise.io/v1alpha1
kind: TrafficPolicy
metadata:
  name: tp-manual-ep-ingress
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
              name: manual-src-svc
`).ApplyOrFail(t, kube.CreateOnly)
		waitForPolicyPresent(t, dst, "tp-manual-ep-ingress")
		src.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.OK()))
		anotherDst.CallOrFail(t, dst.CallOptionsOrFail(t, "http").WithCheck(check.Error()))
	})
}
