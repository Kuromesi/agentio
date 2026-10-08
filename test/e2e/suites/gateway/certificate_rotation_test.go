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

package gateway

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// Explicitly opt in: this test waits for real certificate clocks and interrupts
// the suite-owned control plane. It must not run in parallel with other tests.
func TestSandboxOnDemandCertificateRotation(t *testing.T) {
	if os.Getenv("AGENTIO_E2E_CERT_ROTATION") != "1" {
		t.Skip("set AGENTIO_E2E_CERT_ROTATION=1 to run the slow certificate rotation test")
	}
	environment, scope := rig.BeginScenario(t)
	namespace := resolvedAgentioConfig.Namespace
	restoreReplicas := configureRotationIssuer(t, environment)
	host := fmt.Sprintf("upstream-tls.%s.svc.cluster.local", namespace)
	key, chain, ca := generateConnectProxyCertificate(t, host)
	applyGatewayTLSTerminationProfile(t, scope, host)
	e2econfig.New(scope).EvalFile(namespace, map[string]any{
		"Namespace":         namespace,
		"ServerKey":         key,
		"ServerCertChain":   chain,
		"ServerCA":          ca,
		"ForwardProxyImage": resolvedAgentioConfig.ForwardProxyImage,
	}, "testdata/upstream-tls.yaml").ApplyOrFail(t, kube.CreateOnly)
	ctx, cancel := e2e.Context(t, 8*time.Minute)
	defer cancel()
	if _, err := environment.Kube.WaitReadyPods(ctx, namespace, "app=upstream-tls", 1); err != nil {
		t.Fatal(err)
	}
	rig.ApplyConfig(t, scope, map[string]any{"Namespace": namespace, "Host": host}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+harness.ConfigMapName+`
data:
  config: |
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        includeHosts: ["{{ .Host }}"]
`)
	secret, err := environment.Cluster.Kube.CoreV1().Secrets(namespace).Get(ctx, "agentio-mitm-ca", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	roots := string(secret.Data["root-cert.pem"])
	if roots == "" {
		t.Fatal("MITM root bundle is empty")
	}
	gateway, err := firstReadyPod(ctx, environment, namespace, harness.GatewayPodSelector)
	if err != nil {
		t.Fatal(err)
	}
	probe := func() (*x509.Certificate, error) {
		return rotationCertificate(ctx, environment, host, roots)
	}
	var initial *x509.Certificate
	harness.RetryAssertion(t, time.Minute, time.Second, func() error {
		initial, err = probe()
		return err
	})
	if remaining := time.Until(initial.NotAfter); remaining > 75*time.Second || remaining < 45*time.Second {
		t.Fatalf("unexpected remaining leaf lifetime %s; short-lived issuer is not active", remaining)
	}
	t.Logf("initial serial=%s expires=%s", initial.SerialNumber, initial.NotAfter.Format(time.RFC3339Nano))

	// Once configuration has converged, do not retry away failed handshakes.
	// Two successive serial changes prove repeated real leaf rotation.
	current := initial
	for round := 1; round <= 2; round++ {
		deadline := current.NotAfter.Add(10 * time.Second)
		attempts := 0
		var slowest time.Duration
		for {
			started := time.Now()
			fresh, err := probe()
			slowest = max(slowest, time.Since(started))
			attempts++
			if err != nil {
				t.Fatalf("rotation %d handshake %d: %v", round, attempts, err)
			}
			if fresh.SerialNumber.Cmp(current.SerialNumber) != 0 {
				if !fresh.NotAfter.After(current.NotAfter) {
					t.Fatal("replacement certificate did not extend validity")
				}
				t.Logf(
					"rotation=%d handshakes=%d max_latency=%s serial=%s expires=%s",
					round,
					attempts,
					slowest,
					fresh.SerialNumber,
					fresh.NotAfter.Format(time.RFC3339Nano),
				)
				current = fresh
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("certificate did not rotate")
			}
			time.Sleep(250 * time.Millisecond)
		}
	}

	// Scaling every issuer to zero severs existing SDS streams as well as
	// reconnects. The business path, Envoy and upstream remain alive.
	if err := restoreReplicas(ctx, 0); err != nil {
		t.Fatal(err)
	}
	harness.RetryAssertion(t, 45*time.Second, time.Second, func() error {
		pods, err := environment.Cluster.Kube.CoreV1().
			Pods(namespace).
			List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=agentiod"})
		if err != nil {
			return err
		}
		if len(pods.Items) != 0 {
			return fmt.Errorf("%d issuer pods still exist", len(pods.Items))
		}
		return nil
	})
	cached, err := probe()
	if err != nil {
		t.Fatalf("valid cached certificate unavailable during outage: %v", err)
	}
	if cached.SerialNumber.Cmp(current.SerialNumber) != 0 {
		t.Fatal("certificate changed while issuer was offline")
	}
	before, err := activeCertificateCopies(ctx, environment, gateway.Name, host)
	if err != nil || before < 1 {
		t.Fatalf("no active on-demand certificate before TTL: active=%d error=%v", before, err)
	}
	// TTL is relative to receipt; allow a small transport/scheduling tolerance.
	wait := time.Until(current.NotAfter.Add(3 * time.Second))
	if wait > 0 {
		time.Sleep(wait)
	}
	harness.RetryAssertion(t, 10*time.Second, time.Second, func() error {
		active, err := activeCertificateCopies(ctx, environment, gateway.Name, host)
		if err != nil {
			return err
		}
		if active != 0 {
			return fmt.Errorf("Envoy retained %d certificates after TTL with issuer offline", active)
		}
		return nil
	})
	t.Log("Envoy expired its on-demand certificate while all issuers were offline")
	if _, err := probe(); err == nil {
		t.Fatal("HTTPS unexpectedly succeeded after certificate expiry during outage")
	}
	if err := restoreReplicas(ctx, 1); err != nil {
		t.Fatal(err)
	}
	harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error {
		fresh, err := probe()
		if err != nil {
			return err
		}
		if fresh.SerialNumber.Cmp(current.SerialNumber) == 0 {
			return fmt.Errorf("old certificate survived issuer recovery")
		}
		t.Logf("recovered serial=%s expires=%s", fresh.SerialNumber, fresh.NotAfter.Format(time.RFC3339Nano))
		return nil
	})
	final, err := environment.Cluster.Kube.CoreV1().Pods(namespace).Get(ctx, gateway.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if final.UID != gateway.UID {
		t.Fatal("Envoy was replaced during certificate rotation")
	}
	for i, status := range final.Status.ContainerStatuses {
		if status.RestartCount != gateway.Status.ContainerStatuses[i].RestartCount {
			t.Fatal("Envoy restarted during certificate rotation")
		}
	}
}

// Save and restore only the deployment fields changed by this test, including
// on assertion failure. A dedicated suite-owned installation is required.
func configureRotationIssuer(t *testing.T, environment *e2e.Environment) func(context.Context, int32) error {
	t.Helper()
	if resolvedAgentioConfig.Reuse {
		t.Fatal("certificate rotation requires agentio.reuse=false")
	}
	ctx, cancel := e2e.Context(t, 2*time.Minute)
	defer cancel()
	api := environment.Cluster.Kube.AppsV1().Deployments(resolvedAgentioConfig.Namespace)
	deployments, err := api.List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=agentiod"})
	if err != nil || len(deployments.Items) != 1 {
		t.Fatalf("find unique issuer deployment: %v", err)
	}
	original := deployments.Items[0].DeepCopy()
	if original.Spec.Replicas == nil || *original.Spec.Replicas != 1 {
		t.Fatal("rotation test requires exactly one issuer replica")
	}
	updated := original.DeepCopy()
	index := slices.IndexFunc(
		updated.Spec.Template.Spec.Containers,
		func(c corev1.Container) bool { return c.Name == "discovery" },
	)
	if index < 0 {
		t.Fatal("agentiod container not found")
	}
	originalEnv := slices.Clone(original.Spec.Template.Spec.Containers[index].Env)
	scale := func(ctx context.Context, replicas int32) error {
		current, err := api.GetScale(ctx, original.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		current.Spec.Replicas = replicas
		_, err = api.UpdateScale(ctx, original.Name, current, metav1.UpdateOptions{})
		return err
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		current, err := api.Get(cleanupCtx, original.Name, metav1.GetOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		current.Spec.Replicas = original.Spec.Replicas
		current.Spec.Template.Spec.Containers[index].Env = originalEnv
		if _, err := api.Update(cleanupCtx, current, metav1.UpdateOptions{}); err != nil {
			t.Error(err)
		}
	})
	env := &updated.Spec.Template.Spec.Containers[index].Env
	for name, value := range map[string]string{
		"AGENTIO_MITM_LEAF_LIFETIME": "75s",
		"AGENTIO_MITM_RENEW_BEFORE":  "45s",
		"AGENTIO_MITM_CACHE_MAX_AGE": "1h",
	} {
		*env = slices.DeleteFunc(*env, func(v corev1.EnvVar) bool { return v.Name == name })
		*env = append(*env, corev1.EnvVar{Name: name, Value: value})
	}
	if _, err := api.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	harness.RetryAssertion(t, 2*time.Minute, time.Second, func() error {
		deployment, err := api.Get(ctx, original.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if deployment.Status.ObservedGeneration < deployment.Generation || deployment.Status.UpdatedReplicas != 1 ||
			deployment.Status.ReadyReplicas != 1 || deployment.Status.Replicas != 1 {
			return fmt.Errorf("issuer rollout has not converged")
		}
		pods, err := environment.Cluster.Kube.CoreV1().Pods(resolvedAgentioConfig.Namespace).
			List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=agentiod"})
		if err != nil {
			return err
		}
		if len(pods.Items) != 1 || pods.Items[0].DeletionTimestamp != nil {
			return fmt.Errorf("old issuer pods have not terminated")
		}
		return nil
	})
	return scale
}

func rotationCertificate(
	ctx context.Context,
	environment *e2e.Environment,
	host, roots string,
) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	workloads, err := trafficFixture.Client.Workloads(ctx)
	if err != nil {
		return nil, fmt.Errorf("find TLS probe client: %w", err)
	}
	if len(workloads) == 0 {
		return nil, fmt.Errorf("no ready TLS probe client")
	}
	// Each curl process makes a fresh TLS connection, strictly verifies the
	// MITM CA/SAN/time and reports the peer certificate, plus upstream HTTP 200.
	stdout, stderr, err := environment.Kube.Exec(
		ctx,
		trafficFixture.Client.Namespace(),
		workloads[0].Name,
		"app",
		[]string{
			"curl", "-sS", "--http1.1", "--noproxy", "*", "--cacert", "/dev/stdin",
			"--connect-timeout", "5", "--max-time", "8", "--no-sessionid",
			"--resolve", host + ":18443:192.0.2.1", "-H", "Connection: close",
			"-w", "\\n%{http_code}\\n%{certs}", "https://" + host + ":18443/",
		},
		strings.NewReader(roots),
	)
	if err != nil {
		return nil, fmt.Errorf("TLS probe: %w; stderr=%s", err, stderr)
	}
	if !strings.HasPrefix(stdout, "tls13\n200\n") {
		return nil, fmt.Errorf("unexpected upstream response: %q", stdout)
	}
	start := strings.Index(stdout, "-----BEGIN CERTIFICATE-----")
	if start < 0 {
		return nil, fmt.Errorf("curl did not report peer certificate: %s", stderr)
	}
	block, _ := pem.Decode([]byte(stdout[start:]))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("curl did not report peer certificate: %s", stderr)
	}
	return x509.ParseCertificate(block.Bytes)
}

// Older supported Envoy builds do not expose cert_active. The SDS admin dump
// identifies the exact active secret and distinguishes TTL eviction from a
// client merely rejecting an expired certificate.
func activeCertificateCopies(ctx context.Context, environment *e2e.Environment, pod, name string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stdout, stderr, err := environment.Kube.Exec(ctx, resolvedAgentioConfig.Namespace, pod, "agentio-proxy",
		[]string{"curl", "-fsS", "localhost:15000/config_dump?resource=dynamic_active_secrets"}, nil)
	if err != nil {
		return 0, fmt.Errorf("Envoy active secrets: %w; %s", err, stderr)
	}
	var dump struct {
		Configs []struct {
			Type string `json:"@type"`
			Name string `json:"name"`
		} `json:"configs"`
	}
	if err := json.Unmarshal([]byte(stdout), &dump); err != nil {
		return 0, err
	}
	active, found := 0, false
	for _, secret := range dump.Configs {
		if secret.Type != "type.googleapis.com/envoy.admin.v3.SecretsConfigDump.DynamicSecret" {
			continue
		}
		found = true
		if secret.Name == name {
			active++
		}
	}
	// Workload default/ROOTCA secrets must remain loaded during the outage.
	if !found {
		return 0, fmt.Errorf("Envoy did not report any active SDS secrets")
	}
	return active, nil
}
