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
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

// Save and restore only the deployment fields changed by this test, including
// on assertion failure. A dedicated suite-owned installation is required.
func configureCertificateIssuer(
	t *testing.T,
	environment *e2e.Environment,
	overrides map[string]string,
) func(context.Context, int32) error {
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
	waitReady := func(ctx context.Context) {
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
			return
		}
		waitReady(cleanupCtx)
	})
	env := &updated.Spec.Template.Spec.Containers[index].Env
	for name, value := range overrides {
		*env = slices.DeleteFunc(*env, func(v corev1.EnvVar) bool { return v.Name == name })
		*env = append(*env, corev1.EnvVar{Name: name, Value: value})
	}
	if _, err := api.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitReady(ctx)
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
		[]string{"curl", "-fsS", "localhost:15000/config_dump?resource=dynamic_active_secrets&mask=name"}, nil)
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
