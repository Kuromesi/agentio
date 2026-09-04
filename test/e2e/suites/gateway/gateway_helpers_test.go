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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/test/e2e"
	e2econfig "github.com/openkruise/agentio/test/e2e/config"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/suites/internal/harness"
)

func firstReadyPod(
	ctx context.Context,
	environment *e2e.Environment,
	namespaceName, selector string,
) (corev1.Pod, error) {
	if environment == nil || environment.Kube == nil {
		return corev1.Pod{}, fmt.Errorf("ready Pod lookup requires a Kubernetes environment")
	}
	pods, err := environment.Kube.ReadyPods(ctx, namespaceName, selector)
	if err != nil {
		return corev1.Pod{}, err
	}
	if len(pods) == 0 {
		return corev1.Pod{}, fmt.Errorf("no ready Pods in namespace %s matching %q", namespaceName, selector)
	}
	return pods[0], nil
}

func execFirstReadyPod(
	ctx context.Context,
	environment *e2e.Environment,
	namespaceName, selector, container string,
	command []string,
) (string, string, error) {
	pod, err := firstReadyPod(ctx, environment, namespaceName, selector)
	if err != nil {
		return "", "", err
	}
	return environment.Kube.Exec(ctx, namespaceName, pod.Name, container, command, nil)
}

func logsFirstReadyPod(
	ctx context.Context,
	environment *e2e.Environment,
	namespaceName, selector, container string,
	tailLines *int64,
) (string, error) {
	pod, err := firstReadyPod(ctx, environment, namespaceName, selector)
	if err != nil {
		return "", err
	}
	return environment.Kube.Logs(ctx, namespaceName, pod.Name, container, tailLines)
}

func matchingGatewayAccessLog(logs, requestID, authority string) (string, bool) {
	for _, line := range strings.Split(logs, "\n") {
		fields := struct {
			Method       string `json:"method"`
			RequestID    string `json:"request_id"`
			AuthorityFor string `json:"authority_for"`
		}{}
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			continue
		}
		if fields.Method == "POST" &&
			fields.RequestID == requestID &&
			fields.AuthorityFor == authority {
			return line, true
		}
	}
	return "", false
}

func waitForGatewayAccessLog(
	t *testing.T,
	environment *e2e.Environment,
	requestID, authority string,
) {
	t.Helper()
	var matched string
	tailLines := int64(500)
	harness.RetryAssertion(t, 30*time.Second, time.Second, func() error {
		ctx, cancel := e2e.Context(t, 10*time.Second)
		defer cancel()
		logs, err := logsFirstReadyPod(
			ctx,
			environment,
			resolvedAgentioConfig.Namespace,
			harness.GatewayPodSelector,
			"agentio-proxy",
			&tailLines,
		)
		if err != nil {
			return err
		}
		var found bool
		matched, found = matchingGatewayAccessLog(logs, requestID, authority)
		if !found {
			return fmt.Errorf("gateway access log does not contain gRPC request %q to %q", requestID, authority)
		}
		return nil
	})
	t.Logf("egress gateway handled the gRPC request: %s", matched)
}

func getEgressGatewayConfigDump(ctx context.Context, environment *e2e.Environment) (string, error) {
	stdout, stderr, err := execFirstReadyPod(
		ctx,
		environment,
		resolvedAgentioConfig.Namespace,
		harness.GatewayPodSelector,
		"agentio-proxy",
		[]string{"curl", "-sS", "localhost:15000/config_dump"},
	)
	if err != nil {
		return "", fmt.Errorf("egress gateway config_dump failed: %w; stderr: %s", err, stderr)
	}
	if strings.Contains(stdout, "error_state") {
		return "", fmt.Errorf("egress gateway config_dump contains error_state, xDS push rejected by Envoy")
	}
	return stdout, nil
}

// externalCurl executes curl from the shared sandbox client without a shell.
// Callers supply individual arguments after the common silent/show-error flags.
func externalCurl(ctx context.Context, arguments ...string) (string, string, error) {
	command := append([]string{"curl", "-sS"}, arguments...)
	stdout, stderr, err := trafficFixture.Client.Exec(ctx, command)
	if err != nil {
		return stdout, stderr, fmt.Errorf("external curl failed: %w; stderr: %s", err, stderr)
	}
	return stdout, stderr, nil
}

// applyGatewayTLSTerminationProfile opts the shared client into TLS
// termination when the Agentio suite enables SNI traffic policy. In that
// mode, AgentioConfig.tlsTermination is the certificate authorization boundary
// while a SecurityProfile is the per-Sandbox termination decision.
func applyGatewayTLSTerminationProfile(t *testing.T, scope *kube.ResourceScope, hosts ...string) {
	t.Helper()
	if len(hosts) == 0 {
		t.Fatal("TLS termination profile requires at least one host")
	}
	e2econfig.New(scope).Eval(trafficFixture.Namespace.Name(), map[string]any{
		"Hosts": hosts,
	}, `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: gateway-tls-termination
spec:
  priority: 10
  selector:
    matchLabels:
      app: client
  rules:
  - name: terminate-test-hosts
    match:
    - domains:
{{- range .Hosts }}
      - {{ printf "%q" . }}
{{- end }}
      schemes:
      - https
    actions:
      bypass: true
`).ApplyOrFail(t, kube.CreateOnly)
}

func generateConnectProxyCertificate(t testing.TB, dnsName string) (string, string, string) {
	t.Helper()
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate proxy CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Agentio CONNECT proxy test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create proxy CA certificate: %v", err)
	}

	proxyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate proxy server key: %v", err)
	}
	proxyTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	proxyDER, err := x509.CreateCertificate(rand.Reader, proxyTemplate, caTemplate, &proxyKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create proxy server certificate: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(proxyKey)})
	proxyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxyDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return string(keyPEM), string(append(proxyPEM, caPEM...)), string(caPEM)
}
