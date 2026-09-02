//go:build integ

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

package agentio

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/test/framework"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
	"istio.io/istio/tests/integration/pilot/forwardproxy"
)

const (
	connectProxyHost          = "connect-proxy.test"
	invalidConnectProxyHost   = "invalid-connect-proxy.test"
	connectProxyHTTPNodePort  = 32128
	connectProxyHTTPSNodePort = 32129
)

// TestSandboxForwardHTTPConnect sends real CONNECT requests through ext_proc
// and both the cleartext and TLS-terminated forward-http paths. The explicit
// proxy listens on NodePorts so its intercepted address is not a mesh service
// and therefore exercises the sandbox catchall listener rather than service
// routing.
func TestSandboxForwardHTTPConnect(t *testing.T) {
	framework.NewTest(t).
		Run(func(ctx framework.TestContext) {
			proxyKey, proxyCertChain, proxyCA := generateConnectProxyCertificate(ctx, connectProxyHost)
			bootstrap, err := forwardproxy.GenerateForwardProxyBootstrapConfig([]forwardproxy.ListenerSettings{
				{Port: 3128, HTTPVersion: forwardproxy.HTTP1},
				{Port: 4128, HTTPVersion: forwardproxy.HTTP1, TLSEnabled: true},
			})
			if err != nil {
				ctx.Fatalf("generate forward proxy bootstrap: %v", err)
			}

			systemNamespace := i.Settings().SystemNamespace
			ctx.ConfigIstio().EvalFile(systemNamespace, map[string]any{
				"EnvoyYAML":      bootstrap,
				"Namespace":      systemNamespace,
				"ProxyKey":       proxyKey,
				"ProxyCertChain": proxyCertChain,
				"ProxyCA":        proxyCA,
			}, "testdata/forward-http-connect-proxy.yaml").ApplyOrFail(ctx)

			cluster := ctx.Clusters().Default()
			fetchProxy := testKube.NewPodFetch(cluster, systemNamespace, "app=forward-http-connect-proxy")
			if _, err := testKube.WaitUntilPodsAreReady(fetchProxy,
				retry.Timeout(2*time.Minute), retry.Delay(5*time.Second)); err != nil {
				ctx.Fatalf("forward proxy deployment not ready: %v", err)
			}

			ctx.ConfigIstio().Eval(systemNamespace, map[string]any{
				"Namespace": systemNamespace,
			}, `
apiVersion: v1
kind: ConfigMap
metadata:
  name: `+agentioConfigMapName+`
data:
  config: |
    sandboxExtProc:
      service: ext-proc.{{ .Namespace }}.svc.cluster.local
      port: 9002
      failureModeAllow: false
      request:
        headerMode: SEND
        attributes:
        - destination.port
      response:
        headerMode: SEND
    egressPolicies:
    - gateway:
        service: egress-gateway.{{ .Namespace }}.svc.cluster.local
      policy: GATEWAY
    egressGateways:
    - name: egress-gateway
      namespace: {{ .Namespace }}
      tlsTermination:
        includeHosts:
        - "`+connectProxyHost+`"
        - "`+invalidConnectProxyHost+`"
`).ApplyOrFail(ctx)

			nodeIP := firstNodeInternalIP(ctx)
			src := all[0]
			dst := all[1]
			workload := src.WorkloadsOrFail(ctx)[0]
			target := net.JoinHostPort(dst.Address(), "443")

			curlThroughProxy := func(proxyHost, scheme string, proxyPort int) (string, string, error) {
				proxyURL := fmt.Sprintf("%s://%s:%d", scheme, proxyHost, proxyPort)
				resolve := fmt.Sprintf("%s:%d:%s", proxyHost, proxyPort, nodeIP)
				return cluster.PodExec(workload.PodName(), src.NamespaceName(), "app", fmt.Sprintf(
					"curl -sS -k --proxy-insecure --noproxy '' -o /dev/null -w %%{http_code}:%%{http_connect} --connect-timeout 10 --max-time 20 --resolve %s --proxy %s https://%s/",
					resolve, proxyURL, target))
			}

			checkProxySuccess := func(name, scheme string, proxyPort int) {
				ctx.NewSubTest(name).Run(func(ctx framework.TestContext) {
					retry.UntilSuccessOrFail(ctx, func() error {
						stdout, stderr, err := curlThroughProxy(connectProxyHost, scheme, proxyPort)
						if err != nil {
							return fmt.Errorf("curl through %s failed: %v; stdout=%q stderr=%q", name, err, stdout, stderr)
						}
						if codes := strings.TrimSpace(stdout); codes != "200:200" {
							return fmt.Errorf("curl through %s returned target:CONNECT codes %s, want 200:200; stderr=%q", name, codes, stderr)
						}
						return nil
					}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
				})
			}

			checkProxySuccess("HTTP proxy", "http", connectProxyHTTPNodePort)

			ctx.NewSubTest("HTTPS proxy certificate SAN mismatch").Run(func(ctx framework.TestContext) {
				retry.UntilSuccessOrFail(ctx, func() error {
					stdout, stderr, curlErr := curlThroughProxy(invalidConnectProxyHost, "https", connectProxyHTTPSNodePort)
					codes := strings.Split(strings.TrimSpace(stdout), ":")
					if len(codes) != 2 {
						return fmt.Errorf("parse curl target:CONNECT codes %q: curl error=%v stderr=%q", stdout, curlErr, stderr)
					}
					code, err := strconv.Atoi(codes[1])
					if err != nil {
						return fmt.Errorf("parse curl CONNECT code %q: %v; curl error=%v stderr=%q", codes[1], err, curlErr, stderr)
					}
					if code < 500 || code > 599 {
						return fmt.Errorf("SAN-mismatched HTTPS proxy returned CONNECT %d, want 5xx rejection; curl error=%v stderr=%q", code, curlErr, stderr)
					}
					return nil
				}, retry.Timeout(2*time.Minute), retry.Delay(5*time.Second))
			})

			checkProxySuccess("HTTPS proxy", "https", connectProxyHTTPSNodePort)
		})
}

func firstNodeInternalIP(ctx framework.TestContext) string {
	nodes, err := ctx.Clusters().Default().Kube().CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		ctx.Fatalf("list nodes: %v", err)
	}
	for _, node := range nodes.Items {
		for _, address := range node.Status.Addresses {
			if address.Type == corev1.NodeInternalIP {
				return address.Address
			}
		}
	}
	ctx.Fatal("no node InternalIP found")
	return ""
}

func generateConnectProxyCertificate(ctx framework.TestContext, dnsNames ...string) (string, string, string) {
	if len(dnsNames) == 0 {
		ctx.Fatal("at least one certificate DNS name is required")
	}
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		ctx.Fatalf("generate proxy CA key: %v", err)
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
		ctx.Fatalf("create proxy CA certificate: %v", err)
	}

	proxyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		ctx.Fatalf("generate proxy server key: %v", err)
	}
	proxyTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	proxyDER, err := x509.CreateCertificate(rand.Reader, proxyTemplate, caTemplate, &proxyKey.PublicKey, caKey)
	if err != nil {
		ctx.Fatalf("create proxy server certificate: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(proxyKey)})
	proxyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxyDER})
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return string(keyPEM), string(append(proxyPEM, caPEM...)), string(caPEM)
}
