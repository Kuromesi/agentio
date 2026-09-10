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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/kube"
	"github.com/openkruise/agentio/test/e2e/retry"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const gatewayName = "egress-gateway"
const Marker = "x-agentio-e2e-gateway"

var gateways = schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"}

func object(namespace, kind, name string, fields map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": kind, "metadata": map[string]any{"name": name, "namespace": namespace}}}
	for k, v := range fields {
		u.Object[k] = v
	}
	return u
}

func Gateway(namespace, name string) *unstructured.Unstructured {
	u := object(namespace, "Gateway", name, map[string]any{"spec": map[string]any{
		"gatewayClassName": "agentio-agentgateway",
		"infrastructure":   map[string]any{"parametersRef": map[string]any{"group": "", "kind": "ConfigMap", "name": name + "-config"}},
		"listeners":        []any{map[string]any{"name": "mesh", "protocol": "HBONE", "port": int64(15008)}, map[string]any{"name": "http", "protocol": "HTTP", "port": int64(8080)}},
	}})
	u.SetAPIVersion("gateway.networking.k8s.io/v1")
	u.SetAnnotations(map[string]string{"gateway.agentio.kruise.io/agentgateway-certs": "agentgateway-e2e-certs"})
	return u
}

func NativeConfig(version string, extProc map[string]any) string {
	target := `"host" in source.connectHeaders ? source.connectHeaders["host"] : string(destination.address) + ":" + string(destination.port)`
	policies := map[string]any{"requestHeaderModifier": map[string]any{"set": map[string]any{Marker: "agentgateway"}}, "responseHeaderModifier": map[string]any{"set": map[string]any{Marker: "agentgateway"}}}
	if extProc != nil {
		policies["extProc"] = extProc
	}
	data := map[string]any{"config": map[string]any{"adminAddr": "127.0.0.1:15000"}, "binds": []any{
		map[string]any{"port": 8080, "listeners": []any{map[string]any{"protocol": "HTTP", "routes": []any{map[string]any{"policies": map[string]any{"directResponse": map[string]any{"status": 200, "body": version}}}}}}},
		map[string]any{"port": 15008, "tunnelProtocol": "connect", "listeners": []any{map[string]any{"protocol": "HTTPS", "tls": map[string]any{"cert": "/etc/agentgateway/certs/tls.crt", "key": "/etc/agentgateway/certs/tls.key", "root": "/etc/agentgateway/certs/ca.crt"}, "routes": []any{}}}},
		map[string]any{"mode": "internal", "protocol": "AUTO", "listeners": []any{
			map[string]any{"protocol": "HTTP", "routes": []any{map[string]any{"policies": policies, "backends": []any{map[string]any{"dynamic": map[string]any{"target": target}}}}}},
			map[string]any{"protocol": "TLS", "hostname": "*", "tcpRoutes": []any{map[string]any{"backends": []any{map[string]any{"dynamic": map[string]any{"target": target}}}}}},
			map[string]any{"protocol": "TCP", "tcpRoutes": []any{map[string]any{"backends": []any{map[string]any{"dynamic": map[string]any{"target": target}}}}}},
		}},
	}}
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func Configuration(namespace, name, content string) *unstructured.Unstructured {
	return object(namespace, "ConfigMap", name+"-config", map[string]any{"data": map[string]any{"config.yaml": content}})
}

// Setup provisions the shared native gateway fixture. Leaf issuance is test-only.
func Setup(namespace, content string) e2e.SetupFunc {
	return func(ctx context.Context, env *e2e.Environment) (e2e.CleanupFunc, error) {
		scope := kube.NewResourceScope(env.Kube)
		secret, err := certificate(ctx, env, namespace)
		if err != nil {
			return nil, err
		}
		for _, u := range []*unstructured.Unstructured{secret, Configuration(namespace, gatewayName, content), Gateway(namespace, gatewayName)} {
			if _, err := scope.Apply(ctx, u, kube.CreateOnly); err != nil {
				return nil, err
			}
		}
		if err := WaitReady(ctx, env, namespace, gatewayName, content); err != nil {
			return nil, err
		}
		return func(ctx context.Context) error {
			if env.Retaining() {
				return nil
			}
			return scope.DeleteReverse(ctx)
		}, nil
	}
}

func ExtProc(host string, attrs map[string]string) map[string]any {
	p := map[string]any{"host": host, "failureMode": "failClosed", "processingOptions": map[string]any{"requestBodyMode": "none", "responseBodyMode": "none", "responseHeaderMode": "send", "requestTrailerMode": "skip", "responseTrailerMode": "skip", "allowModeOverride": true}}
	if attrs != nil {
		p["requestAttributes"] = attrs
	}
	return p
}
func WaitGateway(ctx context.Context, env *e2e.Environment, namespace, name, accepted, programmed string) error {
	return retry.UntilSuccess(ctx, retry.Policy{Timeout: 2 * time.Minute, Delay: time.Second, Converge: 1}, func() error {
		gw, err := env.Kube.Get(ctx, gateways, namespace, name)
		if err != nil {
			return err
		}
		conditions, _, _ := unstructured.NestedSlice(gw.Object, "status", "conditions")
		found := 0
		for _, c := range conditions {
			v := c.(map[string]any)
			want := ""
			switch v["type"] {
			case "Accepted":
				want = accepted
			case "Programmed":
				want = programmed
			}
			if want != "" && v["status"] == want && v["observedGeneration"] == gw.GetGeneration() {
				found++
			}
		}
		if found != 2 {
			return fmt.Errorf("Gateway %s conditions not converged: %v", name, conditions)
		}
		return nil
	})
}

// Test-only leaf issuance from the CA of this suite's freshly installed mesh.
// This verifies real ztunnel mTLS without introducing a production certificate
// controller or pretending to implement per-Sandbox gateway identity policies.
func certificate(ctx context.Context, env *e2e.Environment, namespace string) (*unstructured.Unstructured, error) {
	secret, err := env.Cluster.Kube.CoreV1().Secrets(namespace).Get(ctx, "istio-ca-secret", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(secret.Data["ca-cert.pem"])
	if block == nil {
		return nil, fmt.Errorf("CA certificate missing")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(secret.Data["ca-key.pem"])
	if block == nil {
		return nil, fmt.Errorf("CA key missing")
	}
	var key any
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported CA key")
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	uri, _ := url.Parse("spiffe://cluster.local/ns/" + namespace + "/sa/" + gatewayName)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "agentgateway-e2e"}, DNSNames: []string{gatewayName + "." + namespace + ".svc.cluster.local"}, URIs: []*url.URL{uri}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	encode := base64.StdEncoding.EncodeToString
	return object(namespace, "Secret", "agentgateway-e2e-certs", map[string]any{"data": map[string]any{"tls.crt": encode(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), secret.Data["ca-cert.pem"]...)), "tls.key": encode(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), "ca.crt": encode(secret.Data["ca-cert.pem"])}}), nil
}

func WaitReady(ctx context.Context, env *e2e.Environment, namespace, name, content string) error {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	if err := retry.UntilSuccess(ctx, retry.Policy{Timeout: 2 * time.Minute, Delay: time.Second, Converge: 1}, func() error {
		d, err := env.Cluster.Kube.AppsV1().Deployments(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if d.Spec.Template.Annotations["gateway.agentio.kruise.io/config-hash"] != hash || d.Status.ObservedGeneration < d.Generation || d.Status.UpdatedReplicas != *d.Spec.Replicas || d.Status.AvailableReplicas != *d.Spec.Replicas || d.Status.Replicas != *d.Spec.Replicas {
			return fmt.Errorf("%s rollout has not converged to %s: %+v", name, hash, d.Status)
		}
		return nil
	}); err != nil {
		return err
	}
	return WaitGateway(ctx, env, namespace, name, "True", "True")
}
