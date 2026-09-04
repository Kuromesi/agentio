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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	agentiocomponent "github.com/openkruise/agentio/test/e2e/components/agentio"
)

func TestSetupOrder(t *testing.T) {
	digest := "registry.example/test@sha256:" + strings.Repeat("b", 64)
	setups := suiteSetupGraph(agentiocomponent.Config{
		Namespace: "agentio-system", AgentiodImage: digest, ZtunnelImage: digest,
		ProxyInitImage: digest, GatewayImage: digest, EPEImage: digest,
		ExtProcImage: digest, ForwardProxyImage: digest,
	})
	names := make([]string, len(setups))
	for index := range setups {
		names[index] = setups[index].name
	}
	want := []string{
		"agentio", "agentio-baseline", "traffic-policy-namespace", "traffic-policy-client",
		"traffic-policy-server", "traffic-policy-another-server", "ext-proc", "fixture-readiness",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("setup order = %v, want %v", names, want)
	}
}

func TestExtProcFixtureManifest(t *testing.T) {
	image := "registry.example/ext-proc@sha256:" + strings.Repeat("a", 64)
	objects := extProcObjects("agentio-system", image)
	if len(objects) != 2 {
		t.Fatalf("ext-proc objects = %d, want Service and Deployment", len(objects))
	}
	service := fixtureObject(t, objects, "Service", "ext-proc")
	if service.GetNamespace() != "agentio-system" {
		t.Fatalf("ext-proc Service namespace = %q", service.GetNamespace())
	}
	if got := service.GetLabels(); !reflect.DeepEqual(got, map[string]string{"app": "ext-proc", "service": "ext-proc"}) {
		t.Fatalf("ext-proc Service labels = %#v", got)
	}
	ports, found, err := unstructured.NestedSlice(service.Object, "spec", "ports")
	if err != nil || !found || len(ports) != 1 {
		t.Fatalf("ext-proc Service ports = %#v, found %t, error %v", ports, found, err)
	}
	port := ports[0].(map[string]any)
	if port["name"] != "grpc" || port["port"] != int64(9002) || port["targetPort"] != int64(9002) {
		t.Fatalf("ext-proc Service port = %#v", port)
	}

	deployment := fixtureObject(t, objects, "Deployment", "ext-proc")
	if deployment.GetNamespace() != "agentio-system" {
		t.Fatalf("ext-proc Deployment namespace = %q", deployment.GetNamespace())
	}
	podLabels, found, err := unstructured.NestedStringMap(deployment.Object, "spec", "template", "metadata", "labels")
	if err != nil || !found || !reflect.DeepEqual(podLabels, map[string]string{"app": "ext-proc"}) {
		t.Fatalf("ext-proc Pod labels = %#v, found %t, error %v", podLabels, found, err)
	}
	containers, found, err := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "containers")
	if err != nil || !found || len(containers) != 1 {
		t.Fatalf("ext-proc containers = %#v, found %t, error %v", containers, found, err)
	}
	container := containers[0].(map[string]any)
	if container["image"] != image {
		t.Fatalf("ext-proc image = %#v, want immutable %q", container["image"], image)
	}
	containerPorts := container["ports"].([]any)
	if len(containerPorts) != 1 || containerPorts[0].(map[string]any)["containerPort"] != int64(9002) {
		t.Fatalf("ext-proc container ports = %#v", containerPorts)
	}
}

func TestConnectProxyCertificateFixture(t *testing.T) {
	keyPEM, chainPEM, caPEM := generateConnectProxyCertificate(t, "connect-proxy.test")
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		t.Fatalf("private key PEM block = %#v", keyBlock)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	leafBlock, rest := pem.Decode([]byte(chainPEM))
	caChainBlock, trailing := pem.Decode(rest)
	if leafBlock == nil || caChainBlock == nil || len(trailing) != 0 {
		t.Fatalf("certificate chain is not exactly leaf + CA")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	caBlock, caTrailing := pem.Decode([]byte(caPEM))
	if caBlock == nil || len(caTrailing) != 0 || !reflect.DeepEqual(caBlock.Bytes, caChainBlock.Bytes) {
		t.Fatal("Agentio CA does not match the chain issuer")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "connect-proxy.test", Roots: roots}); err != nil {
		t.Fatalf("verify generated chain and DNS SAN: %v", err)
	}
	publicKey, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.N.Cmp(privateKey.PublicKey.N) != 0 || publicKey.E != privateKey.PublicKey.E {
		t.Fatal("leaf certificate does not contain the generated private key's public key")
	}
}

func TestMatchingGatewayAccessLogRequiresRequestAndDestination(t *testing.T) {
	logs := strings.Join([]string{
		`ordinary proxy log line`,
		`{"request_id":"grpc-other","authority_for":"server.sandbox.svc.cluster.local:7070","method":"POST"}`,
		`{"request_id":"grpc-probe","authority_for":"other.sandbox.svc.cluster.local:7070","method":"POST"}`,
		`{"authority_for":"server.sandbox.svc.cluster.local:7070","bytes_received":17,"duration":1,"method":"POST","request_id":"grpc-probe","requested_server_name":null}`,
	}, "\n")

	line, found := matchingGatewayAccessLog(
		logs,
		"grpc-probe",
		"server.sandbox.svc.cluster.local:7070",
	)
	if !found || !strings.Contains(line, `"request_id":"grpc-probe"`) {
		t.Fatalf("matchingGatewayAccessLog() = %q, %t", line, found)
	}
	if _, found := matchingGatewayAccessLog(logs, "grpc-missing", "server.sandbox.svc.cluster.local:7070"); found {
		t.Fatal("matched a different request ID")
	}
	if _, found := matchingGatewayAccessLog(logs, "grpc-probe", "server.sandbox.svc.cluster.local:7443"); found {
		t.Fatal("matched a different destination authority")
	}
}

func fixtureObject(t *testing.T, objects []*unstructured.Unstructured, kind, name string) *unstructured.Unstructured {
	t.Helper()
	for _, object := range objects {
		if object.GetKind() == kind && object.GetName() == name {
			return object
		}
	}
	t.Fatalf("%s %s not found", kind, name)
	return nil
}
