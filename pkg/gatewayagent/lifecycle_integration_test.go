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

package gatewayagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

type lifecycleDiscovery struct {
	discovery.UnimplementedAggregatedDiscoveryServiceServer
	resources map[string]*discovery.Resource
}

func (s *lifecycleDiscovery) DeltaAggregatedResources(
	stream discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	for {
		r, err := stream.Recv()
		if err != nil {
			return err
		}
		if r.ErrorDetail != nil {
			return fmt.Errorf("Envoy NACK: %v", r.ErrorDetail)
		}
		if r.ResponseNonce != "" {
			continue
		}
		resource, ok := s.resources[r.TypeUrl]
		if !ok {
			return fmt.Errorf("unexpected subscription %s", r.TypeUrl)
		}
		if err := stream.Send(
			&discovery.DeltaDiscoveryResponse{
				TypeUrl:   r.TypeUrl,
				Nonce:     "1",
				Resources: []*discovery.Resource{resource},
			},
		); err != nil {
			return err
		}
	}
}

// Exercise the deployed CLI and its actual child, including SDS delivery and
// rotation in Envoy, rather than testing Run's components independently.
func TestGatewayAgentLifecycle(t *testing.T) {
	binary := os.Getenv("AGENTIO_TEST_AGENT_BINARY")
	if binary == "" {
		t.Skip("set AGENTIO_TEST_AGENT_BINARY to test the gateway process")
	}
	dir := t.TempDir()
	ca := newTestCA(t)
	ca.lifetime = 10 * time.Second
	caAddress := ca.serve(t)
	release := make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprint(w, "started\n"); err != nil {
			t.Errorf("write response: %v", err)
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if _, err := fmt.Fprint(w, "finished\n"); err != nil {
			t.Errorf("finish response: %v", err)
		}
	}))
	defer backend.CloseClientConnections()
	defer backend.Close()
	defer finish()
	port, admin, status := freePort(t), freePort(t), freePort(t)
	fixture := &lifecycleDiscovery{resources: map[string]*discovery.Resource{}}
	for name, raw := range map[string]string{
		"backend": fmt.Sprintf(`{"@type":"type.googleapis.com/envoy.config.cluster.v3.Cluster","name":"backend","type":"STATIC","connect_timeout":"1s","load_assignment":{"cluster_name":"backend","endpoints":[{"lb_endpoints":[{"endpoint":{"address":{"socket_address":{"address":"127.0.0.1","port_value":%s}}}}]}]}}`, strings.Split(backend.Listener.Addr().String(), ":")[1]),
		"tls":     fmt.Sprintf(`{"@type":"type.googleapis.com/envoy.config.listener.v3.Listener","name":"tls","address":{"socket_address":{"address":"127.0.0.1","port_value":%d}},"filter_chains":[{"transport_socket":{"name":"envoy.transport_sockets.tls","typed_config":{"@type":"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext","common_tls_context":{"tls_certificate_sds_secret_configs":[{"name":"default","sds_config":{"api_config_source":{"api_type":"GRPC","transport_api_version":"V3","grpc_services":[{"envoy_grpc":{"cluster_name":"sds-grpc"}}]},"resource_api_version":"V3"}}]}}},"filters":[{"name":"envoy.filters.network.http_connection_manager","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager","stat_prefix":"lifecycle","route_config":{"name":"test","virtual_hosts":[{"name":"test","domains":["*"],"routes":[{"match":{"prefix":"/"},"route":{"cluster":"backend","timeout":"0s"}}]}]},"http_filters":[{"name":"envoy.filters.http.router","typed_config":{"@type":"type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]}}]}]}`, port),
	} {
		resource := &anypb.Any{}
		if err := protojson.Unmarshal([]byte(raw), resource); err != nil {
			t.Fatal(err)
		}
		fixture.resources[resource.TypeUrl] = &discovery.Resource{Name: name, Version: "1", Resource: resource}
	}
	upstream := grpc.NewServer()
	discovery.RegisterAggregatedDiscoveryServiceServer(upstream, fixture)
	server := httptest.NewUnstartedServer(upstream)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	defer upstream.Stop()
	for name, data := range map[string][]byte{
		"token":   []byte("fixture"),
		"ca.pem":  ca.root,
		"xds.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	options, err := json.Marshal(map[string]any{
		"concurrency":              1,
		"adminPort":                admin,
		"statusPort":               status,
		"envoyStatusPort":          freePort(t),
		"prometheusPort":           freePort(t),
		"workloadSocket":           filepath.Join(dir, "SDS"),
		"rotationJitter":           0,
		"eccCurve":                 "P256",
		"drainDuration":            "1s",
		"terminationDrainDuration": "4s",
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = append(
		os.Environ(),
		"POD_NAME=gateway",
		"POD_NAMESPACE=demo",
		"POD_UID=lifecycle",
		"SERVICE_ACCOUNT=egress",
		"INSTANCE_IP=127.0.0.1",
		"AGENTIO_CONFIG_DIR="+dir,
		"AGENTIO_TOKEN_FILE="+filepath.Join(dir, "token"),
		"AGENTIO_XDS_ROOT_CA="+filepath.Join(dir, "xds.pem"),
		"AGENTIO_ROOT_CA="+filepath.Join(dir, "ca.pem"),
		"CA_ADDR="+caAddress,
		"AGENTIO_XDS_ADDRESS="+server.Listener.Addr().String(),
		"ENVOY_BINARY="+os.Getenv("AGENTIO_TEST_ENVOY_BINARY"),
		"AGENTIO_GATEWAY_CONFIG="+string(options),
	)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var exitErr error
	go func() {
		exitErr = cmd.Wait()
		close(done)
	}()
	defer func() {
		select {
		case <-done:
		default:
			if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				t.Errorf("kill test process group: %v", err)
			}
			<-done
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	client := &http.Client{Timeout: time.Second}
	readyURL := fmt.Sprintf("http://127.0.0.1:%d/healthz/ready", status)
	waitFor := func(description string, check func() bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			select {
			case <-done:
				t.Fatalf("agent exited during %s: %v", description, exitErr)
			default:
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", description)
	}
	ready := func(code int) bool {
		r, err := client.Get(readyURL)
		if err != nil {
			return false
		}
		defer closeResource(r.Body)
		return r.StatusCode == code
	}
	waitFor("readiness", func() bool { return ready(200) })
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.root)
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyConnection: func(s tls.ConnectionState) error {
			// Workload certificates identify a SPIFFE URI, not the listener's IP.
			cert := s.PeerCertificates[0]
			if _, err := cert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
				return err
			}
			if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://cluster.local/ns/demo/sa/egress" {
				return fmt.Errorf("unexpected identity")
			}
			return nil
		},
	}
	tlsAddress := fmt.Sprintf("127.0.0.1:%d", port)
	serial := func() string {
		conn, err := tls.Dial("tcp", tlsAddress, tlsConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer closeResource(conn)
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	first := serial()
	waitFor("Envoy SDS certificate rotation", func() bool { return serial() != first })
	t.Log("Envoy served a renewed CA-issued workload certificate")
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	traffic := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := traffic.Get("https://" + tlsAddress + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(response.Body)
	prefix := make([]byte, len("started\n"))
	if _, err := io.ReadFull(response.Body, prefix); err != nil {
		t.Fatal(err)
	}

	// Linux records children under the OS thread that spawned them.
	childFiles, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	var childIDs []string
	for _, path := range childFiles {
		children, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		childIDs = append(childIDs, strings.Fields(string(children))...)
	}

	if len(childIDs) != 1 {
		t.Fatalf("expected one Envoy child, got %q", childIDs)
	}
	childPID, err := strconv.Atoi(childIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitFor("readiness withdrawal", func() bool { return ready(503) })
	// New local streams must still work while a business response is draining.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	xds, err := grpc.NewClient(
		"unix://"+filepath.Join(dir, "XDS"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(xds)
	ads, err := discovery.NewAggregatedDiscoveryServiceClient(xds).DeltaAggregatedResources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ads.Send(
		&discovery.DeltaDiscoveryRequest{
			Node:    &core.Node{Id: "agentio-egress/demo/lifecycle"},
			TypeUrl: "type.googleapis.com/envoy.config.cluster.v3.Cluster",
		},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := ads.Recv(); err != nil {
		t.Fatalf("ADS stopped before drain completed: %v", err)
	}
	secrets, err := grpc.NewClient(
		"unix://"+filepath.Join(dir, "SDS"),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer closeResource(secrets)
	stream, err := sds.NewSecretDiscoveryServiceClient(secrets).StreamSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(
		&discovery.DiscoveryRequest{
			TypeUrl:       "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
			ResourceNames: []string{"default", "ROOTCA"},
		},
	); err != nil {
		t.Fatal(err)
	}
	result, err := stream.Recv()
	if err != nil {
		t.Fatalf("SDS stopped before drain completed: %v", err)
	}
	if len(result.Resources) != 2 {
		t.Fatalf("expected identity and root secrets, got %d", len(result.Resources))
	}
	finish()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "finished\n" {
		t.Fatalf("in-flight response interrupted: %q, %v", body, err)
	}
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("agent did not exit within drain budget")
	}
	if exitErr != nil {
		t.Fatalf("agent exit: %v", exitErr)
	}
	if err := syscall.Kill(childPID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("Envoy child was not reaped: %v", err)
	}
	t.Log("SIGTERM withdrew readiness, kept ADS/SDS alive during drain, finished traffic and reaped Envoy")
}
