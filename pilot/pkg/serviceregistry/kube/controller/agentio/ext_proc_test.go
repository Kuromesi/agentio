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
	"testing"
	"time"

	extproc "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
)

func sandboxEgressProxy() *model.Proxy {
	return &model.Proxy{
		Labels: map[string]string{
			LabelSandboxEgress: "true",
		},
	}
}

func nonEgressProxy() *model.Proxy {
	return &model.Proxy{Labels: map[string]string{}}
}

func minimalExtProcConfig() *model.AgentioConfig {
	return &model.AgentioConfig{
		AgentioConfig: &extensions.AgentioConfig{
			SandboxExtProc: &extensions.ExtProcProvider{
				Service: "ext-proc.svc.local",
				Port:    9000,
			},
		},
	}
}

func TestResolveExtProcNilConfig(t *testing.T) {
	if got := resolveExtProc(sandboxEgressProxy(), nil); got != nil {
		t.Fatalf("expected nil ext_proc provider without Agentio config, got %v", got)
	}
}

func TestParseMessageTimeout(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want *durationpb.Duration
	}{
		{"empty returns nil", "", nil},
		{"invalid returns nil", "not-a-duration", nil},
		{"valid 5s", "5s", durationpb.New(5 * time.Second)},
		{"valid 100ms", "100ms", durationpb.New(100 * time.Millisecond)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseMessageTimeout(tc.in)
			if tc.want == nil && got != nil {
				t.Fatalf("expected nil, got %v", got)
			}
			if tc.want != nil && (got == nil || got.AsDuration() != tc.want.AsDuration()) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestToEnvoyHeaderSendMode(t *testing.T) {
	cases := []struct {
		name string
		in   extensions.HeaderSendMode
		def  extproc.ProcessingMode_HeaderSendMode
		want extproc.ProcessingMode_HeaderSendMode
	}{
		{"SEND maps to SEND", extensions.HeaderSendMode_SEND, extproc.ProcessingMode_SKIP, extproc.ProcessingMode_SEND},
		{"SKIP maps to SKIP", extensions.HeaderSendMode_SKIP, extproc.ProcessingMode_SEND, extproc.ProcessingMode_SKIP},
		{"DEFAULT falls back to defaultMode", extensions.HeaderSendMode_DEFAULT, extproc.ProcessingMode_SEND, extproc.ProcessingMode_SEND},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toEnvoyHeaderSendMode(tc.in, tc.def)
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestBuildExtProcClusters_Skip(t *testing.T) {
	cases := []struct {
		name   string
		proxy  *model.Proxy
		config *model.AgentioConfig
	}{
		{"non-egress proxy returns nil", nonEgressProxy(), minimalExtProcConfig()},
		{"egress proxy but nil ext_proc config returns nil",
			sandboxEgressProxy(),
			&model.AgentioConfig{AgentioConfig: &extensions.AgentioConfig{}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BuildExtProcClusters(tc.proxy, tc.config); got != nil {
				t.Fatalf("expected nil, got %+v", got)
			}
		})
	}
}

func TestBuildExtProcClusters_Build(t *testing.T) {
	cfg := minimalExtProcConfig()
	clusters := BuildExtProcClusters(sandboxEgressProxy(), cfg)
	if len(clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(clusters))
	}
	c := clusters[0]
	if c.Name != SandboxExtProcName {
		t.Errorf("cluster name: expected %s, got %s", SandboxExtProcName, c.Name)
	}
	endpoints := c.GetLoadAssignment().GetEndpoints()
	if len(endpoints) != 1 || len(endpoints[0].LbEndpoints) != 1 {
		t.Fatalf("expected exactly one LB endpoint")
	}
	addr := endpoints[0].LbEndpoints[0].GetEndpoint().GetAddress().GetSocketAddress()
	if addr.Address != "ext-proc.svc.local" {
		t.Errorf("address: expected ext-proc.svc.local, got %s", addr.Address)
	}
	if addr.GetPortValue() != 9000 {
		t.Errorf("port: expected 9000, got %d", addr.GetPortValue())
	}
	if c.CircuitBreakers == nil || len(c.CircuitBreakers.Thresholds) == 0 {
		t.Error("expected non-empty circuit breaker thresholds")
	}
}

func TestBuildExtProcHttpProtocolOptions(t *testing.T) {
	t.Run("no http settings uses defaults", func(t *testing.T) {
		opts := buildExtProcHttpProtocolOptions(minimalExtProcConfig().GetSandboxExtProc())
		if opts.CommonHttpProtocolOptions.IdleTimeout.AsDuration() != 5*time.Minute {
			t.Errorf("expected 5m idle timeout, got %v", opts.CommonHttpProtocolOptions.IdleTimeout.AsDuration())
		}
		http2 := opts.GetExplicitHttpConfig().GetHttp2ProtocolOptions()
		if http2 == nil || !http2.AllowConnect {
			t.Error("expected http2 options with AllowConnect")
		}
		if http2.MaxConcurrentStreams != nil {
			t.Errorf("expected nil MaxConcurrentStreams when unset, got %v", http2.MaxConcurrentStreams)
		}
		if opts.CommonHttpProtocolOptions.MaxRequestsPerConnection != nil {
			t.Errorf("expected nil MaxRequestsPerConnection when unset, got %v", opts.CommonHttpProtocolOptions.MaxRequestsPerConnection)
		}
	})

	t.Run("http settings populate values", func(t *testing.T) {
		cfg := &model.AgentioConfig{
			AgentioConfig: &extensions.AgentioConfig{
				SandboxExtProc: &extensions.ExtProcProvider{
					Service: "svc", Port: 1,
					ClusterSettings: &extensions.ClusterSettings{
						Http: &extensions.HttpSettings{
							MaxConcurrentStreams:     200,
							MaxRequestsPerConnection: 50,
						},
					},
				},
			},
		}
		opts := buildExtProcHttpProtocolOptions(cfg.GetSandboxExtProc())
		http2 := opts.GetExplicitHttpConfig().GetHttp2ProtocolOptions()
		if http2.MaxConcurrentStreams.Value != 200 {
			t.Errorf("MaxConcurrentStreams: expected 200, got %d", http2.MaxConcurrentStreams.Value)
		}
		if opts.CommonHttpProtocolOptions.MaxRequestsPerConnection.Value != 50 {
			t.Errorf("MaxRequestsPerConnection: expected 50, got %d", opts.CommonHttpProtocolOptions.MaxRequestsPerConnection.Value)
		}
	})
}

func TestBuildExtProcFilter_Skip(t *testing.T) {
	cases := []struct {
		name   string
		proxy  *model.Proxy
		config *model.AgentioConfig
	}{
		{"non-egress proxy returns nil", nonEgressProxy(), minimalExtProcConfig()},
		{"nil ext_proc returns nil",
			sandboxEgressProxy(),
			&model.AgentioConfig{AgentioConfig: &extensions.AgentioConfig{}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BuildExtProcFilter(tc.proxy, tc.config); got != nil {
				t.Fatalf("expected nil, got %+v", got)
			}
		})
	}
}

func TestBuildExtProcFilter_Defaults(t *testing.T) {
	cfg := minimalExtProcConfig()
	filters := BuildExtProcFilter(sandboxEgressProxy(), cfg)
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
	// Decoded ExternalProcessor proto must default to SEND request headers and
	// SKIP response headers when Request/Response are nil.
	processor := &extproc.ExternalProcessor{}
	if err := filters[0].GetTypedConfig().UnmarshalTo(processor); err != nil {
		t.Fatalf("unmarshal typed config: %v", err)
	}
	if processor.ProcessingMode.RequestHeaderMode != extproc.ProcessingMode_SEND {
		t.Errorf("default request header mode: expected SEND, got %v", processor.ProcessingMode.RequestHeaderMode)
	}
	if processor.ProcessingMode.ResponseHeaderMode != extproc.ProcessingMode_SKIP {
		t.Errorf("default response header mode: expected SKIP, got %v", processor.ProcessingMode.ResponseHeaderMode)
	}
	if processor.GetGrpcService().GetEnvoyGrpc().GetClusterName() != SandboxExtProcName {
		t.Errorf("cluster name: expected %s, got %s", SandboxExtProcName, processor.GetGrpcService().GetEnvoyGrpc().GetClusterName())
	}
}

func TestBuildExtProcFilter_CustomModes(t *testing.T) {
	cfg := &model.AgentioConfig{
		AgentioConfig: &extensions.AgentioConfig{
			SandboxExtProc: &extensions.ExtProcProvider{
				Service: "svc", Port: 1,
				FailureModeAllow: true,
				MessageTimeout:   "200ms",
				Request: &extensions.ProcessingModeOptions{
					HeaderMode: extensions.HeaderSendMode_SKIP,
					Attributes: []string{"req-attr-1"},
				},
				Response: &extensions.ProcessingModeOptions{
					HeaderMode: extensions.HeaderSendMode_SEND,
					Attributes: []string{"resp-attr-1"},
				},
			},
		},
	}
	filters := BuildExtProcFilter(sandboxEgressProxy(), cfg)
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
	processor := &extproc.ExternalProcessor{}
	if err := filters[0].GetTypedConfig().UnmarshalTo(processor); err != nil {
		t.Fatalf("unmarshal typed config: %v", err)
	}
	if !processor.FailureModeAllow {
		t.Error("FailureModeAllow not propagated")
	}
	if processor.ProcessingMode.RequestHeaderMode != extproc.ProcessingMode_SKIP {
		t.Errorf("request header mode: expected SKIP, got %v", processor.ProcessingMode.RequestHeaderMode)
	}
	if processor.ProcessingMode.ResponseHeaderMode != extproc.ProcessingMode_SEND {
		t.Errorf("response header mode: expected SEND, got %v", processor.ProcessingMode.ResponseHeaderMode)
	}
	if len(processor.RequestAttributes) != 1 || processor.RequestAttributes[0] != "req-attr-1" {
		t.Errorf("request attributes: expected [req-attr-1], got %v", processor.RequestAttributes)
	}
	if len(processor.ResponseAttributes) != 1 || processor.ResponseAttributes[0] != "resp-attr-1" {
		t.Errorf("response attributes: expected [resp-attr-1], got %v", processor.ResponseAttributes)
	}
	if processor.MessageTimeout == nil || processor.MessageTimeout.AsDuration() != 200*time.Millisecond {
		t.Errorf("message timeout: expected 200ms, got %v", processor.MessageTimeout)
	}
}
