// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egressauthz

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/openkruise/agentio/pkg/dns"
)

func TestHostnameResolutionDoesNotQueryAAAA(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var aQueries, otherQueries atomic.Int32
	started := make(chan struct{})
	done := make(chan error, 1)
	server := &mdns.Server{
		PacketConn:        packet,
		NotifyStartedFunc: func() { close(started) },
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
			response := new(mdns.Msg)
			response.SetReply(request)
			if request.Question[0].Qtype == mdns.TypeA {
				aQueries.Add(1)
				response.Answer = []mdns.RR{&mdns.A{
					Hdr: mdns.RR_Header{
						Name:   request.Question[0].Name,
						Rrtype: mdns.TypeA,
						Class:  mdns.ClassINET,
						Ttl:    60,
					},
					A: net.ParseIP("192.0.2.1"),
				}}
			} else {
				// A resolver whose AAAA queries fail must not break IPv4 traffic.
				otherQueries.Add(1)
				response.Rcode = mdns.RcodeServerFailure
			}
			if err := w.WriteMsg(response); err != nil {
				t.Errorf("write DNS response: %v", err)
			}
		}),
	}
	go func() { done <- server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Errorf("shutdown DNS server: %v", err)
		}
		if err := <-done; err != nil {
			t.Errorf("serve DNS: %v", err)
		}
	})
	client := dns.NewClient(dns.NewTransport([]string{packet.LocalAddr().String()}, time.Second), time.Second)
	target := run(t, NewAggregate(client).Authorize, "api.example", 443).Upstream
	if target.Address.String() != "192.0.2.1:443" {
		t.Fatalf("target=%v", target.Address)
	}
	if aQueries.Load() != 1 || otherQueries.Load() != 0 {
		t.Fatalf("queries: A=%d other=%d, want A only", aQueries.Load(), otherQueries.Load())
	}
}
