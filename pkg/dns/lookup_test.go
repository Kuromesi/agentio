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

package dns

import (
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestQueryServersRetriesTruncatedResponseOverTCP(t *testing.T) {
	for _, truncateTCP := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete_tcp_answer", true: "truncated_tcp_answer"}[truncateTCP], func(t *testing.T) {
			tcp, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			udp, err := net.ListenPacket("udp", tcp.Addr().String())
			if err != nil {
				tcp.Close()
				t.Fatal(err)
			}
			udpReady, tcpReady := make(chan struct{}), make(chan struct{})
			udpServer := &mdns.Server{PacketConn: udp, NotifyStartedFunc: func() { close(udpReady) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
				m := new(mdns.Msg)
				m.SetReply(r)
				m.Truncated = true
				_ = w.WriteMsg(m)
			})}
			tcpServer := &mdns.Server{Listener: tcp, NotifyStartedFunc: func() { close(tcpReady) }, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
				m := new(mdns.Msg)
				m.SetReply(r)
				m.Truncated = truncateTCP
				m.Answer = []mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: r.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 30}, A: net.ParseIP("192.0.2.1")}}
				_ = w.WriteMsg(m)
			})}
			go func() { _ = udpServer.ActivateAndServe() }()
			go func() { _ = tcpServer.ActivateAndServe() }()
			t.Cleanup(func() { _ = udpServer.Shutdown(); _ = tcpServer.Shutdown() })
			for _, ready := range []chan struct{}{udpReady, tcpReady} {
				select {
				case <-ready:
				case <-time.After(time.Second):
					t.Fatal("DNS server did not start")
				}
			}
			addresses, ttl, err := queryServers(t.Context(), []string{tcp.Addr().String()}, time.Second, "example.com", mdns.TypeA)
			if truncateTCP {
				if err == nil {
					t.Fatal("accepted truncated TCP response")
				}
				return
			}
			if err != nil || len(addresses) != 1 || addresses[0].String() != "192.0.2.1" || ttl != 30*time.Second {
				t.Fatalf("answer=%v ttl=%v err=%v", addresses, ttl, err)
			}
		})
	}
}
