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
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	mdns "github.com/miekg/dns"
)

type LookupResult struct {
	Addresses []netip.Addr
	TTL       time.Duration
}

func systemDNSServers() []string {
	configuration, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(configuration.Servers) == 0 {
		return []string{"127.0.0.1:53"}
	}
	port := configuration.Port
	if port == "" {
		port = "53"
	}
	servers := make([]string, 0, len(configuration.Servers))
	for _, server := range configuration.Servers {
		servers = append(servers, net.JoinHostPort(server, port))
	}
	return servers
}

func newProtocolLookup(servers []string, timeout time.Duration) Lookup {
	return func(ctx context.Context, host string) (LookupResult, error) {
		result := LookupResult{}
		for _, queryType := range []uint16{mdns.TypeA, mdns.TypeAAAA} {
			addresses, ttl, err := queryServers(ctx, servers, timeout, host, queryType)
			if err != nil {
				return LookupResult{}, err
			}
			result.Addresses = append(result.Addresses, addresses...)
			if ttl > 0 && (result.TTL == 0 || ttl < result.TTL) {
				result.TTL = ttl
			}
		}
		return result, nil
	}
}

func queryServers(
	ctx context.Context,
	servers []string,
	timeout time.Duration,
	host string,
	queryType uint16,
) ([]netip.Addr, time.Duration, error) {
	if len(servers) == 0 {
		return nil, 0, fmt.Errorf("no DNS servers configured")
	}
	request := new(mdns.Msg)
	request.SetQuestion(mdns.Fqdn(host), queryType)
	client := &mdns.Client{Timeout: timeout}
	var lastErr error
	for _, server := range servers {
		response, _, err := client.ExchangeContext(ctx, request, server)
		if err != nil {
			lastErr = err
			continue
		}
		if response.Rcode == mdns.RcodeNameError {
			return nil, negativeTTL(response), nil
		}
		if response.Rcode != mdns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS server %s returned %s for %s", server, mdns.RcodeToString[response.Rcode], host)
			continue
		}
		addresses := make([]netip.Addr, 0, len(response.Answer))
		var ttl time.Duration
		for _, answer := range response.Answer {
			var address netip.Addr
			switch record := answer.(type) {
			case *mdns.A:
				if queryType != mdns.TypeA {
					continue
				}
				address, _ = netip.ParseAddr(record.A.String())
			case *mdns.AAAA:
				if queryType != mdns.TypeAAAA {
					continue
				}
				address, _ = netip.ParseAddr(record.AAAA.String())
			default:
				continue
			}
			if !address.IsValid() {
				continue
			}
			addresses = append(addresses, address.Unmap())
			recordTTL := time.Duration(answer.Header().Ttl) * time.Second
			if ttl == 0 || recordTTL < ttl {
				ttl = recordTTL
			}
		}
		if len(addresses) == 0 {
			ttl = negativeTTL(response)
		}
		return addresses, ttl, nil
	}
	return nil, 0, fmt.Errorf("resolve %s type %s: %w", host, mdns.TypeToString[queryType], lastErr)
}

func negativeTTL(response *mdns.Msg) time.Duration {
	var ttl time.Duration
	for _, record := range response.Ns {
		soa, ok := record.(*mdns.SOA)
		if !ok {
			continue
		}
		seconds := min(soa.Hdr.Ttl, soa.Minttl)
		candidate := time.Duration(seconds) * time.Second
		if ttl == 0 || candidate < ttl {
			ttl = candidate
		}
	}
	return ttl
}
