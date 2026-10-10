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
	// NameError distinguishes NXDOMAIN from a successful empty RRset (NODATA).
	NameError bool
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

// Transport performs DNS protocol queries without caching. It does not consult
// hosts files or search domains.
type Transport struct {
	servers []string
	timeout time.Duration
}

// NewTransport uses resolv.conf nameservers when servers is empty.
func NewTransport(servers []string, timeout time.Duration) *Transport {
	if len(servers) == 0 {
		servers = systemDNSServers()
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Transport{servers: append([]string(nil), servers...), timeout: timeout}
}

// Lookup returns addresses in DNS response order and their minimum TTL.
func (t *Transport) Lookup(ctx context.Context, host string, family Family) (LookupResult, error) {
	var types []uint16
	switch family {
	case IPv4Only:
		types = []uint16{mdns.TypeA}
	case IPv6Only:
		types = []uint16{mdns.TypeAAAA}
	case DualStack:
		types = []uint16{mdns.TypeA, mdns.TypeAAAA}
	default:
		return LookupResult{}, ErrInvalidFamily
	}
	result := LookupResult{}
	ttlSet := false
	for _, queryType := range types {
		answer, err := queryServers(ctx, t.servers, t.timeout, host, queryType)
		if err != nil {
			return LookupResult{}, err
		}
		if answer.NameError {
			return answer, nil
		}
		result.Addresses = append(result.Addresses, answer.Addresses...)
		if !ttlSet || answer.TTL < result.TTL {
			result.TTL = answer.TTL
		}
		ttlSet = true
	}
	return result, nil
}

func queryServers(
	ctx context.Context,
	servers []string,
	timeout time.Duration,
	host string,
	queryType uint16,
) (LookupResult, error) {
	if len(servers) == 0 {
		return LookupResult{}, fmt.Errorf("no DNS servers configured")
	}
	request := new(mdns.Msg)
	request.SetQuestion(mdns.Fqdn(host), queryType)
	client := &mdns.Client{Timeout: timeout}
	var lastErr error
	for _, server := range servers {
		response, _, err := client.ExchangeContext(ctx, request, server)
		if err == nil && response.Truncated {
			tcpClient := &mdns.Client{Net: "tcp", Timeout: timeout}
			response, _, err = tcpClient.ExchangeContext(ctx, request, server)
			if err == nil && response.Truncated {
				err = fmt.Errorf("DNS server %s returned a truncated TCP response for %s", server, host)
			}
		}
		if err != nil {
			lastErr = err
			continue
		}
		if response.Rcode == mdns.RcodeNameError {
			return LookupResult{TTL: negativeTTL(response), NameError: true}, nil
		}
		if response.Rcode != mdns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS server %s returned %s for %s", server, mdns.RcodeToString[response.Rcode], host)
			continue
		}
		addresses := make([]netip.Addr, 0, len(response.Answer))
		var ttl time.Duration
		ttlSet := false
		includeTTL := func(seconds uint32) {
			value := time.Duration(seconds) * time.Second
			if !ttlSet || value < ttl {
				ttl = value
			}
			ttlSet = true
		}
		for _, answer := range response.Answer {
			var address netip.Addr
			switch record := answer.(type) {
			case *mdns.CNAME:
				includeTTL(record.Hdr.Ttl)
				continue
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
			includeTTL(answer.Header().Ttl)
			addresses = append(addresses, address.Unmap())
		}
		if len(addresses) == 0 {
			ttl = negativeTTL(response)
		}
		return LookupResult{Addresses: addresses, TTL: ttl}, nil
	}
	return LookupResult{}, fmt.Errorf("resolve %s type %s: %w", host, mdns.TypeToString[queryType], lastErr)
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
