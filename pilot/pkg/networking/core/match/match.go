// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package match

import (
	xds "github.com/cncf/xds/go/xds/core/v3"
	matcher "github.com/cncf/xds/go/xds/type/matcher/v3"
	network "github.com/envoyproxy/go-control-plane/envoy/extensions/matching/common_inputs/network/v3"
	wrappers "google.golang.org/protobuf/types/known/wrapperspb"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"istio.io/istio/pilot/pkg/xds/filters"
	"istio.io/istio/pkg/log"
)

var (
	DestinationPort = &xds.TypedExtensionConfig{
		Name:        "port",
		TypedConfig: protoconv.MessageToAny(&network.DestinationPortInput{}),
	}
	DestinationIP = &xds.TypedExtensionConfig{
		Name:        "ip",
		TypedConfig: protoconv.MessageToAny(&network.DestinationIPInput{}),
	}
	SourceIP = &xds.TypedExtensionConfig{
		Name:        "source-ip",
		TypedConfig: protoconv.MessageToAny(&network.SourceIPInput{}),
	}
	SNI = &xds.TypedExtensionConfig{
		Name:        "sni",
		TypedConfig: protoconv.MessageToAny(&network.ServerNameInput{}),
	}
	ApplicationProtocolInput = &xds.TypedExtensionConfig{
		Name:        "application-protocol",
		TypedConfig: protoconv.MessageToAny(&network.ApplicationProtocolInput{}),
	}
	TransportProtocolInput = &xds.TypedExtensionConfig{
		Name:        "transport-protocol",
		TypedConfig: protoconv.MessageToAny(&network.TransportProtocolInput{}),
	}
	AuthorityFilterStateInput = &xds.TypedExtensionConfig{
		Name: "authority-filter-state",
		TypedConfig: protoconv.MessageToAny(&network.FilterStateInput{
			Key: filters.AuthorityFilterStateKey,
		}),
	}
	RequestSourceFilterStateInput = &xds.TypedExtensionConfig{
		Name: "request-source-filter-state",
		TypedConfig: protoconv.MessageToAny(&network.FilterStateInput{
			Key: filters.RequestSourceFilterStateKey,
		}),
	}
)

type Mapper struct {
	*matcher.Matcher
	Map map[string]*matcher.Matcher_OnMatch
}

func newMapper(input *xds.TypedExtensionConfig) Mapper {
	m := map[string]*matcher.Matcher_OnMatch{}
	match := &matcher.Matcher{
		MatcherType: &matcher.Matcher_MatcherTree_{
			MatcherTree: &matcher.Matcher_MatcherTree{
				Input: input,
				TreeType: &matcher.Matcher_MatcherTree_ExactMatchMap{
					ExactMatchMap: &matcher.Matcher_MatcherTree_MatchMap{
						Map: m,
					},
				},
			},
		},
		OnNoMatch: nil,
	}
	return Mapper{Matcher: match, Map: m}
}

func NewDestinationIP() Mapper {
	return newMapper(DestinationIP)
}

func NewSourceIP() Mapper {
	return newMapper(SourceIP)
}

func NewDestinationPort() Mapper {
	return newMapper(DestinationPort)
}

func NewRequestSource() Mapper {
	return newMapper(RequestSourceFilterStateInput)
}

type ProtocolMatch struct {
	TCP, HTTP *matcher.Matcher_OnMatch
}

func NewAppProtocol(pm ProtocolMatch) *matcher.Matcher {
	m := newMapper(ApplicationProtocolInput)
	m.Map["'h2c'"] = pm.HTTP
	m.Map["'http/1.1'"] = pm.HTTP
	if features.HTTP10 {
		m.Map["'http/1.0'"] = pm.HTTP
	}
	m.OnNoMatch = pm.TCP
	return m.Matcher
}

type TransportProtocolMatch struct {
	TLS   *matcher.Matcher_OnMatch
	Other *matcher.Matcher
}

func NewTransportProtocol(pm TransportProtocolMatch) *matcher.Matcher {
	m := newMapper(TransportProtocolInput)
	m.Map["tls"] = pm.TLS
	m.OnNoMatch = ToMatcher(pm.Other)
	return m.Matcher
}

type SNIDomainMatch struct {
	Domains []string
	OnMatch *matcher.Matcher_OnMatch
}

func NewSNIMatcher(domainMatches []SNIDomainMatch, onNoMatch *matcher.Matcher_OnMatch) *matcher.Matcher {
	var domainMatchers []*matcher.ServerNameMatcher_DomainMatcher
	for _, dm := range domainMatches {
		if len(dm.Domains) > 0 {
			domainMatchers = append(domainMatchers, &matcher.ServerNameMatcher_DomainMatcher{
				Domains: dm.Domains,
				OnMatch: dm.OnMatch,
			})
		}
	}
	return &matcher.Matcher{
		MatcherType: &matcher.Matcher_MatcherTree_{
			MatcherTree: &matcher.Matcher_MatcherTree{
				Input: SNI,
				TreeType: &matcher.Matcher_MatcherTree_CustomMatch{
					CustomMatch: &xds.TypedExtensionConfig{
						Name:        "sni",
						TypedConfig: protoconv.MessageToAny(&matcher.ServerNameMatcher{DomainMatchers: domainMatchers}),
					},
				},
			},
		},
		OnNoMatch: onNoMatch,
	}
}

const (
	// SniTrafficPolicyCapability is the stable proxy capability advertised in node metadata.
	SniTrafficPolicyCapability = "sni_traffic_policy"

	// SniTrafficPolicyMatcherName is the registered Envoy custom matcher factory.
	SniTrafficPolicyMatcherName = "kruise.matching.custom_matchers.sni_traffic_policy"

	// SniTrafficPolicyMatcherTypeURL is the Agentio-owned custom matcher that resolves the
	// SNI traffic policy bound to the downstream peer workload. See
	// source/extensions/matching/network/sni_policy in the proxy repository.
	SniTrafficPolicyMatcherTypeURL = "type.googleapis.com/kruise.networking.policy_runtime.v1alpha1.SniTrafficPolicyMatcher"

	// SniTrafficPolicyFailureModeAllowRuntimeKey is the emergency runtime override for
	// policy-resolution failures. Its configured default remains fail-closed.
	SniTrafficPolicyFailureModeAllowRuntimeKey = "kruise.sni_traffic_policy.failure_mode_allow"
)

// NewSniTrafficPolicyMatcher selects a filter chain by evaluating the SNI traffic
// policy for the connection's peer workload.
//
// Unlike NewSNIMatcher, the domains are not part of this config: the matcher
// reads them from the gateway policy store, which is fed by delta xDS. Listener
// size therefore does not grow with the number of clients or policies, which is
// what makes per-client TLS termination expressible here at all -- encoding the
// table into the listener would re-push all of it on every policy edit.
//
// OnNoMatch routes to the passthrough chain: an empty ClientHello SNI matches
// no rule (every rule form requires a non-empty SNI), and the documented
// contract for no-SNI TLS connections is passthrough, not a closed connection.
func NewSniTrafficPolicyMatcher(terminateChain, passthroughChain, denyChain string) *matcher.Matcher {
	return &matcher.Matcher{
		OnNoMatch: ToChain(passthroughChain),
		MatcherType: &matcher.Matcher_MatcherTree_{
			MatcherTree: &matcher.Matcher_MatcherTree{
				// Unused by this matcher, which reads the connection directly, but
				// MatcherTree requires an input.
				Input: SNI,
				TreeType: &matcher.Matcher_MatcherTree_CustomMatch{
					CustomMatch: &xds.TypedExtensionConfig{
						Name: SniTrafficPolicyMatcherName,
						TypedConfig: protoconv.TypedStructWithFields(SniTrafficPolicyMatcherTypeURL,
							map[string]any{
								"on_tls_termination": chainActionFields(terminateChain),
								"on_passthrough":     chainActionFields(passthroughChain),
								"on_deny":            chainActionFields(denyChain),
								"failure_mode_allow": map[string]any{
									"runtime_key":   SniTrafficPolicyFailureModeAllowRuntimeKey,
									"default_value": features.SniTrafficPolicyFailureModeAllow,
								},
							}),
					},
				},
			},
		},
	}
}

// chainActionFields mirrors ToChain as untyped fields, since the matcher's
// config message is not compiled into this binary.
func chainActionFields(name string) map[string]any {
	return map[string]any{
		"action": map[string]any{
			"name": name,
			"typed_config": map[string]any{
				"@type": "type.googleapis.com/google.protobuf.StringValue",
				"value": name,
			},
		},
	}
}

func ToChain(name string) *matcher.Matcher_OnMatch {
	return &matcher.Matcher_OnMatch{
		OnMatch: &matcher.Matcher_OnMatch_Action{
			Action: &xds.TypedExtensionConfig{
				Name:        name,
				TypedConfig: protoconv.MessageToAny(&wrappers.StringValue{Value: name}),
			},
		},
	}
}

func ToMatcher(match *matcher.Matcher) *matcher.Matcher_OnMatch {
	return &matcher.Matcher_OnMatch{
		OnMatch: &matcher.Matcher_OnMatch_Matcher{
			Matcher: match,
		},
	}
}

// BuildMatcher cleans the entire match tree to avoid empty maps and returns a viable top-level matcher.
// Note: this mutates the internal mappers/matchers that make up the tree.
func (m Mapper) BuildMatcher() *matcher.Matcher {
	root := m
	for len(root.Map) == 0 {
		// the top level matcher is empty; if its fallback goes to a matcher, return that
		// TODO is there a way we can just say "always go to action"?
		if fallback := root.GetOnNoMatch(); fallback != nil {
			if replacement, ok := mapperFromMatch(fallback.GetMatcher()); ok {
				root = replacement
				continue
			}
		}
		// no fallback or fallback isn't a mapper
		log.Warnf("could not repair invalid matcher; empty map at root matcher does not have a map fallback")
		return nil
	}
	q := []*matcher.Matcher_OnMatch{m.OnNoMatch}
	for _, onMatch := range root.Map {
		q = append(q, onMatch)
	}

	// fix the matchers, add child mappers OnMatch to the queue
	for len(q) > 0 {
		head := q[0]
		q = q[1:]
		q = append(q, fixEmptyOnMatchMap(head)...)
	}
	return root.Matcher
}

// if the onMatch sends to an empty mapper, make the onMatch send directly to the onNoMatch of that empty mapper
// returns mapper if it doesn't need to be fixed, or can't be fixed
func fixEmptyOnMatchMap(onMatch *matcher.Matcher_OnMatch) []*matcher.Matcher_OnMatch {
	if onMatch == nil {
		return nil
	}
	innerMatcher := onMatch.GetMatcher()
	if innerMatcher == nil {
		// this already just performs an Action
		return nil
	}
	innerMapper, ok := mapperFromMatch(innerMatcher)
	if !ok {
		// this isn't a mapper or action, not supported by this func
		return nil
	}
	if len(innerMapper.Map) > 0 {
		return innerMapper.allOnMatches()
	}

	if fallback := innerMapper.GetOnNoMatch(); fallback != nil {
		// change from: onMatch -> map (empty with fallback) to onMatch -> fallback
		// that fallback may be an empty map, so we re-queue onMatch in case it still needs fixing
		onMatch.OnMatch = fallback.OnMatch
		return []*matcher.Matcher_OnMatch{onMatch} // the inner mapper is gone
	}

	// envoy will nack this eventually
	log.Warnf("empty mapper %v with no fallback", innerMapper.Matcher)
	return innerMapper.allOnMatches()
}

func (m Mapper) allOnMatches() []*matcher.Matcher_OnMatch {
	var out []*matcher.Matcher_OnMatch
	out = append(out, m.OnNoMatch)
	if m.Map == nil {
		return out
	}
	for _, match := range m.Map {
		out = append(out, match)
	}
	return out
}

func mapperFromMatch(mmatcher *matcher.Matcher) (Mapper, bool) {
	if mmatcher == nil {
		return Mapper{}, false
	}
	switch m := mmatcher.MatcherType.(type) {
	case *matcher.Matcher_MatcherTree_:
		var mmap *matcher.Matcher_MatcherTree_MatchMap
		switch t := m.MatcherTree.TreeType.(type) {
		case *matcher.Matcher_MatcherTree_PrefixMatchMap:
			mmap = t.PrefixMatchMap
		case *matcher.Matcher_MatcherTree_ExactMatchMap:
			mmap = t.ExactMatchMap
		default:
			return Mapper{}, false
		}
		return Mapper{Matcher: mmatcher, Map: mmap.Map}, true
	}
	return Mapper{}, false
}
