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
package httpcallout

import (
	"fmt"
	"unicode/utf8"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
)

// headerContentType is the one request header the callout always sees, because
// it is carried as its own field rather than through header forwarding.
const headerContentType = "content-type"

// buildRequestInvocation renders the request-phase view. It is a free function
// rather than a method so the field mapping is testable without a Filter.
func buildRequestInvocation(cfg Config, id filter.UnitID, st *filter.Stream, body filter.Body) (Invocation, error) {
	text, err := bodyText(cfg, body, "request")
	if err != nil {
		return Invocation{}, err
	}
	request := correlationView(st)
	request.Headers = forwardedRequestHeaders(cfg.RequestHeaders, st.Request.Headers)
	request.Body = &text
	return Invocation{
		Version: ProtocolVersion,
		Phase:   PhaseRequest,
		Source:  sourceContext(st),
		Policy:  policyContext(id),
		Request: &request,
	}, nil
}

// buildResponseInvocation renders the response-phase view: the upstream response
// plus the request correlation fields only. Request headers and the request body
// are deliberately absent, which is what frees EPE from retaining a request body
// across directions.
func buildResponseInvocation(cfg Config, id filter.UnitID, st *filter.Stream, body filter.Body) (Invocation, error) {
	text, err := bodyText(cfg, body, "response")
	if err != nil {
		return Invocation{}, err
	}
	request := correlationView(st)
	headers := make(map[string]string, len(st.Response.Headers))
	for name, value := range st.Response.Headers {
		headers[name] = value
	}
	return Invocation{
		Version: ProtocolVersion,
		Phase:   PhaseResponse,
		Source:  sourceContext(st),
		Policy:  policyContext(id),
		Request: &request,
		Response: &HTTPResponse{
			StatusCode:  st.Response.Status,
			ContentType: st.Response.Headers[headerContentType],
			// Never nil: Invocation.Validate rejects nil response headers, and
			// an upstream that sent none is a real case.
			Headers: headers,
			Body:    text,
		},
	}, nil
}

// correlationView is the request metadata both phases share.
func correlationView(st *filter.Stream) HTTPRequest {
	return HTTPRequest{
		ID:     st.RequestID,
		Method: st.Request.Method,
		Scheme: st.Request.Scheme,
		Host:   st.Request.Host,
		Port:   st.Request.Port,
		Path:   st.Request.Path,
		// RawQuery, not the parsed Query: url.ParseQuery drops pairs it cannot
		// parse and normalizes escaping, so a callout computing a signature over
		// the parsed form would disagree with the wire.
		RawQuery:    st.Request.RawQuery,
		ContentType: st.Request.Headers[headerContentType],
	}
}

// sourceContext copies the peer identity. Peer.Token and anything derived from
// it are deliberately absent: the endpoint sits outside the mesh trust boundary.
func sourceContext(st *filter.Stream) SourceContext {
	return SourceContext{
		Namespace: st.Peer.Pod.Namespace,
		Pod:       st.Peer.Pod.Name,
		IP:        st.Peer.IP,
		Labels:    st.Peer.Labels,
	}
}

func policyContext(id filter.UnitID) PolicyContext {
	return PolicyContext{Scope: id.Scope, Rule: id.Name, Ordinal: id.Ordinal}
}

// forwardedRequestHeaders applies the disclosure mode. It always builds a new
// map: st.Request.Headers is the single shared holder of the request headers for
// the whole request path, so aliasing it would let a callout view mutate what
// every later filter reads.
func forwardedRequestHeaders(cfg RequestHeadersConfig, headers map[string]string) map[string]string {
	switch cfg.Mode {
	case RequestHeadersAllowlist:
		out := make(map[string]string, len(cfg.Allowlist))
		for _, name := range cfg.Allowlist {
			if value, found := headers[name]; found {
				out[name] = value
			}
		}
		return out
	case RequestHeadersAll:
		out := make(map[string]string, len(headers))
		for name, value := range headers {
			// "all" means all of the operator's headers, not the caller's
			// credentials: the endpoint is a third party outside the mesh.
			// Effective already rejects an allowlist naming these, so this is
			// the only mode where the filter has to apply the rule.
			if neverForwardHeader(name) {
				continue
			}
			out[name] = value
		}
		return out
	default:
		// none, including an unset mode that never reached Effective.
		return nil
	}
}

// bodyText converts one direction's buffered body. An oversized body is a
// failure rather than a truncation: handing a scanner a prefix and treating its
// verdict as covering the whole body is a hole, not a degradation.
func bodyText(cfg Config, body filter.Body, direction string) (string, error) {
	if int64(len(body.Bytes)) > cfg.MaxBodyBytes {
		return "", fmt.Errorf("callout %s body is %d bytes, over the %d byte limit", direction, len(body.Bytes), cfg.MaxBodyBytes)
	}
	if !utf8.Valid(body.Bytes) {
		return "", fmt.Errorf("callout %s body is not valid UTF-8", direction)
	}
	return string(body.Bytes), nil
}
