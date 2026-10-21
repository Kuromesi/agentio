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

package extproc

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/pkg/dns"
)

func TestAuthorizationDenialHasCorrelatedJSONResponse(t *testing.T) {
	audit := &capturedAuditLogger{}
	client := dns.NewClient(nil, time.Second)
	cfg := egressauthz.Config{
		Policies: []egressauthz.Policy{
			{
				Name: "sandbox/deny-test",
				Rules: []egressauthz.Rule{
					{Action: egressauthz.Deny, CIDRs: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")}},
				},
			},
		},
	}
	server := NewServer(
		ServerDeps{
			AuditLogger: audit,
			Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
				return engine.Resolution{}, nil
			},
			AuthorizeRequest: func(ctx context.Context, stream *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
				return egressauthz.Authorize(ctx, cfg, client, stream)
			},
		},
	)
	headers := makeRequestHeaders("1.1.1.1:80", "/", "GET")
	headers.Headers.Headers = append(
		headers.Headers.Headers,
		&corev3.HeaderValue{Key: "x-request-id", RawValue: []byte("request-123")},
	)
	stream := &collectingStream{
		ctx: t.Context(),
		msgs: []*extProcPb.ProcessingRequest{
			{
				Request:    &extProcPb.ProcessingRequest_RequestHeaders{RequestHeaders: headers},
				Attributes: makeAttrsWithLabels("sandbox", "client-v1", ""),
			},
		},
	}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries: %v", audit.entries)
	}
	reply := stream.sent[0].GetImmediateResponse()
	entry := audit.entries[0]
	if entry.Outcome != "blocked" || entry.Units != 0 || len(entry.Actions) != 0 {
		t.Fatalf("audit: %+v", entry)
	}
	decision := entry.Authorization
	if decision == nil || decision.Action != "deny" || decision.Reason != filter.AuthorizationReasonPolicyDenied ||
		decision.Destination != "1.1.1.1:80" ||
		decision.Policy != "sandbox/deny-test" ||
		decision.RuleIndex == nil ||
		*decision.RuleIndex != 0 {
		t.Fatalf("decision: %+v", decision)
	}
	headersOut := reply.GetHeaders().GetSetHeaders()
	if len(headersOut) != 1 || headersOut[0].GetHeader().GetKey() != "content-type" ||
		string(headersOut[0].GetHeader().GetRawValue()) != "application/json" {
		t.Fatalf("headers: %v", headersOut)
	}
	var body map[string]string
	if err := json.Unmarshal(reply.GetBody(), &body); err != nil {
		t.Fatalf("expected JSON denial body, got %q: %v", reply.GetBody(), err)
	}
	if reply.GetStatus().GetCode() != 403 || body["code"] != "epe_egress_denied" ||
		body["message"] != "Outbound destination is denied by policy." ||
		body["requestID"] != audit.entries[0].RequestID ||
		body["requestID"] != "request-123" {
		t.Fatalf("reply=%v body=%v", reply, body)
	}
}

func TestAuthorizationFailureResponseDoesNotExposeInternalError(t *testing.T) {
	audit := &capturedAuditLogger{}
	server := NewServer(ServerDeps{AuditLogger: audit,
		Resolve: func(context.Context, inputs.Pod, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{}, nil
		},
		AuthorizeRequest: func(context.Context, *filter.Stream) (*filter.UpstreamTarget, *filter.Reply, error) {
			return nil, nil, errors.New("private control-plane failure")
		},
	})
	stream := &collectingStream{
		ctx: t.Context(),
		msgs: []*extProcPb.ProcessingRequest{
			{
				Request: &extProcPb.ProcessingRequest_RequestHeaders{
					RequestHeaders: makeRequestHeaders("example.com:80", "/", "GET"),
				},
				Attributes: makeAttrsWithLabels("sandbox", "client-v1", ""),
			},
		},
	}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	reply := stream.sent[0].GetImmediateResponse()
	var body map[string]string
	if err := json.Unmarshal(reply.GetBody(), &body); err != nil {
		t.Fatal(err)
	}
	if reply.GetStatus().GetCode() != 500 || body["code"] != "epe_request_authorization_failed" ||
		strings.Contains(string(reply.GetBody()), "private") {
		t.Fatalf("reply: %v", reply)
	}
	entry := audit.entries[0]
	if entry.Authorization.Action != "error" ||
		entry.Authorization.Reason != filter.AuthorizationReasonFailed ||
		!strings.Contains(entry.Error, "private control-plane failure") {
		t.Fatalf("audit: %+v", entry)
	}
}
