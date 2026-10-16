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

package processor

import (
	"context"
	"errors"
	"strings"
	"time"

	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/extensions/porter/pkg/metrics"
	"github.com/openkruise/agentio/pkg/model"
)

// WorkloadIdentity identifies the source Pod by name and namespace.
type WorkloadIdentity struct {
	Name      string
	Namespace string
}

// Source comes from filter state captured by the gateway on the outer CONNECT.
// It is independent of the inner HTTP request and its user-controlled headers.
type Source struct {
	Workload  WorkloadIdentity
	SandboxID string
	PeerIP    string
	Principal string
}

// Request is the context available to connection-stage handlers.
type Request struct {
	Source     Source
	Authority  string
	ConnectUDP bool
}

// Result is generic connection metadata, relative to the agentio namespace.
// A nonzero DenyStatus rejects CONNECT before a tunnel is established.
type Result struct {
	Metadata   map[string]any
	DenyStatus envoytype.StatusCode
}

// Handler decides an outer CONNECT independently of HTTP processing.
type Handler interface {
	Handle(context.Context, Request) (Result, error)
}

// Server exchanges headers once. It does not subscribe to tunnel bytes or keep
// an ext_proc stream alive for the lifetime of a tunnel.
type Server struct {
	extproc.UnimplementedExternalProcessorServer
	Handler Handler
	Timeout time.Duration
	Metrics *metrics.Metrics
}

// Process handles the CONNECT header exchange and publishes its decision.
func (s *Server) Process(stream extproc.ExternalProcessor_ProcessServer) (err error) {
	var request Request
	var result Result
	var handlerErr error
	if log.DebugEnabled() {
		started := time.Now()
		defer func() {
			log.Debug(
				"CONNECT processing completed",
				"authority",
				request.Authority,
				"connect_udp",
				request.ConnectUDP,
				"workload",
				request.Source.Workload.Namespace+"/"+request.Source.Workload.Name,
				"grpc_code",
				status.Code(err).String(),
				"deadline_exceeded",
				errors.Is(handlerErr, context.DeadlineExceeded),
				"deny_status",
				int32(result.DenyStatus),
				"duration",
				time.Since(started),
			)
		}()
	}
	message, err := stream.Recv()
	if err != nil {
		return err
	}
	started := time.Now()
	headers := message.GetRequestHeaders()
	if headers == nil {
		return status.Error(codes.InvalidArgument, "CONNECT requires request headers")
	}
	method, authority, upgrade := "", "", ""
	for _, h := range headers.GetHeaders().GetHeaders() {
		value := h.GetValue()
		if h.RawValue != nil {
			value = string(h.RawValue)
		}
		switch h.GetKey() {
		case ":method":
			method = value
		case ":authority":
			authority = value
		case "upgrade":
			upgrade = value
		}
	}
	// Envoy normalizes extended CONNECT to GET with an Upgrade header before filters.
	connectUDP := method == "GET" && strings.EqualFold(upgrade, "connect-udp")
	if (method != "CONNECT" && !connectUDP) || authority == "" {
		return status.Error(codes.InvalidArgument, "expected CONNECT with an authority")
	}
	protocol := "tcp"
	if connectUDP {
		protocol = "udp"
	}
	if s.Metrics != nil {
		s.Metrics.ConnectStarted(protocol)
		defer func() {
			completionErr := err
			if handlerErr != nil {
				completionErr = handlerErr
			}
			s.Metrics.ConnectCompleted(protocol, result.DenyStatus != 0, time.Since(started), completionErr)
		}()
	}
	attrs := message.GetAttributes()[model.ExtProcAttributesKey]
	attr := func(key string) string {
		value := attrs.GetFields()[key]
		// Envoy filter-state objects may be serialized as a value wrapper.
		if object := value.GetStructValue(); object != nil {
			return object.GetFields()["value"].GetStringValue()
		}
		return value.GetStringValue()
	}
	request = Request{
		Source: Source{
			Workload: WorkloadIdentity{
				Name:      attr(model.AttributeWorkloadName),
				Namespace: attr(model.AttributeWorkloadNamespace),
			},
			SandboxID: attr(model.AttributeSandboxID),
			PeerIP:    attr(model.AttributePeerIP),
			Principal: attr(model.AttributePeerPrincipal),
		},
		Authority:  authority,
		ConnectUDP: connectUDP,
	}
	ctx, cancel := context.WithTimeout(stream.Context(), s.Timeout)
	defer cancel()
	result, handlerErr = s.Handler.Handle(ctx, request)
	if handlerErr != nil {
		return status.Errorf(codes.Unavailable, "CONNECT processing failed: %v", handlerErr)
	}
	response := &extproc.ProcessingResponse{Response: &extproc.ProcessingResponse_RequestHeaders{
		RequestHeaders: &extproc.HeadersResponse{Response: &extproc.CommonResponse{}},
	}}
	if result.DenyStatus != 0 {
		response.Response = &extproc.ProcessingResponse_ImmediateResponse{ImmediateResponse: &extproc.ImmediateResponse{
			Status:  &envoytype.HttpStatus{Code: result.DenyStatus},
			Body:    []byte("connection denied"),
			Details: "agentio_connect_denied",
		}}
	}
	if len(result.Metadata) > 0 {
		metadata, err := structpb.NewStruct(result.Metadata)
		if err != nil {
			return status.Errorf(codes.Internal, "invalid CONNECT metadata: %v", err)
		}
		response.DynamicMetadata = &structpb.Struct{Fields: map[string]*structpb.Value{
			model.GatewayMetadataNamespace: structpb.NewStructValue(metadata),
		}}
	}
	return stream.Send(response)
}
