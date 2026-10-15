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
package extproc

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

func TestProcessLogsBodyMetadataAndCorrelatesResponsePhases(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	logger := zapr.NewLogger(zap.New(core))
	response := &responseBodyProbe{}
	server, _ := wantsServer(t, []filter.Registration{
		pauseReg("request-body", &pauseFilter{}),
		responseBodyReg("response-body", response, filter.FailClosed),
	}, []string{"rule"})
	headers := makeRequestHeaders("api.example.com", "/token", "POST")
	headers.Headers.Headers = append(
		headers.Headers.Headers,
		&corev3.HeaderValue{Key: "x-request-id", RawValue: []byte("request-123")},
	)
	body := []byte("client_secret=private-credential&code_verifier=private-verifier")
	stream := &collectingStream{
		ctx: log.IntoContext(t.Context(), logger),
		msgs: []*extProcPb.ProcessingRequest{
			{
				Request:    &extProcPb.ProcessingRequest_RequestHeaders{RequestHeaders: headers},
				Attributes: makeAttrsWithLabels("default", "pod", testLabelsB64),
			},
			{
				Request: &extProcPb.ProcessingRequest_RequestBody{
					RequestBody: &extProcPb.HttpBody{Body: body, EndOfStream: true},
				},
			},
			{Request: &extProcPb.ProcessingRequest_ResponseHeaders{ResponseHeaders: responseHeaderMsg("200")}},
			{
				Request: &extProcPb.ProcessingRequest_ResponseBody{
					ResponseBody: &extProcPb.HttpBody{Body: []byte("response-credential"), EndOfStream: true},
				},
			},
		},
	}
	if err := server.Process(stream); err != nil {
		t.Fatal(err)
	}
	for _, entry := range logs.All() {
		fields := entry.ContextMap()
		if entry.Message != "processing request started" && fields["requestID"] != "request-123" {
			t.Errorf("log %q missing request ID: %v", entry.Message, fields)
		}
		rendered := fmt.Sprint(fields)
		for _, secret := range []string{"private-credential", "private-verifier", "response-credential"} {
			if strings.Contains(rendered, secret) {
				t.Errorf("log %q leaked body content", entry.Message)
			}
		}
	}
	chunks := logs.FilterMessage("incoming body chunk").All()
	if len(chunks) != 1 || chunks[0].ContextMap()["bodyLen"] != int64(len(body)) ||
		chunks[0].ContextMap()["EoS"] != true {
		t.Fatalf("body metadata logs = %v", chunks)
	}
	if response.bodyCalls != 1 || logs.FilterMessage("running deferred response-body filters").Len() != 1 {
		t.Fatal("response body phase was not exercised")
	}
}

func TestProcessErrorLogsKeepRequestID(t *testing.T) {
	for _, tc := range []struct {
		name         string
		message      string
		sendErr      error
		recvErr      error
		handlerError bool
	}{
		{name: "send", message: "send failed", sendErr: errors.New("send broken")},
		{name: "receive", message: "cannot receive stream request", recvErr: errors.New("receive broken")},
		{name: "handler", message: "failed to process request", handlerError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			headers := makeRequestHeaders("api.example.com", "/", "GET")
			headers.Headers.Headers = append(
				headers.Headers.Headers,
				&corev3.HeaderValue{Key: "x-request-id", RawValue: []byte("failed-request")},
			)
			stream := &collectingStream{
				ctx: log.IntoContext(t.Context(), zapr.NewLogger(zap.New(core))),
				msgs: []*extProcPb.ProcessingRequest{
					{Request: &extProcPb.ProcessingRequest_RequestHeaders{RequestHeaders: headers}},
				},
				sendErr: tc.sendErr,
				recvErr: tc.recvErr,
			}
			if tc.handlerError {
				stream.msgs = append(
					stream.msgs,
					&extProcPb.ProcessingRequest{
						Request: &extProcPb.ProcessingRequest_ResponseBody{ResponseBody: &extProcPb.HttpBody{}},
					},
				)
			}
			if err := NewServer(ServerDeps{}).Process(stream); err == nil {
				t.Fatal("expected stream failure")
			}
			entries := logs.FilterMessage(tc.message).All()
			if len(entries) != 1 || entries[0].ContextMap()["requestID"] != "failed-request" {
				t.Fatalf("error log lost request ID: %v", entries)
			}
		})
	}
}
