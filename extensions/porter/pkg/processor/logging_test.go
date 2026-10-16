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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/protobuf/types/known/structpb"

	agentiolog "github.com/openkruise/agentio/pkg/log"
	"github.com/openkruise/agentio/pkg/model"
)

type logTestStream struct {
	extproc.ExternalProcessor_ProcessServer
	message *extproc.ProcessingRequest
}

func (s *logTestStream) Context() context.Context                  { return context.Background() }
func (s *logTestStream) Recv() (*extproc.ProcessingRequest, error) { return s.message, nil }
func (s *logTestStream) Send(*extproc.ProcessingResponse) error    { return nil }

func TestConnectLogging(t *testing.T) {
	previous, level := slog.Default(), agentiolog.OutputLevel()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		agentiolog.ConfigureOutputLevel(level)
	})
	for _, tc := range []struct {
		name       string
		level      string
		denied     bool
		handlerErr error
		code       string
	}{
		{name: "info hides requests", level: "info", code: "OK"},
		{name: "success", level: "debug", code: "OK"},
		{name: "denied", level: "debug", denied: true, code: "OK"},
		{name: "timeout", level: "debug", handlerErr: context.DeadlineExceeded, code: "Unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			logger, err := agentiolog.NewLogger(&output, tc.level, "json")
			if err != nil {
				t.Fatal(err)
			}
			slog.SetDefault(logger)
			server := &Server{
				Timeout: time.Second,
				Handler: handlerFunc(func(context.Context, Request) (Result, error) {
					if tc.denied {
						return Result{DenyStatus: envoytype.StatusCode_Forbidden}, nil
					}
					return Result{}, tc.handlerErr
				}),
			}
			message := connectMessage("")
			message.GetRequestHeaders().Headers.Headers = append(message.GetRequestHeaders().Headers.Headers,
				&core.HeaderValue{Key: "authorization", Value: "secret-token"})
			message.Attributes[model.ExtProcAttributesKey].Fields[model.AttributeSandboxID] = structpb.NewStringValue(
				"secret-sandbox",
			)
			err = server.Process(&logTestStream{message: message})
			if (err != nil) != (tc.handlerErr != nil) {
				t.Fatalf("Process error = %v", err)
			}
			if tc.level == "info" {
				if output.Len() != 0 {
					t.Fatalf("request logged at info: %s", &output)
				}
				return
			}
			var entry map[string]any
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}
			if entry["level"] != "DEBUG" || entry["grpc_code"] != tc.code || entry["component"] != "porter.processor" {
				t.Fatalf("unexpected log: %s", &output)
			}
			if entry["deadline_exceeded"] != (tc.handlerErr != nil) ||
				(entry["deny_status"] == float64(403)) != tc.denied {
				t.Fatalf("incorrect outcome: %s", &output)
			}
			if entry["workload"] != "demo/client" || entry["authority"] != "203.0.113.10:443" ||
				entry["duration"] == nil {
				t.Fatalf("missing request context: %s", &output)
			}
			if strings.Contains(output.String(), "secret-") {
				t.Fatalf("sensitive request logged: %s", &output)
			}
		})
	}
}
