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
	"testing"
	"testing/synctest"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoytype "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/openkruise/agentio/extensions/porter/pkg/metrics"
)

type timedStream struct {
	logTestStream
	sendErr error
}

func (s *timedStream) Recv() (*extproc.ProcessingRequest, error) {
	time.Sleep(10 * time.Second)
	return s.message, nil
}
func (s *timedStream) Send(*extproc.ProcessingResponse) error {
	time.Sleep(2 * time.Second)
	return s.sendErr
}

func TestConnectMetrics(t *testing.T) {
	for _, tc := range []struct {
		name       string
		result     string
		udp        bool
		deny       bool
		handlerErr error
		sendErr    error
	}{
		{name: "allow", result: "allow"},
		{name: "udp deny", result: "deny", udp: true, deny: true},
		{name: "timeout", result: "timeout", handlerErr: context.DeadlineExceeded},
		{name: "canceled", result: "canceled", handlerErr: context.Canceled},
		{name: "handler error", result: "error", handlerErr: errors.New("lookup failed")},
		{name: "send error overrides deny", result: "error", deny: true, sendErr: errors.New("send failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m := metrics.New()
				message := connectMessage("")
				protocol := "tcp"
				if tc.udp {
					protocol = "udp"
					message.GetRequestHeaders().Headers.Headers[0].Value = "GET"
					message.GetRequestHeaders().Headers.Headers = append(
						message.GetRequestHeaders().Headers.Headers,
						&core.HeaderValue{Key: "upgrade", Value: "connect-udp"},
					)
				}
				server := Server{
					Metrics: m,
					Timeout: 4 * time.Second,
					Handler: handlerFunc(func(context.Context, Request) (Result, error) {
						families, err := m.Registry.Gather()
						if err != nil {
							t.Fatal(err)
						}
						found := false
						for _, f := range families {
							if f.GetName() == "agentio_porter_connect_inflight" {
								for _, v := range f.Metric {
									if v.GetLabel()[0].GetValue() == protocol {
										found = true
										if v.GetGauge().GetValue() != 1 {
											t.Error("inflight not recorded during handler")
										}
									}
								}
							}
						}
						if !found {
							t.Error("inflight missing")
						}
						time.Sleep(time.Second)
						result := Result{}
						if tc.deny {
							result.DenyStatus = envoytype.StatusCode_Forbidden
						}
						return result, tc.handlerErr
					}),
				}
				err := server.Process(&timedStream{logTestStream: logTestStream{message: message}, sendErr: tc.sendErr})
				if (err != nil) != (tc.handlerErr != nil || tc.sendErr != nil) {
					t.Fatalf("Process: %v", err)
				}
				families, err := m.Registry.Gather()
				if err != nil {
					t.Fatal(err)
				}
				foundDuration := false
				for _, f := range families {
					for _, v := range f.Metric {
						switch f.GetName() {
						case "agentio_porter_connect_duration_seconds":
							foundDuration = true
							want := 3.0
							if tc.handlerErr != nil {
								want = 1
							}
							if v.GetHistogram().GetSampleCount() != 1 || v.GetHistogram().GetSampleSum() != want {
								t.Errorf("duration includes receive wait or excludes response send: %v", v)
							}
							labels := map[string]string{}
							for _, l := range v.Label {
								labels[l.GetName()] = l.GetValue()
							}
							if labels["protocol"] != protocol || labels["result"] != tc.result {
								t.Errorf("labels: %v", labels)
							}
						case "agentio_porter_connect_inflight":
							if v.GetGauge().GetValue() != 0 {
								t.Error("inflight leaked")
							}
						}
					}
				}
				if !foundDuration {
					t.Fatal("missing duration")
				}
			})
		})
	}
}
