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
	"github.com/prometheus/client_golang/prometheus"
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

func TestConnectDuration(t *testing.T) {
	for _, tc := range []struct {
		name       string
		udp        bool
		handlerErr error
		sendErr    error
	}{
		{name: "tcp"},
		{name: "udp", udp: true},
		{name: "timeout", handlerErr: context.DeadlineExceeded},
		{name: "send error", sendErr: errors.New("send failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				duration := prometheus.NewHistogramVec(
					prometheus.HistogramOpts{Name: "connect_duration_seconds"},
					[]string{"protocol"},
				)
				registry := prometheus.NewRegistry()
				registry.MustRegister(duration)
				message := connectMessage("")
				protocol := "tcp"
				if tc.udp {
					protocol = "udp"
					message.GetRequestHeaders().Headers.Headers[0].Value = "GET"
					message.GetRequestHeaders().Headers.Headers = append(message.GetRequestHeaders().Headers.Headers,
						&core.HeaderValue{Key: "upgrade", Value: "connect-udp"})
				}
				server := Server{
					ConnectDuration: duration,
					Timeout:         4 * time.Second,
					Handler: handlerFunc(func(context.Context, Request) (Result, error) {
						time.Sleep(time.Second)
						return Result{}, tc.handlerErr
					}),
				}
				err := server.Process(&timedStream{logTestStream: logTestStream{message: message}, sendErr: tc.sendErr})
				if (err != nil) != (tc.handlerErr != nil || tc.sendErr != nil) {
					t.Fatalf("Process: %v", err)
				}
				families, err := registry.Gather()
				if err != nil {
					t.Fatal(err)
				}
				if len(families) != 1 || len(families[0].Metric) != 1 {
					t.Fatalf("expected one histogram: %v", families)
				}
				sample := families[0].Metric[0]
				want := 3.0
				if tc.handlerErr != nil {
					want = 1
				}
				if sample.GetHistogram().GetSampleCount() != 1 || sample.GetHistogram().GetSampleSum() != want {
					t.Errorf("duration includes receive wait or excludes response send: %v", sample)
				}
				if sample.GetLabel()[0].GetValue() != protocol {
					t.Errorf("protocol label: %v", sample.GetLabel())
				}
			})
		})
	}
}
