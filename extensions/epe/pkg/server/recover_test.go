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
package server

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeServerStream is the minimum grpc.ServerStream the interceptor touches: it
// reads Context() to find the logger and nothing else.
type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f fakeServerStream) Context() context.Context { return f.ctx }

func streamInfo() *grpc.StreamServerInfo {
	return &grpc.StreamServerInfo{FullMethod: "/envoy.service.ext_proc.v3.ExternalProcessor/Process"}
}

// A panicking handler must surface as an error on that stream rather than
// unwinding into the runtime, which is what would kill the process and every
// other stream with it.
func TestRecoverStreamPanic_ContainsPanic(t *testing.T) {
	ss := fakeServerStream{ctx: context.Background()}

	err := recoverStreamPanic(nil, ss, streamInfo(), func(any, grpc.ServerStream) error {
		panic("filter exploded")
	})

	if err == nil {
		t.Fatal("panic was not converted into an error")
	}
	if got := status.Code(err); got != codes.Internal {
		t.Errorf("status code = %v, want %v", got, codes.Internal)
	}
	// The panic value may name internals, and Envoy's failure_mode_allow — not
	// this message — decides what happens to the request.
	if strings.Contains(status.Convert(err).Message(), "filter exploded") {
		t.Errorf("panic value leaked into the gRPC message: %q", status.Convert(err).Message())
	}
}

// nilMap defeats the nilness analyzer, which would otherwise flag the
// deliberate nil-map write below as a defect rather than the fixture it is.
func nilMap() map[string]string { return nil }

// A runtime panic must be contained too, not just an explicit panic() call: the
// defects worth surviving are the unplanned ones.
func TestRecoverStreamPanic_ContainsRuntimePanic(t *testing.T) {
	ss := fakeServerStream{ctx: context.Background()}

	err := recoverStreamPanic(nil, ss, streamInfo(), func(any, grpc.ServerStream) error {
		nilMap()["boom"] = "x" // assignment to entry in nil map
		return nil
	})

	if status.Code(err) != codes.Internal {
		t.Errorf("status code = %v, want %v", status.Code(err), codes.Internal)
	}
}

// The happy path must be transparent: the handler's own return value, error or
// nil, has to reach gRPC unchanged, including a status the handler chose.
func TestRecoverStreamPanic_PassesThrough(t *testing.T) {
	ss := fakeServerStream{ctx: context.Background()}

	if err := recoverStreamPanic(nil, ss, streamInfo(), func(any, grpc.ServerStream) error {
		return nil
	}); err != nil {
		t.Errorf("nil return became %v", err)
	}

	sentinel := status.Error(codes.FailedPrecondition, "handler said so")
	err := recoverStreamPanic(nil, ss, streamInfo(), func(any, grpc.ServerStream) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("handler error was not passed through: got %v", err)
	}
}
