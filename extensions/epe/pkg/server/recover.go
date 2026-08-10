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
	"fmt"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	log "sigs.k8s.io/controller-runtime/pkg/log"
)

// recoverStreamPanic turns a panic in a stream handler into a failed stream.
//
// grpc-go does not recover handler panics, so without this one panicking filter
// takes the process down and with it every other in-flight stream on the pod —
// a request-scoped defect escalated to a pod-wide outage, and, because Envoy's
// ext_proc failure_mode_allow decides what happens to traffic when the processor
// is gone, potentially to unenforced egress for as long as the restart takes.
//
// This is the one place a stacktrace is worth its cost. A panic is a defect in
// this binary rather than a condition a client or a policy produced, its stack
// is the only thing that locates it, and it is not a per-request event — the
// reason the logger's stacktrace threshold sits above every level the request
// path uses (cmd/epe/main.go).
//
// The stream fails with codes.Internal and no detail from the panic value:
// Envoy's failure_mode_allow, not this message, decides the request's fate, and
// a panic value can carry internals that should not travel to the data plane.
func recoverStreamPanic(
	srv any,
	ss grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) (err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		log.FromContext(ss.Context()).Error(
			fmt.Errorf("panic in stream handler: %v", r),
			"Recovered from panic; failing this stream only",
			"method", info.FullMethod,
			"stack", string(debug.Stack()),
		)
		err = status.Error(codes.Internal, "internal error")
	}()
	return handler(srv, ss)
}
