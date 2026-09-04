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
package filter

import "github.com/openkruise/agentio/extensions/epe/pkg/httpreq"

// Body is the complete buffered view of one direction's body; both
// OnRequestBody and OnResponseBody receive it.
type Body struct {
	Bytes []byte
	// Complete reports that Bytes is the whole body. The adapter only ever
	// dispatches whole bodies — it requests Envoy's BUFFERED mode, which
	// delivers the body in one message — so this is always true in practice.
	// The field lets a filter that must not decide on a fragment reject one
	// explicitly rather than assuming.
	Complete bool
}

// Stream is the per-request view handed to every filter. Filters must treat
// its fields as read-only.
type Stream struct {
	Peer      Peer
	Request   httpreq.HTTPRequest
	RequestID string
	// Response is populated from OnResponseHeaders onward.
	Response httpreq.HTTPResponse
	// Info accumulates per-stream observations; the engine writes it, the
	// stream loggers read it at stream end.
	Info *StreamInfo
}
