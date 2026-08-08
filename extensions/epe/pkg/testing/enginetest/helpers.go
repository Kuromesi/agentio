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

package enginetest

import (
	"context"
	"sync"
	"testing"
)

// DeliverySweep runs fn once per body-delivery shape Envoy actually produces
// in BUFFERED mode, handing it a function that attaches the body to a
// builder. There are exactly two shapes and both carry the complete body: the
// end-of-stream message, and the trailer flush that leaves EndOfStream clear.
// A verdict must come out the same either way — keying on EndOfStream
// releases the trailer-flush body unjudged, because trailer mode is SKIP and
// no further message follows it.
//
// Envoy never splits a body across messages in BUFFERED mode (it buffers
// internally and emits the whole body at once), so sweeping split points
// would exercise a wire shape production never sees; use BodyChunks directly
// to pin behaviour for that.
func DeliverySweep(t *testing.T, body []byte, fn func(t *testing.T, withBody func(*RequestBuilder) *RequestBuilder)) {
	t.Helper()
	shapes := []struct {
		name  string
		apply func(*RequestBuilder) *RequestBuilder
	}{
		{"end-of-stream", func(b *RequestBuilder) *RequestBuilder { return b.Body(body) }},
		{"trailer-flush", func(b *RequestBuilder) *RequestBuilder { return b.TrailerFlushedBody(body) }},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) { fn(t, s.apply) })
	}
}

// RunParallel drives n requests through the server concurrently, one
// stream each, and returns the verdicts in request order. The shared
// ResolutionProbe cannot attribute resolutions to individual concurrent
// requests, so Verdict.Resolution is left nil; assert on wire-level facts.
func (h *Harness) RunParallel(t *testing.T, n int, build func(i int) *RequestBuilder) []*Verdict {
	t.Helper()

	verdicts := make([]*Verdict, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stream := NewScriptedStream(context.Background(), build(i).Build()...)
			err := h.Server.Process(stream)
			verdicts[i] = ParseVerdict(stream.Responses(), err)
		}(i)
	}
	wg.Wait()
	return verdicts
}
