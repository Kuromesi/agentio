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

package httpcallout

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	protocol "github.com/openkruise/agentio/extensions/epe/pkg/filters/httpcallout"
)

func TestHandler(t *testing.T) {
	h := &Handler{}
	s := httptest.NewServer(h)
	defer s.Close()
	for _, phase := range []protocol.Phase{protocol.PhaseRequest, protocol.PhaseResponse} {
		inv := protocol.Invocation{
			Version: protocol.ProtocolVersion,
			Phase:   phase,
			Request: &protocol.HTTPRequest{Method: "POST"},
		}
		if phase == protocol.PhaseResponse {
			inv.Response = &protocol.HTTPResponse{StatusCode: 200}
		}
		raw, err := json.Marshal(inv)
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"continue", "mutate", "respond", "delay?duration=1ms"} {
			resp, err := http.Post(s.URL+"/"+mode, "application/json", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			var d protocol.Decision
			err = json.NewDecoder(resp.Body).Decode(&d)
			closeBody(t, resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.Validate(phase); err != nil {
				t.Fatalf("%s: %v", mode, err)
			}
			if mode == "mutate" && d.Request == nil && d.Response == nil {
				t.Fatal("missing mutation")
			}
		}
	}
	for _, body := range []string{`{}`, `{"version":"0.1","phase":"request","request":{}} {}`} {
		resp, err := http.Post(s.URL+"/continue", "application/json", bytes.NewBufferString(body))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}
		closeBody(t, resp.Body)
		if resp.StatusCode != 400 {
			t.Fatalf("invalid input status=%d", resp.StatusCode)
		}
	}
	if h.Calls.Load() != 8 || h.Active.Load() != 0 {
		t.Fatalf("calls=%d active=%d", h.Calls.Load(), h.Active.Load())
	}
}

func closeBody(t *testing.T, body io.Closer) {
	t.Helper()
	if err := body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
}
