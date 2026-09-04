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

package echo

import (
	"strings"
	"testing"
)

func TestParseResponsesPreservesHeadersBodyAndWorkloads(t *testing.T) {
	output := `[0] X-Request-Id=0
[0] StatusCode=200
[0] Hostname=server-a
[0] RequestHeader=X-Test:first
[0] RequestHeader=X-Test:second
[0] ResponseHeader=Content-Type:text/plain
[0 body] key=value=with-equals
[1] X-Request-Id=1
[1] StatusCode=201
[1] Hostname=server-b
`
	responses, err := ParseResponses(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 2 || responses[0].StatusCode != 200 || responses[1].StatusCode != 201 {
		t.Fatalf("responses = %+v", responses)
	}
	if got := responses[0].RequestHeaders.Values("X-Test"); len(got) != 2 || got[1] != "second" {
		t.Fatalf("request headers = %#v", responses[0].RequestHeaders)
	}
	if responses[0].Body["key"] != "value=with-equals" {
		t.Fatalf("body = %#v", responses[0].Body)
	}
}

func TestParseResponsesRejectsMalformedStatusCode(t *testing.T) {
	_, err := ParseResponses("[0] StatusCode=success\n")
	if err == nil || !strings.Contains(err.Error(), "StatusCode") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseResponsesRejectsOutputWithoutRequestFrames(t *testing.T) {
	_, err := ParseResponses("ordinary log line\n")
	if err == nil || !strings.Contains(err.Error(), "request frames") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseResponsesProjectsCurrentEchoBodyMetadata(t *testing.T) {
	output := `[0] Url=http://server.sandbox.svc.cluster.local:80
[0] StatusCode=200
[0 body] Host=server.sandbox.svc.cluster.local:80
[0 body] URL=/
[0 body] Proto=HTTP/1.1
[0 body] Hostname=server-7645585ff8-cdwtz
`
	responses, err := ParseResponses(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 1 {
		t.Fatalf("responses = %+v", responses)
	}
	response := responses[0]
	if response.Hostname != "server-7645585ff8-cdwtz" || response.Host != "server.sandbox.svc.cluster.local:80" || response.URL != "/" || response.Protocol != "HTTP/1.1" {
		t.Fatalf("response metadata = %+v", response)
	}
}

func TestParseResponsesAllowsFourMiBConfigDump(t *testing.T) {
	marker := "tp-large-config-dump"
	output := "[0] StatusCode=200\n[0 body] config=" + strings.Repeat("x", 3*1024*1024) + marker + "\n"
	responses, err := ParseResponses(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 1 || !strings.Contains(responses[0].RawContent, marker) {
		t.Fatalf("large response did not preserve marker; responses = %d", len(responses))
	}
}
