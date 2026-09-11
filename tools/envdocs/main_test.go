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

package main

import (
	"strings"
	"testing"
)

func TestReplaceTablePreservesHandwrittenContent(t *testing.T) {
	prefix := "# Reference\n\nManual instructions.\n\n" + beginMarker
	suffix := endMarker + "\n\n## Examples\n\nKeep this example exactly.\n"
	original := prefix + "\nOld generated content\n" + suffix
	table := []byte("| Variable | Type | Binary default | Description |\n| --- | --- | --- | --- |\n| TEST | String | empty | Example |\n")
	got, err := replaceTable([]byte(original), table)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), prefix) || !strings.HasSuffix(string(got), suffix) || strings.Contains(string(got), "Old generated content") {
		t.Fatalf("handwritten content was not preserved: %s", got)
	}
	again, err := replaceTable(got, table)
	if err != nil || string(again) != string(got) {
		t.Fatalf("generation is not idempotent: %v", err)
	}
}

func TestReplaceTableRejectsAmbiguousMarkersAndBadOutput(t *testing.T) {
	table := []byte("| Variable | Type | Binary default | Description |\n| --- | --- | --- | --- |\n| TEST | String | empty | Example |\n")
	for _, document := range []string{
		"no markers", beginMarker, endMarker,
		endMarker + beginMarker,
		beginMarker + beginMarker + endMarker,
		beginMarker + endMarker + endMarker,
	} {
		if _, err := replaceTable([]byte(document), table); err == nil {
			t.Errorf("accepted invalid markers: %q", document)
		}
	}
	for _, output := range [][]byte{nil, []byte("log message\n"), []byte("| Variable | Type | Binary default | Description |\n")} {
		if _, err := replaceTable([]byte(beginMarker+endMarker), output); err == nil {
			t.Errorf("accepted invalid export: %q", output)
		}
	}
}
