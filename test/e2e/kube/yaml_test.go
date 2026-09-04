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

package kube

import (
	"strings"
	"testing"
)

func TestDecodeYAMLSkipsEmptyDocuments(t *testing.T) {
	objects, err := DecodeYAML(strings.NewReader("\n---\n# comment only\n---\nnull\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 0 {
		t.Fatalf("objects = %#v, want none", objects)
	}
}

func TestDecodeYAMLDecodesMultipleDocuments(t *testing.T) {
	input := `apiVersion: v1
kind: ConfigMap
metadata:
  name: first
---
apiVersion: v1
kind: Service
metadata:
  name: second
`
	objects, err := DecodeYAML(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 2 || objects[0].GetName() != "first" || objects[1].GetName() != "second" {
		t.Fatalf("objects = %#v", objects)
	}
}

func TestDecodeYAMLFlattensListInOrder(t *testing.T) {
	input := `apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: ConfigMap
  metadata:
    name: first
- apiVersion: v1
  kind: Secret
  metadata:
    name: second
`
	objects, err := DecodeYAML(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 2 || objects[0].GetKind() != "ConfigMap" || objects[1].GetKind() != "Secret" {
		t.Fatalf("objects = %#v", objects)
	}
}

func TestDecodeYAMLReportsDocumentNumber(t *testing.T) {
	input := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: valid\n---\nmetadata: [broken\n"
	_, err := DecodeYAML(strings.NewReader(input))
	if err == nil || !strings.Contains(err.Error(), "document 2") {
		t.Fatalf("error = %v, want document 2", err)
	}
}

func TestDecodeYAMLRejectsScalarDocument(t *testing.T) {
	_, err := DecodeYAML(strings.NewReader("just-a-string\n"))
	if err == nil || !strings.Contains(err.Error(), "document 1") {
		t.Fatalf("error = %v", err)
	}
}
