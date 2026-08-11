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

import (
	"maps"
	"slices"
)

// HeaderOpKind distinguishes the three header operations. HeaderOps is an
// ordered list, not a map, because ordered multi-value headers
// (set-cookie) cannot be expressed by map[string]string.
type HeaderOpKind uint8

const (
	// HeaderSet overwrites all existing values of the header.
	HeaderSet HeaderOpKind = iota
	// HeaderAppend adds one value, preserving order.
	HeaderAppend
	// HeaderRemove deletes the header. Envoy rejects REMOVE of
	// pseudo-headers and host unconditionally.
	HeaderRemove
)

// HeaderOp is one ordered header operation.
type HeaderOp struct {
	Kind  HeaderOpKind
	Name  string
	Value string
}

// Mutation is the plain, proto-free change set a filter returns. A filter
// must not modify a Mutation after returning it; the engine folds without
// deep-copying.
type Mutation struct {
	HeaderOps []HeaderOp
	// Body: nil = unchanged; non-nil (including empty) = replace.
	Body []byte
	// ClearRouteCache must be set when :path/:authority/:method/:scheme/
	// host change, or an earlier filter's cached route silently wins. The
	// helpers below set it for you; the adapter also forces it for those
	// keys.
	ClearRouteCache bool
}

func (m Mutation) equal(o Mutation) bool {
	return m.ClearRouteCache == o.ClearRouteCache &&
		slices.Equal(m.Body, o.Body) &&
		slices.Equal(m.HeaderOps, o.HeaderOps)
}

// SetHeader builds a single-op mutation overwriting name with value.
func SetHeader(name, value string) Mutation {
	return Mutation{HeaderOps: []HeaderOp{{Kind: HeaderSet, Name: name, Value: value}}}
}

// AppendHeader builds a single-op mutation appending one value.
func AppendHeader(name, value string) Mutation {
	return Mutation{HeaderOps: []HeaderOp{{Kind: HeaderAppend, Name: name, Value: value}}}
}

// RemoveHeader builds a single-op mutation removing the header.
func RemoveHeader(name string) Mutation {
	return Mutation{HeaderOps: []HeaderOp{{Kind: HeaderRemove, Name: name}}}
}

// SetPath rewrites :path. :path SET is allowed by Envoy's default mutation
// rules (unlike :method/:authority/:scheme/host); route-affecting, so
// ClearRouteCache is forced here rather than left to each filter.
func SetPath(path string) Mutation {
	return Mutation{
		HeaderOps:       []HeaderOp{{Kind: HeaderSet, Name: ":path", Value: path}},
		ClearRouteCache: true,
	}
}

// Reply is a blocking local response, translated to an ext_proc
// ImmediateResponse by the adapter.
type Reply struct {
	Status  int
	Headers map[string]string
	Body    []byte
	// Details feeds RESPONSE_CODE_DETAILS; the framework may synthesize it.
	Details string
}

func (r Reply) equal(o Reply) bool {
	return r.Status == o.Status && r.Details == o.Details &&
		slices.Equal(r.Body, o.Body) && maps.Equal(r.Headers, o.Headers)
}
