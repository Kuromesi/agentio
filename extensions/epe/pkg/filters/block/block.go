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

// Package block short-circuits a matched request with a configured HTTP
// response.
package block

import (
	"context"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// FilterName is the registry name used for metrics and accesslog attribution.
const FilterName = "block"

// defaultStatus is used when Config.Status is zero (the CRD also defaults
// to 403).
const defaultStatus = 403

// Config is the filter's decoded form of a block payload.
type Config struct {
	Status int
	// Body is sent verbatim; Envoy applies a default text/plain
	// content-type. Empty means no body.
	Body string
	// HasBody distinguishes "empty body configured" from "no body".
	HasBody bool
}

// Filter stops with the configured reply.
type Filter struct {
	filter.PassThrough
	cfg Config
}

func New(rule filter.RuleConfig[Config]) filter.Filter {
	return &Filter{cfg: rule.Cfg}
}

func (f *Filter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	status := f.cfg.Status
	if status == 0 {
		status = defaultStatus
	}
	var body []byte
	if f.cfg.HasBody {
		body = []byte(f.cfg.Body)
	}
	return filter.Stop(filter.Reply{Status: status, Body: body}), nil
}

// Descriptor declares block to the framework.
func Descriptor() filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name:    FilterName,
		Phases:  filter.PhaseRequestHeaders,
		OnError: filter.Always[Config](filter.FailClosed),
		New:     New,
	}
}
