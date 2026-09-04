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

// Package bypass skips the remaining actions and rules while preserving
// work already performed by earlier rules.
package bypass

import (
	"context"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

// FilterName is the registry name used for attribution.
const FilterName = "bypass"

// Config is intentionally empty.
type Config struct{}

type Filter struct{ filter.PassThrough }

func New(filter.RuleConfig[Config]) filter.Filter { return &Filter{} }

func (f *Filter) OnRequestHeaders(context.Context, *filter.Stream) (filter.Action, error) {
	return filter.Bypass(), nil
}

// Descriptor declares bypass to the framework.
func Descriptor() filter.Descriptor[Config] {
	return filter.Descriptor[Config]{
		Name:    FilterName,
		Phases:  filter.PhaseRequestHeaders,
		OnError: filter.Always[Config](filter.FailClosed),
		New:     New,
	}
}
