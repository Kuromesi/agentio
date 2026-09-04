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

package log

import (
	"context"
	"log/slog"
)

// NewDynamicHandler filters records using their component attribute. Records
// without a component use the default scope.
func NewDynamicHandler(next slog.Handler) slog.Handler {
	return &dynamicHandler{next: next}
}

type dynamicHandler struct {
	next      slog.Handler
	component string
}

func (h *dynamicHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if h.component != "" {
		return scopeEnabled(h.component, level) && h.next.Enabled(ctx, level)
	}
	return level >= minimumOutputLevel() && h.next.Enabled(ctx, level)
}

func (h *dynamicHandler) Handle(ctx context.Context, record slog.Record) error {
	component := h.component
	record.Attrs(func(attribute slog.Attr) bool {
		if attribute.Key == "component" && attribute.Value.Kind() == slog.KindString {
			component = attribute.Value.String()
		}
		return true
	})
	if !scopeEnabled(component, record.Level) {
		return nil
	}
	return h.next.Handle(ctx, record)
}

func (h *dynamicHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	component := h.component
	for _, attribute := range attributes {
		if attribute.Key == "component" && attribute.Value.Kind() == slog.KindString {
			component = attribute.Value.String()
		}
	}
	return &dynamicHandler{next: h.next.WithAttrs(attributes), component: component}
}

func (h *dynamicHandler) WithGroup(name string) slog.Handler {
	return &dynamicHandler{next: h.next.WithGroup(name), component: h.component}
}
