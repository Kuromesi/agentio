// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

// Package scenario defines the client-side scenario contract and factory registry.
// It intentionally has no Kubernetes dependency. Registries are populated at startup.
package scenario

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

type Factory[T any] func(json.RawMessage) (T, error)
type Registry[T any] struct{ factories map[string]Factory[T] }

func NewRegistry[T any]() *Registry[T] { return &Registry[T]{factories: map[string]Factory[T]{}} }
func (r *Registry[T]) Register(name string, f Factory[T]) error {
	if name == "" || f == nil {
		return errors.New("scenario name and factory are required")
	}
	if _, ok := r.factories[name]; ok {
		return fmt.Errorf("scenario %q already registered", name)
	}
	r.factories[name] = f
	return nil
}
func (r *Registry[T]) New(name string, config json.RawMessage) (T, error) {
	f, ok := r.factories[name]
	if !ok {
		var zero T
		return zero, fmt.Errorf("unknown scenario %q (available: %v)", name, r.Names())
	}
	return f(config)
}
func (r *Registry[T]) Names() []string {
	names := make([]string, 0, len(r.factories))
	for n := range r.factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Decode rejects unknown fields and trailing input, catching misspelled scenario options.
func Decode(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON value")
	}
	return nil
}
