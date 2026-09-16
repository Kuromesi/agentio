// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

// Package scenario defines the client-side scenario contract without Kubernetes dependencies.
package scenario

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

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
