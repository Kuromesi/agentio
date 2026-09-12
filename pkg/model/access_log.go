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

package model

import (
	"fmt"
	"strings"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

// ValidateAccessLogFormat validates the shape of a gateway's log format at
// configuration ingestion and compilation. Envoy validates substitution operators.
func ValidateAccessLogFormat(format *configv1.AccessLogFormat) error {
	if format == nil {
		return nil
	}
	// jsonpb silently accepts multiple oneof members. Keep presence-aware
	// fields and validate exclusivity here for both configuration sources.
	if format.Text != nil && format.Json != nil {
		return fmt.Errorf("accessLogFormat must specify only one of text or json")
	}
	if format.Text != nil && strings.TrimSpace(format.GetText()) == "" {
		return fmt.Errorf("accessLogFormat.text must not be blank")
	}
	if format.Json != nil && len(format.Json.GetFields()) == 0 {
		return fmt.Errorf("accessLogFormat.json must contain at least one field")
	}
	return nil
}
