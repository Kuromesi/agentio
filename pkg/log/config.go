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
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// NewLogger creates the text or JSON logger shared by Agentio processes and
// initializes the output level for all registered components.
func NewLogger(output io.Writer, levelName, formatName string) (*slog.Logger, error) {
	format := strings.ToLower(strings.TrimSpace(formatName))
	if format != "text" && format != "json" {
		return nil, fmt.Errorf("invalid AGENTIO_LOG_FORMAT %q: must be text or json", formatName)
	}
	level, err := ParseOutputLevelName(levelName)
	if err != nil {
		return nil, fmt.Errorf("invalid AGENTIO_LOG_LEVEL: %w", err)
	}
	ConfigureOutputLevel(level)

	options := &slog.HandlerOptions{Level: slog.LevelDebug}
	var handler slog.Handler
	switch format {
	case "text":
		handler = slog.NewTextHandler(output, options)
	case "json":
		handler = slog.NewJSONHandler(output, options)
	}
	return slog.New(NewDynamicHandler(handler)), nil
}
