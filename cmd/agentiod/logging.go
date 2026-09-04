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
	"fmt"
	"io"
	"log/slog"
	"strings"

	"k8s.io/klog/v2"

	agentiolog "github.com/openkruise/agentio/pkg/log"
	"istio.io/istio/pkg/env"
)

var (
	logLevel = env.Register(
		"AGENTIO_LOG_LEVEL",
		"info",
		"Minimum agentiod log level: debug, info, warn, error, or none.",
	).Get()
	logFormat = env.Register(
		"AGENTIO_LOG_FORMAT",
		"text",
		"agentiod log encoding: text or json.",
	).Get()
)

func newLogger(output io.Writer, levelName, formatName string) (*slog.Logger, error) {
	format := strings.ToLower(strings.TrimSpace(formatName))
	if format != "text" && format != "json" {
		return nil, fmt.Errorf("invalid AGENTIO_LOG_FORMAT %q: must be text or json", formatName)
	}
	level, err := agentiolog.ParseOutputLevelName(levelName)
	if err != nil {
		return nil, fmt.Errorf("invalid AGENTIO_LOG_LEVEL: %w", err)
	}
	agentiolog.ConfigureOutputLevel(level)

	options := &slog.HandlerOptions{Level: slog.LevelDebug}
	var handler slog.Handler
	switch format {
	case "text":
		handler = slog.NewTextHandler(output, options)
	case "json":
		handler = slog.NewJSONHandler(output, options)
	}
	return slog.New(agentiolog.NewDynamicHandler(handler)), nil
}

func installLogger(logger *slog.Logger) {
	slog.SetDefault(logger)
	klog.SetSlogLogger(logger)
}
