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

// Package log provides module loggers backed by the process-wide slog handler.
package log

import (
	"context"
	"log/slog"
	"runtime"
	"time"
)

// Logger carries immutable module and request attributes. It deliberately does
// not retain a slog.Handler, so package-level loggers follow later calls to
// slog.SetDefault made by the process entrypoint.
type Logger struct {
	component string
	attrs     []any
}

// New returns a logger that identifies records with component.
func New(component string) *Logger {
	registerScope(component)
	return &Logger{component: component, attrs: []any{"component", component}}
}

// With returns a logger containing the receiver's attributes followed by attrs.
func (l *Logger) With(attrs ...any) *Logger {
	combined := make([]any, 0, len(l.attrs)+len(attrs))
	combined = append(combined, l.attrs...)
	combined = append(combined, attrs...)
	return &Logger{component: l.component, attrs: combined}
}

// Enabled reports whether the current process handler accepts level.
func (l *Logger) Enabled(ctx context.Context, level slog.Level) bool {
	return scopeEnabled(l.component, level) && slog.Default().Enabled(ctx, level)
}

// DebugEnabled reports whether debug records would be emitted. Callers use it to
// guard attributes that are expensive to build.
func (l *Logger) DebugEnabled() bool {
	return l.Enabled(context.Background(), slog.LevelDebug)
}

// Debug logs a structured message at debug level.
func (l *Logger) Debug(msg string, attrs ...any) {
	l.emit(context.Background(), slog.LevelDebug, msg, attrs...)
}

// Info logs a structured message at info level.
func (l *Logger) Info(msg string, attrs ...any) {
	l.emit(context.Background(), slog.LevelInfo, msg, attrs...)
}

// Warn logs a structured message at warn level.
func (l *Logger) Warn(msg string, attrs ...any) {
	l.emit(context.Background(), slog.LevelWarn, msg, attrs...)
}

// Error logs a structured message at error level.
func (l *Logger) Error(msg string, attrs ...any) {
	l.emit(context.Background(), slog.LevelError, msg, attrs...)
}

func (l *Logger) emit(ctx context.Context, level slog.Level, msg string, attrs ...any) {
	logger := slog.Default()
	if !l.Enabled(ctx, level) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(3, pcs[:]) // Callers, emit, level method, original caller.
	record := slog.NewRecord(time.Now(), level, msg, pcs[0])
	record.Add(l.attrs...)
	record.Add(attrs...)
	_ = logger.Handler().Handle(ctx, record)
}
