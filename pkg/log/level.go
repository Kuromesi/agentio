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
	"log/slog"
	"sort"
	"strings"
	"sync"
)

var (
	outputLevel slog.LevelVar
	scopesMu    sync.RWMutex
	scopes      = map[string]*slog.LevelVar{}
)

// LevelNone is higher than every standard slog level and disables output.
const LevelNone slog.Level = 100

// DynamicLevel returns the process-wide level selector used by slog handlers.
// Handlers retain this object and observe later SetOutputLevel calls.
func DynamicLevel() slog.Leveler {
	return &outputLevel
}

func OutputLevel() slog.Level {
	return outputLevel.Level()
}

func OutputLevelName() string {
	return levelName(outputLevel.Level())
}

func SetOutputLevel(level slog.Level) {
	outputLevel.Set(level)
}

// ConfigureOutputLevel establishes the startup level for the default scope and
// every component registered during package initialization.
func ConfigureOutputLevel(level slog.Level) {
	outputLevel.Set(level)
	scopesMu.RLock()
	defer scopesMu.RUnlock()
	for _, scope := range scopes {
		scope.Set(level)
	}
}

func SetOutputLevelName(name string) error {
	level, err := ParseOutputLevelName(name)
	if err != nil {
		return err
	}
	SetOutputLevel(level)
	return nil
}

type ScopeInfo struct {
	Name        string `json:"name"`
	OutputLevel string `json:"output_level"`
}

func Scopes() []ScopeInfo {
	scopesMu.RLock()
	result := make([]ScopeInfo, 0, len(scopes)+1)
	result = append(result, ScopeInfo{Name: "default", OutputLevel: OutputLevelName()})
	for name, scope := range scopes {
		result = append(result, ScopeInfo{Name: name, OutputLevel: levelName(scope.Level())})
	}
	scopesMu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func ScopeOutputLevelName(name string) (string, bool) {
	if name == "default" {
		return OutputLevelName(), true
	}
	scopesMu.RLock()
	scope, found := scopes[name]
	scopesMu.RUnlock()
	if !found {
		return "", false
	}
	return levelName(scope.Level()), true
}

func SetScopeOutputLevelName(name, levelName string) error {
	level, err := ParseOutputLevelName(levelName)
	if err != nil {
		return err
	}
	if name == "default" {
		SetOutputLevel(level)
		return nil
	}
	scopesMu.RLock()
	scope, found := scopes[name]
	scopesMu.RUnlock()
	if !found {
		return fmt.Errorf("unknown logging scope %q", name)
	}
	scope.Set(level)
	return nil
}

func registerScope(name string) {
	if name == "" || name == "default" {
		return
	}
	scopesMu.Lock()
	defer scopesMu.Unlock()
	if _, found := scopes[name]; found {
		return
	}
	scope := &slog.LevelVar{}
	scope.Set(outputLevel.Level())
	scopes[name] = scope
}

func scopeEnabled(name string, level slog.Level) bool {
	if name == "" || name == "default" {
		return level >= outputLevel.Level()
	}
	scopesMu.RLock()
	scope, found := scopes[name]
	scopesMu.RUnlock()
	if !found {
		return level >= outputLevel.Level()
	}
	return level >= scope.Level()
}

func minimumOutputLevel() slog.Level {
	minimum := outputLevel.Level()
	scopesMu.RLock()
	defer scopesMu.RUnlock()
	for _, scope := range scopes {
		if scope.Level() < minimum {
			minimum = scope.Level()
		}
	}
	return minimum
}

func ParseOutputLevelName(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	case "none":
		return LevelNone, nil
	default:
		return 0, fmt.Errorf("invalid log level %q: must be debug, info, warn, error, or none", name)
	}
}

func levelName(level slog.Level) string {
	switch level {
	case slog.LevelDebug:
		return "debug"
	case slog.LevelInfo:
		return "info"
	case slog.LevelWarn:
		return "warn"
	case slog.LevelError:
		return "error"
	case LevelNone:
		return "none"
	default:
		return strings.ToLower(level.String())
	}
}
