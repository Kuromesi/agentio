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

package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"go.uber.org/zap/zapcore"

	"github.com/openkruise/agentio/extensions/epe/pkg/logging"
)

const (
	loggingPath         = "/debug/logging"
	maxLoggingBodyBytes = 4096
	// A threshold above Fatal suppresses every record without changing the
	// logger's panic/fatal control flow.
	disabledLoggingLevel = zapcore.FatalLevel + 1
)

type loggingInfo struct {
	Name        string `json:"name"`
	OutputLevel string `json:"output_level"`
}

type loggingConfig struct {
	Level string `json:"level"`
}

type loggingUpdate struct {
	Name        string  `json:"name"`
	OutputLevel *string `json:"output_level"`
	Level       *string `json:"level"`
}

func (h *handler) handleLogging(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w = loggingHeadResponseWriter{w}
	}
	scoped := r.URL.Path != loggingPath && r.URL.Path != loggingPath+"/"
	if scoped {
		scope := strings.TrimPrefix(r.URL.Path, loggingPath+"/")
		if strings.Contains(scope, "/") {
			http.NotFound(w, r)
			return
		}
		if scope != "default" {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown logging scope %q", scope))
			return
		}
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		info := loggingInfo{Name: "default", OutputLevel: outputLevelName(h.logLevel.Level())}
		if scoped {
			writeJSON(w, http.StatusOK, info)
		} else {
			writeJSON(w, http.StatusOK, []loggingInfo{info})
		}
	case http.MethodPut:
		h.updateLogging(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed; use GET, HEAD or PUT")
	}
}

func (h *handler) updateLogging(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoggingBodyBytes))
	decoder.DisallowUnknownFields()
	var requested loggingUpdate
	if err := decoder.Decode(&requested); err != nil {
		writeError(w, http.StatusBadRequest, "invalid logging configuration: "+err.Error())
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "logging configuration must contain exactly one JSON object")
		return
	}
	if requested.Name != "" && requested.Name != "default" {
		writeError(w, http.StatusBadRequest, "logging name must match URL scope \"default\"")
		return
	}
	if (requested.OutputLevel == nil) == (requested.Level == nil) {
		writeError(w, http.StatusBadRequest, "specify exactly one of output_level or level")
		return
	}
	var level zapcore.Level
	var err error
	if requested.OutputLevel != nil {
		level, err = parseOutputLevel(*requested.OutputLevel)
	} else {
		level, err = parseLoggingLevel(*requested.Level)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.logLevel.SetLevel(level)
	if requested.OutputLevel != nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, loggingConfig{Level: loggingLevelName(level)})
}

// parseOutputLevel uses agentiod's names, mapping debug and info to EPE's
// verbosity constants. Numeric verbosity and other Zap names are EPE extensions.
func parseOutputLevel(name string) (zapcore.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return -logging.DEBUG, nil
	case "info":
		return -logging.DEFAULT, nil
	default:
		return parseLoggingLevel(name)
	}
}

// parseLoggingLevel follows --zap-log-level: names use Zap's levels, while a
// numeric string is a positive logr verbosity, e.g. "4" enables V(4).
// It also accepts none to disable output, as supported by agentiod.
func parseLoggingLevel(name string) (zapcore.Level, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "none" {
		return disabledLoggingLevel, nil
	}
	if name != "" {
		if level, err := zapcore.ParseLevel(name); err == nil {
			return level, nil
		}
		if verbosity, err := strconv.Atoi(name); err == nil && verbosity >= 0 && verbosity <= 127 {
			return zapcore.Level(-verbosity), nil
		}
	}
	return 0, fmt.Errorf(
		"invalid log level %q: use debug, info, warn, error, dpanic, panic, fatal, none, or a verbosity from 0 to 127",
		name,
	)
}

func outputLevelName(level zapcore.Level) string {
	switch level {
	case -logging.DEBUG:
		return "debug"
	case -logging.DEFAULT:
		return "info"
	case zapcore.DebugLevel, zapcore.InfoLevel:
		// Preserve the precise threshold when a Zap flag or the level field was
		// used: output_level's named debug/info have different verbosity.
		return strconv.Itoa(-int(level))
	default:
		return loggingLevelName(level)
	}
}

func loggingLevelName(level zapcore.Level) string {
	if level == disabledLoggingLevel {
		return "none"
	}
	if level < zapcore.DebugLevel {
		return strconv.Itoa(-int(level))
	}
	return level.String()
}

type loggingHeadResponseWriter struct {
	http.ResponseWriter
}

func (w loggingHeadResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}
