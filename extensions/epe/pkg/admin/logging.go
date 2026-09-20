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
	var requested loggingInfo
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
	level, err := parseOutputLevel(requested.OutputLevel)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.logLevel.SetLevel(level)
	w.WriteHeader(http.StatusAccepted)
}

// parseOutputLevel uses agentiod's names, mapping debug and info to EPE's
// verbosity constants. Numeric verbosity and other Zap names are EPE extensions.
func parseOutputLevel(name string) (zapcore.Level, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "debug":
		return -logging.DEBUG, nil
	case "info":
		return -logging.DEFAULT, nil
	case "none":
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
	case disabledLoggingLevel:
		return "none"
	}
	if level <= zapcore.InfoLevel {
		// Preserve exact verbosity, including Zap flag values 0 and 1:
		// output_level's named info/debug mean EPE verbosity 2 and 4.
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
