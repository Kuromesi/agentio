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
)

const maxLoggingBodyBytes = 4096

type loggingConfig struct {
	Level string `json:"level"`
}

func (h *handler) handleLogging(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, loggingConfig{Level: loggingLevelName(h.logLevel.Level())})
	case http.MethodPut:
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoggingBodyBytes))
		decoder.DisallowUnknownFields()
		var requested loggingConfig
		if err := decoder.Decode(&requested); err != nil {
			writeError(w, http.StatusBadRequest, "invalid logging configuration: "+err.Error())
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			writeError(w, http.StatusBadRequest, "logging configuration must contain exactly one JSON object")
			return
		}
		level, err := parseLoggingLevel(requested.Level)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.logLevel.SetLevel(level)
		writeJSON(w, http.StatusOK, loggingConfig{Level: loggingLevelName(level)})
	default:
		w.Header().Set("Allow", "GET, PUT")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed; use GET or PUT")
	}
}

// parseLoggingLevel follows --zap-log-level: names use Zap's levels, while a
// numeric string is a positive logr verbosity, e.g. "4" enables V(4).
func parseLoggingLevel(name string) (zapcore.Level, error) {
	name = strings.TrimSpace(name)
	if name != "" {
		if level, err := zapcore.ParseLevel(name); err == nil {
			return level, nil
		}
		if verbosity, err := strconv.Atoi(name); err == nil && verbosity >= 0 && verbosity <= 127 {
			return zapcore.Level(-verbosity), nil
		}
	}
	return 0, fmt.Errorf(
		"invalid log level %q: use debug, info, warn, error, dpanic, panic, fatal, or a verbosity from 0 to 127",
		name,
	)
}

func loggingLevelName(level zapcore.Level) string {
	if level < zapcore.DebugLevel {
		return strconv.Itoa(-int(level))
	}
	return level.String()
}
