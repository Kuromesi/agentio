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

package debug

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	agentiolog "github.com/openkruise/agentio/pkg/log"
)

const LoggingPath = "/debug/logging"

type loggingInfo = agentiolog.ScopeInfo

func serveLogging(w http.ResponseWriter, r *http.Request) {
	scope, scoped, valid := loggingScope(r.URL.Path)
	if !valid {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !scoped {
			writeLoggingJSON(w, r, agentiolog.Scopes())
			return
		}
		level, found := agentiolog.ScopeOutputLevelName(scope)
		if !found {
			http.Error(w, fmt.Sprintf("unknown logging scope %q", scope), http.StatusBadRequest)
			return
		}
		writeLoggingJSON(w, r, loggingInfo{Name: scope, OutputLevel: level})
	case http.MethodPut:
		if !scoped {
			scope = "default"
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		var requested loggingInfo
		if err := decoder.Decode(&requested); err != nil {
			http.Error(w, fmt.Sprintf("invalid logging configuration: %v", err), http.StatusBadRequest)
			return
		}
		if err := requireJSONEOF(decoder); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if requested.Name != "" && requested.Name != scope {
			http.Error(w, fmt.Sprintf("logging scope %q does not match URL scope %q", requested.Name, scope), http.StatusBadRequest)
			return
		}
		if err := agentiolog.SetScopeOutputLevelName(scope, requested.OutputLevel); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func loggingScope(path string) (string, bool, bool) {
	if path == LoggingPath || path == LoggingPath+"/" {
		return "", false, true
	}
	if !strings.HasPrefix(path, LoggingPath+"/") {
		return "", false, false
	}
	scope := strings.TrimPrefix(path, LoggingPath+"/")
	if scope == "" || strings.Contains(scope, "/") {
		return "", false, false
	}
	return scope, true, true
}

func writeLoggingJSON(w http.ResponseWriter, r *http.Request, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "failed to encode logging configuration", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(encoded)
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid logging configuration: multiple JSON values")
		}
		return fmt.Errorf("invalid logging configuration: %v", err)
	}
	return nil
}
