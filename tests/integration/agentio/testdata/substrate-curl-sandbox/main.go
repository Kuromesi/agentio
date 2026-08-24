// Copyright 2026 The Kruise Authors.
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

// Command egress accepts an HTTP or HTTPS URL and fetches it by executing the
// curl binary inside the Actor sandbox. The response includes runtime evidence
// so the PoC can distinguish sandbox execution from a Worker-side request.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	listenAddress  = ":80"
	curlBinary     = "/usr/bin/curl"
	maxRequestBody = 64 << 10
	requestTimeout = 20 * time.Second
	statusMarker   = "\n__AGENTIO_CURL_HTTP_STATUS__:"
)

type fetchRequest struct {
	URL string `json:"url"`
}

type executionEvidence struct {
	Binary           string   `json:"binary"`
	Argv             []string `json:"argv"`
	CurlVersion      string   `json:"curlVersion"`
	PID              int      `json:"pid"`
	Hostname         string   `json:"hostname"`
	PIDNamespace     string   `json:"pidNamespace"`
	NetworkNamespace string   `json:"networkNamespace"`
	MountNamespace   string   `json:"mountNamespace"`
	Cgroup           string   `json:"cgroup,omitempty"`
}

type fetchResponse struct {
	StatusCode int                `json:"statusCode,omitempty"`
	Body       string             `json:"body,omitempty"`
	Error      string             `json:"error,omitempty"`
	Execution  *executionEvidence `json:"execution,omitempty"`
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	slog.Info("starting sandbox curl demo", "address", listenAddress, "curl", curlBinary)
	if err := http.ListenAndServe(listenAddress, newHandler()); err != nil {
		slog.Error("sandbox curl demo stopped", "error", err)
		os.Exit(1)
	}
}

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, fetchResponse{Error: "method must be POST"})
			return
		}

		var input fetchRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
		if err := decoder.Decode(&input); err != nil {
			writeJSON(w, http.StatusBadRequest, fetchResponse{Error: fmt.Sprintf("invalid JSON payload: %v", err)})
			return
		}
		if err := validateURL(input.URL); err != nil {
			writeJSON(w, http.StatusBadRequest, fetchResponse{Error: err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()
		statusCode, body, evidence, err := executeCurl(ctx, input.URL, r.Header.Get("traceparent"))
		if err != nil {
			writeJSON(w, http.StatusBadGateway, fetchResponse{
				Error:     fmt.Sprintf("curl failed: %v", err),
				Execution: evidence,
			})
			return
		}
		writeJSON(w, statusCode, fetchResponse{StatusCode: statusCode, Body: body, Execution: evidence})
	})
	return mux
}

func executeCurl(ctx context.Context, target, traceparent string) (int, string, *executionEvidence, error) {
	args := []string{
		"--silent",
		"--show-error",
		"--max-time", strconv.Itoa(int(requestTimeout.Seconds())),
		"--output", "-",
		"--write-out", statusMarker + "%{http_code}",
	}
	if traceparent != "" {
		args = append(args, "--header", "traceparent: "+traceparent)
	}
	args = append(args, target)

	evidence := collectExecutionEvidence(args)
	slog.Info("executing curl inside actor sandbox", "pid", evidence.PID, "hostname", evidence.Hostname,
		"pid_namespace", evidence.PIDNamespace, "network_namespace", evidence.NetworkNamespace,
		"argv", append([]string{curlBinary}, args...))

	output, err := exec.CommandContext(ctx, curlBinary, args...).CombinedOutput()
	if err != nil {
		return 0, "", evidence, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	markerIndex := strings.LastIndex(string(output), statusMarker)
	if markerIndex < 0 {
		return 0, "", evidence, fmt.Errorf("curl output did not contain HTTP status marker")
	}
	body := string(output[:markerIndex])
	statusText := strings.TrimSpace(string(output[markerIndex+len(statusMarker):]))
	statusCode, err := strconv.Atoi(statusText)
	if err != nil || statusCode < 100 || statusCode > 599 {
		return 0, "", evidence, fmt.Errorf("invalid HTTP status %q", statusText)
	}
	return statusCode, body, evidence, nil
}

func collectExecutionEvidence(args []string) *executionEvidence {
	hostname, _ := os.Hostname()
	return &executionEvidence{
		Binary:           curlBinary,
		Argv:             append([]string(nil), args...),
		CurlVersion:      curlVersion(),
		PID:              os.Getpid(),
		Hostname:         hostname,
		PIDNamespace:     readLink("/proc/self/ns/pid"),
		NetworkNamespace: readLink("/proc/self/ns/net"),
		MountNamespace:   readLink("/proc/self/ns/mnt"),
		Cgroup:           readFile("/proc/self/cgroup"),
	}
}

func curlVersion() string {
	output, err := exec.Command(curlBinary, "--version").Output()
	if err != nil {
		return fmt.Sprintf("unavailable: %v", err)
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(output)), "\n")
	return line
}

func readLink(path string) string {
	value, err := os.Readlink(path)
	if err != nil {
		return fmt.Sprintf("unavailable: %v", err)
	}
	return value
}

func readFile(path string) string {
	value, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("unavailable: %v", err)
	}
	return strings.TrimSpace(string(value))
}

func validateURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}
	if parsed.Hostname() == "" {
		return fmt.Errorf("URL must include a hostname")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, response fetchResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}
