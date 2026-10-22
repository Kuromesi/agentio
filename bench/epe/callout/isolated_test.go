// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package callout

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/procfs"

	calloutfixture "github.com/openkruise/agentio/test/fixtures/httpcallout"
)

var (
	isolatedLoad = flag.Bool(
		"callout-isolated",
		false,
		"run EPE, callout endpoint and upstream in separate processes",
	)
	processRole      = flag.String("callout-process-role", "", "internal isolated fixture role")
	processReady     = flag.String("callout-process-ready", "", "internal ready file")
	processEndpoint  = flag.String("callout-process-endpoint", "", "internal endpoint URL")
	processUpstream  = flag.String("callout-process-upstream", "", "internal upstream URL")
	processArtifacts = flag.String("callout-process-artifacts", "", "isolated child logs and CPU profiles directory")
)

func TestCalloutProcess(t *testing.T) {
	if *processRole == "" {
		t.Skip("isolated fixture helper")
	}
	// Return through testing's normal shutdown so -test.cpuprofile is flushed.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	var url string
	switch *processRole {
	case "endpoint":
		s := httptest.NewServer(&calloutfixture.Handler{})
		defer s.Close()
		url = s.URL
	case "upstream":
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if _, err := w.Write(body); err != nil {
				t.Logf("upstream response interrupted: %v", err)
			}
		}))
		defer s.Close()
		url = s.URL
	case "epe":
		f := newFixtureWithEndpoints(t, *processEndpoint, *processUpstream)
		url = f.url
	default:
		t.Fatalf("unknown role %q", *processRole)
	}
	if err := os.WriteFile(*processReady, []byte(url), 0600); err != nil {
		t.Fatal(err)
	}
	<-stop
}

func newIsolatedFixture(t *testing.T) *fixture {
	t.Helper()
	if *envoyImage == "" {
		t.Skip("set -envoy-image to run isolated load")
	}
	dir := *processArtifacts
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := func(role, procs, endpoint, upstream string) (string, int) {
		ready := filepath.Join(t.TempDir(), role+".ready")
		args := []string{
			"-test.run=^TestCalloutProcess$",
			"-test.v",
			"-test.timeout=15m",
			"-callout-process-role=" + role,
			"-callout-process-ready=" + ready,
			"-envoy-image=" + *envoyImage,
			"-callout-forward-headers=" + strconv.FormatBool(*forwardHeaders),
			"-callout-process-endpoint=" + endpoint,
			"-callout-process-upstream=" + upstream,
		}
		if *processArtifacts != "" {
			args = append(args, "-test.cpuprofile="+filepath.Join(dir, role+".pprof"))
		}
		cmd := exec.Command(binary, args...)
		for _, v := range os.Environ() {
			if !strings.HasPrefix(v, "GOMAXPROCS=") {
				cmd.Env = append(cmd.Env, v)
			}
		}
		cmd.Env = append(cmd.Env, "GOMAXPROCS="+procs)
		log, err := os.Create(filepath.Join(dir, role+".log"))
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			closeBody(t, log)
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		t.Cleanup(func() {
			if err := cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Errorf("interrupt %s: %v", role, err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("%s process: %v; log: %s", role, err, log.Name())
				}
			case <-time.After(15 * time.Second):
				if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					t.Errorf("kill %s: %v", role, err)
				}
				<-done
				t.Errorf("%s failed to stop", role)
			}
			closeBody(t, log)
		})
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
			raw, err := os.ReadFile(ready)
			if err == nil && len(raw) > 0 {
				return string(raw), cmd.Process.Pid
			}
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s not ready; log: %s", role, log.Name())
		return "", 0
	}
	endpoint, endpointPID := start("endpoint", "8", "", "")
	upstream, _ := start("upstream", "4", "", "")
	proxy, pid := start("epe", "4", endpoint, upstream)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns, tr.MaxIdleConnsPerHost = 512, 256
	t.Cleanup(tr.CloseIdleConnections)
	// The parent owns only load generation; child profiles exclude other roles.
	return &fixture{
		url:         proxy,
		statsURL:    endpoint + "/stats",
		client:      &http.Client{Transport: tr, Timeout: 10 * time.Second},
		epePID:      pid,
		endpointPID: endpointPID,
	}
}

func (f *fixture) endpointStats(t *testing.T) (int64, int64) {
	t.Helper()
	if f.statsURL == "" {
		return f.handler.Calls.Load(), f.handler.Active.Load()
	}
	resp, err := f.client.Get(f.statsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBody(t, resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("stats status: %d", resp.StatusCode)
	}
	var stats struct {
		Calls  int64 `json:"calls"`
		Active int64 `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	return stats.Calls, stats.Active
}

func (f *fixture) callCount(t *testing.T) int64 {
	calls, _ := f.endpointStats(t)
	return calls
}
func (f *fixture) activeCalls(t *testing.T) int64 {
	_, active := f.endpointStats(t)
	return active
}

func (f *fixture) epeResources(t *testing.T) (float64, int) {
	t.Helper()
	return processResources(t, f.epePID)
}

func processResources(t *testing.T, pid int) (float64, int) {
	t.Helper()
	if pid == 0 {
		return 0, 0
	}
	p, err := procfs.NewProc(pid)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return s.CPUTime(), s.ResidentMemory()
}
