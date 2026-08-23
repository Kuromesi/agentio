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

// Package policyready gates pilot-agent readiness on the gateway policy store
// having synced, so that an unsynced gateway stays out of the load balancer
// instead of accepting connections and then fail-closing them.
//
// It lives in its own package rather than extending status/ready so that the
// only edits to upstream Istio files are the injection site in status/server.go.
package policyready

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"istio.io/istio/pkg/http"
)

const (
	// readyStat is the Envoy gauge published by the native gateway policy store.
	// It becomes 1 after the first Workload discovery response and the first
	// response for every policy TypeURL referenced by those workloads. Missing
	// named policy resources remain fail-closed per workload, but do not make the whole gateway
	// unavailable indefinitely.
	readyStat = "policy_store.initial_sync_ready"

	readyStatFilter = `^policy_store\.initial_sync_ready$`

	// Kubelet's own probe timeout for the gateway is 1s, which is the effective
	// budget regardless of what we set here.
	scrapeTimeout = time.Second
)

// Probe reports the gateway policy store's sync state as a readiness signal.
type Probe struct {
	localHostAddr string
	adminPort     uint16

	// Readiness is a startup gate. Once the initial subscriptions have converged,
	// later policy changes are handled per workload and must not drain the gateway.
	ready bool
}

// New builds a policy store readiness probe.
func New(localHostAddr string, adminPort uint16) *Probe {
	return &Probe{
		localHostAddr: localHostAddr,
		adminPort:     adminPort,
	}
}

// Check implements ready.Prober.
func (p *Probe) Check() error {
	if p.ready {
		return nil
	}

	value, err := p.scrape()
	if err == nil && value == 1 {
		p.ready = true
		return nil
	}

	if err != nil {
		return err
	}
	return fmt.Errorf("gateway policy store has not synced (%s=%d)", readyStat, value)
}

// scrape reads readyStat from the Envoy admin endpoint.
func (p *Probe) scrape() (uint64, error) {
	host := p.localHostAddr
	if host == "" {
		host = "localhost"
	}
	// The filter is interpolated raw, matching status/util.GetReadinessStats; the
	// Envoy admin endpoint accepts the regex unescaped.
	statsURL := fmt.Sprintf("http://%s/stats?usedonly&filter=%s",
		net.JoinHostPort(host, strconv.Itoa(int(p.adminPort))), readyStatFilter)
	body, err := http.DoHTTPGetWithTimeout(statsURL, scrapeTimeout)
	if err != nil {
		return 0, fmt.Errorf("failed to get %s: %v", readyStat, err)
	}
	return parseGauge(body.String())
}

// parseGauge matches the stat name exactly rather than by prefix.
func parseGauge(body string) (uint64, error) {
	for line := range strings.SplitSeq(body, "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found || strings.TrimSpace(name) != readyStat {
			continue
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed parsing %s from %q: %v", readyStat, line, err)
		}
		return parsed, nil
	}
	// Absent means the extension is not loaded, or the bootstrap's stats
	// inclusion list does not admit the policy_store scope. Both are
	// misconfigurations that must not read as synced.
	return 0, fmt.Errorf("%s is not present in Envoy stats", readyStat)
}
