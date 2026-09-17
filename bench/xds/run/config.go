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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/api/resource"
)

type intList []int

func (v *intList) String() string {
	parts := make([]string, len(*v))
	for i, n := range *v {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}
func (v *intList) Set(value string) error {
	var result []int
	for part := range strings.SplitSeq(value, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 {
			return errors.New("expected comma-separated positive integers")
		}
		result = append(result, n)
	}
	*v = result
	return nil
}

type config struct {
	Context          string          `json:"context"`
	Kubeconfig       string          `json:"kubeconfig"`
	Image            string          `json:"image"`
	ImagePullPolicy  string          `json:"image_pull_policy"`
	XDSAddress       string          `json:"xds_address"`
	ServerName       string          `json:"server_name"`
	CANamespace      string          `json:"ca_namespace"`
	CAConfigMap      string          `json:"ca_configmap"`
	CAKey            string          `json:"ca_key"`
	TokenAudience    string          `json:"token_audience"`
	Scenario         string          `json:"scenario"`
	ScenarioConfig   json.RawMessage `json:"scenario_config"`
	Pods             int             `json:"pods"`
	Stages           intList         `json:"stages"`
	Rate             float64         `json:"rate"`
	Rounds           int             `json:"rounds"`
	TimeoutSeconds   float64         `json:"timeout"`
	AckDelay         string          `json:"ack_delay"`
	HoldSeconds      float64         `json:"hold_seconds"`
	SetupWaitSeconds float64         `json:"setup_wait_seconds"`
	CPULimit         string          `json:"cpu_limit"`
	MemoryLimit      string          `json:"memory_limit"`
	MetricsURL       string          `json:"metrics_url"`
	ControlPlane     string          `json:"control_plane"`
	RawSamples       bool            `json:"raw_samples"`
	KeepResources    bool            `json:"keep_resources"`
	Output           string          `json:"output"`
}

func parseConfig(args []string, out io.Writer) (config, error) {
	c := config{Stages: intList{100, 1000}, ScenarioConfig: json.RawMessage(`{}`)}
	f := flag.NewFlagSet("xds-run", flag.ContinueOnError)
	f.SetOutput(out)
	f.StringVar(&c.Context, "context", "", "explicit Kubernetes context (required)")
	f.StringVar(&c.Kubeconfig, "kubeconfig", "", "kubeconfig path; default loading rules when omitted")
	f.StringVar(&c.Image, "image", "", "load application image (required)")
	f.StringVar(&c.ImagePullPolicy, "image-pull-policy", "IfNotPresent", "Never, IfNotPresent, or Always")
	f.StringVar(&c.XDSAddress, "xds-address", "", "xDS host:port reachable from Pods (required)")
	f.StringVar(&c.ServerName, "server-name", "", "TLS certificate DNS name (required)")
	f.StringVar(&c.CANamespace, "ca-namespace", "", "CA ConfigMap namespace (required)")
	f.StringVar(&c.CAConfigMap, "ca-configmap", "agentio-ca-root-cert", "CA ConfigMap name")
	f.StringVar(&c.CAKey, "ca-key", "root-cert.pem", "CA ConfigMap key")
	f.StringVar(&c.TokenAudience, "token-audience", "agentio-ca", "projected token audience")
	f.StringVar(&c.Scenario, "scenario", "trafficpolicy", "driver scenario: discovery or trafficpolicy")
	f.Func("scenario-config", "scenario-specific JSON options", func(v string) error {
		if !json.Valid([]byte(v)) {
			return errors.New("invalid scenario JSON")
		}
		c.ScenarioConfig = json.RawMessage(v)
		return nil
	})
	f.IntVar(&c.Pods, "pods", 4, "number of load Pods / identities")
	f.Var(&c.Stages, "stages", "increasing total connection counts, comma-separated")
	f.Float64Var(&c.Rate, "rate", 10, "total new connections/sec across load Pods")
	f.IntVar(&c.Rounds, "rounds", 3, "scenario repetitions per stage")
	f.Float64Var(&c.TimeoutSeconds, "timeout", 120, "ready/push timeout in seconds; ramp time added separately")
	f.StringVar(&c.AckDelay, "ack-delay", "0s", "Go duration: intentional per-response ACK delay")
	f.Float64Var(&c.HoldSeconds, "hold-seconds", 0, "hold final connection count while checking health")
	f.Float64Var(
		&c.SetupWaitSeconds,
		"setup-wait-seconds",
		0,
		"wait after resource setup before opening connections; not a readiness check",
	)
	f.StringVar(&c.CPULimit, "cpu-limit", "2", "load Pod CPU limit")
	f.StringVar(&c.MemoryLimit, "memory-limit", "3Gi", "load Pod memory limit")
	f.StringVar(&c.MetricsURL, "metrics-url", "", "optional control-plane Prometheus URL reachable by runner")
	f.StringVar(&c.ControlPlane, "control-plane", "", "optional namespace/deployment to snapshot, never modified")
	f.BoolVar(&c.RawSamples, "raw-samples", false, "save per-client sample files")
	f.BoolVar(&c.KeepResources, "keep-resources", false, "leave run resources for inspection")
	f.StringVar(&c.Output, "output", "", "fresh output directory (default out/xds/<run-id>)")
	if err := f.Parse(args); err != nil {
		return c, err
	}
	if f.NArg() != 0 {
		return c, fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	return c, c.validate()
}

func (c config) validate() error {
	for name, value := range map[string]string{"context": c.Context, "image": c.Image, "xds-address": c.XDSAddress, "server-name": c.ServerName, "ca-namespace": c.CANamespace, "ca-configmap": c.CAConfigMap, "ca-key": c.CAKey, "token-audience": c.TokenAudience} {
		if value == "" {
			return fmt.Errorf("--%s is required", name)
		}
	}
	if _, _, err := net.SplitHostPort(c.XDSAddress); err != nil {
		return fmt.Errorf("xds-address: %w", err)
	}
	if !slices.Contains([]string{"Never", "IfNotPresent", "Always"}, c.ImagePullPolicy) {
		return errors.New("invalid image-pull-policy")
	}
	if _, err := newScenario(c.Scenario, c.ScenarioConfig); err != nil {
		return err
	}
	if err := c.validateLoad(); err != nil {
		return err
	}
	for _, value := range []string{c.CPULimit, c.MemoryLimit} {
		q, err := resource.ParseQuantity(value)
		if err != nil || q.Sign() <= 0 {
			return errors.New("invalid Pod resource limit")
		}
	}
	if c.ControlPlane != "" {
		parts := strings.Split(c.ControlPlane, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return errors.New("control-plane must be namespace/deployment")
		}
	}
	return nil
}
func (c config) validateLoad() error {
	if c.Pods < 1 || len(c.Stages) == 0 {
		return errors.New("pods and stages must be positive")
	}
	previous := 0
	for _, n := range c.Stages {
		if n < c.Pods || n <= previous {
			return errors.New("stages must strictly increase and each be >= pods")
		}
		previous = n
	}
	if math.IsNaN(c.Rate) || math.IsInf(c.Rate, 0) || c.Rate/float64(c.Pods) < .001 || c.Rate/float64(c.Pods) > 100000 {
		return errors.New("per-Pod rate must be within 0.001..100000")
	}
	if !validSeconds(c.TimeoutSeconds) || c.TimeoutSeconds == 0 || !validSeconds(c.HoldSeconds) {
		return errors.New("invalid timeout/hold-seconds")
	}
	if !validSeconds(c.SetupWaitSeconds) {
		return errors.New("invalid setup-wait-seconds")
	}
	if float64(c.Stages[len(c.Stages)-1])/c.Rate+c.TimeoutSeconds > float64(math.MaxInt64)/float64(time.Second) {
		return errors.New("ramp duration overflows time.Duration")
	}
	if c.Rounds < 1 {
		return errors.New("rounds must be positive")
	}
	if delay, err := time.ParseDuration(c.AckDelay); err != nil || delay < 0 {
		return errors.New("invalid ack-delay")
	}
	return nil
}

func validSeconds(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v < float64(math.MaxInt64)/float64(time.Second)
}
func seconds(v float64) time.Duration   { return time.Duration(v * float64(time.Second)) }
func (c config) timeout() time.Duration { return seconds(c.TimeoutSeconds) }
func targetFor(total, pods, index int) int {
	n := total / pods
	if index < total%pods {
		n++
	}
	return n
}
