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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/openkruise/agentio/bench/xds/loadapi"
	"github.com/openkruise/agentio/bench/xds/scenario/driver"
)

type runner struct {
	cfg                config
	id                 string
	out                string
	pods               []string
	urls               []string
	roundID            uint64
	scenario           driver.Driver
	resources          []driver.Resource
	rest               *rest.Config
	kube               kubernetes.Interface
	dynamic            dynamic.Interface
	http               *http.Client
	forwards           []forwardHandle
	namespaceAttempted bool
	result             result
}

func newRunner(cfg config) (*runner, error) {
	sc, err := newScenario(cfg.Scenario, cfg.ScenarioConfig)
	if err != nil {
		return nil, err
	}
	rc, k, d, err := clients(cfg)
	if err != nil {
		return nil, err
	}
	var suffix [3]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("ads-bench-%s-%x", time.Now().UTC().Format("0102-150405"), suffix)
	out := cfg.Output
	if out == "" {
		out = filepath.Join("out", "xds", id)
	}
	if err = os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		return nil, err
	}
	if err = os.Mkdir(out, 0755); err != nil {
		return nil, fmt.Errorf("output must be a fresh directory: %w", err)
	}
	r := &runner{cfg: cfg,
		id:       id,
		out:      out,
		rest:     rc,
		kube:     k,
		dynamic:  d,
		http:     &http.Client{Timeout: 30 * time.Second},
		scenario: sc,
		result:   result{RunID: id, Parameters: cfg, Stages: []stageResult{}, Rounds: []roundResult{}}}
	for i := 0; i < cfg.Pods; i++ {
		r.pods = append(r.pods, fmt.Sprintf("client-%d", i))
	}
	if err = r.save("parameters.json", cfg); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *runner) save(name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.out, name), append(data, '\n'), 0644)
}
func emit(value any) error { return json.NewEncoder(os.Stdout).Encode(value) }

func waitFor(parent context.Context, timeout time.Duration, fn func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		done, err := fn(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if err = sleep(ctx, 250*time.Millisecond); err != nil {
			return err
		}
	}
}
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (r *runner) request(ctx context.Context, url string, body, out any) (err error) {
	var reader io.Reader
	method := http.MethodGet
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return errors.Join(fmt.Errorf("%s: HTTP %d: %s", url, resp.StatusCode, data), readErr)
	}
	if out == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (r *runner) statuses(ctx context.Context, samples bool, expected int) ([]loadapi.Status, error) {
	path := "/status"
	if samples {
		path += "?samples=1"
	}
	statuses := make([]loadapi.Status, len(r.urls))
	group, ctx := errgroup.WithContext(ctx)
	for i, url := range r.urls {
		group.Go(func() error { return r.request(ctx, url+path, nil, &statuses[i]) })
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	ready := int64(0)
	for i, s := range statuses {
		if s.Failures != 0 {
			return nil, fmt.Errorf("%s: client failures: %v", r.pods[i], s.Errors)
		}
		ready += s.Ready
	}
	if expected >= 0 && ready != int64(expected) {
		return nil, fmt.Errorf("ready clients changed: %d, expected %d", ready, expected)
	}
	return statuses, nil
}

func (r *runner) metrics(ctx context.Context, label string) (values map[string]float64, err error) {
	values = map[string]float64{}
	if r.cfg.MetricsURL == "" {
		return values, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.cfg.MetricsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(r.out, label+".prom"), raw, 0644); err != nil {
		return nil, err
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		end := strings.IndexAny(line, " \t")
		if labels := strings.LastIndex(line, "}"); labels >= 0 {
			end = labels + 1
		}
		if end < 0 {
			continue
		}
		parts := strings.Fields(line[end:])
		if len(parts) == 0 {
			continue
		}
		value, err := strconv.ParseFloat(parts[0], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		values[strings.TrimSpace(line[:end])] = value
	}
	return values, nil
}

func (r *runner) clockOffsets(ctx context.Context) ([]calibration, error) {
	clocks := make([]calibration, len(r.urls))
	for i, url := range r.urls {
		for attempt := range 3 {
			start := time.Now()
			var status loadapi.Status
			if err := r.request(ctx, url+"/status", nil, &status); err != nil {
				return nil, err
			}
			end := time.Now()
			if status.NowNS <= 0 {
				return nil, errors.New("missing client clock")
			}
			c := calibration{
				RTTNS:    end.Sub(start).Nanoseconds(),
				OffsetNS: status.NowNS - (start.UnixNano()+end.UnixNano())/2,
			}
			if attempt == 0 || c.RTTNS < clocks[i].RTTNS {
				clocks[i] = c
			}
		}
	}
	return clocks, nil
}

//nolint:gocyclo,funlen // Keep the ordered measurement steps together so timing boundaries remain visible.
func (r *runner) update(ctx context.Context, n int, parameters json.RawMessage) error {
	r.roundID++
	expected := loadapi.Round{ID: r.roundID, Parameters: parameters}
	group, armCtx := errgroup.WithContext(ctx)
	for _, url := range r.urls {
		group.Go(func() error {
			var got loadapi.Round
			if err := r.request(armCtx, url+"/round", expected, &got); err != nil {
				return err
			}
			if got.ID != expected.ID || !bytes.Equal(got.Parameters, expected.Parameters) {
				return errors.New("client armed an unexpected round")
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return err
	}
	clocks, err := r.clockOffsets(ctx)
	if err != nil {
		return err
	}
	before, err := r.statuses(ctx, false, n)
	if err != nil {
		return err
	}
	label := fmt.Sprintf("%d-%d", n, r.roundID)
	m0, err := r.metrics(ctx, label+"-before")
	if err != nil {
		return err
	}
	if r.cfg.MetricsURL != "" {
		if _, ok := m0["agentio_xds_acks_total"]; !ok {
			return errors.New("metrics missing agentio_xds_acks_total")
		}
	}
	start := time.Now()
	if err = r.scenario.Trigger(ctx, r.environment(), parameters); err != nil {
		return err
	}
	if err = waitFor(ctx, r.cfg.timeout(), func(ctx context.Context) (bool, error) {
		s, err := r.statuses(ctx, false, n)
		if err != nil {
			return false, err
		}
		received := 0
		for _, v := range s {
			received += v.Received
		}
		return received == n, nil
	}); err != nil {
		return fmt.Errorf("wait for round %d: %w", r.roundID, err)
	}
	observed := float64(time.Since(start)) / float64(time.Millisecond)
	var serverObserved *float64
	if r.cfg.MetricsURL != "" {
		if err = waitFor(ctx, r.cfg.timeout(), func(ctx context.Context) (bool, error) {
			m, err := r.metrics(ctx, label+"-after")
			if err != nil {
				return false, err
			}
			ack, ok := m["agentio_xds_acks_total"]
			if !ok || ack < m0["agentio_xds_acks_total"] {
				return false, errors.New("server ACK counter missing/reset during round")
			}
			return ack-m0["agentio_xds_acks_total"] >= float64(n), nil
		}); err != nil {
			return err
		}
		elapsed := float64(time.Since(start)) / float64(time.Millisecond)
		serverObserved = &elapsed
	}
	after, err := r.statuses(ctx, true, n)
	if err != nil {
		return err
	}
	samples, err := collectSamples(n, r.pods, after, clocks)
	if err != nil {
		return err
	}
	checks, err := r.scenario.Check(parameters, before, after)
	if err != nil {
		return err
	}
	receive := make([]float64, len(samples))
	ack := make([]float64, len(samples))
	for i, s := range samples {
		receive[i] = float64(s.ReceiveCorrectedNS-start.UnixNano()) / 1e6
		ack[i] = float64(s.AckCorrectedNS-start.UnixNano()) / 1e6
	}
	uncertainty := float64(0)
	for _, c := range clocks {
		uncertainty = max(uncertainty, float64(c.RTTNS)/2e6)
	}
	record := roundResult{Connections: n,
		RoundID:              r.roundID,
		Parameters:           parameters,
		Checks:               checks,
		StartNS:              start.UnixNano(),
		SampleCount:          len(samples),
		ReceiveMS:            quantiles(receive),
		AckSubmitMS:          quantiles(ack),
		AllClientsObservedMS: observed,
		ServerACKObservedMS:  serverObserved,
		ClockCalibration:     clocks,
		ClockUncertaintyMS:   uncertainty}
	if r.cfg.RawSamples {
		if err = r.save("samples-"+label+".json", samples); err != nil {
			return err
		}
	}
	r.result.Rounds = append(r.result.Rounds, record)
	if err = r.save("results.json", r.result); err != nil {
		return err
	}
	return emit(record)
}

func (r *runner) run(ctx context.Context) error {
	if err := r.setup(ctx); err != nil {
		return err
	}
	if err := sleep(ctx, seconds(r.cfg.SetupWaitSeconds)); err != nil {
		return err
	}
	previous := 0
	for _, n := range r.cfg.Stages {
		start := time.Now()
		for i, url := range r.urls {
			path := fmt.Sprintf("/scale?n=%d&rate=%g", targetFor(n, r.cfg.Pods, i), r.cfg.Rate/float64(r.cfg.Pods))
			if err := r.request(ctx, url+path, struct{}{}, nil); err != nil {
				return err
			}
		}
		var statuses []loadapi.Status
		var lastPrint time.Time
		err := waitFor(
			ctx,
			r.cfg.timeout()+seconds(float64(n-previous)/r.cfg.Rate),
			func(ctx context.Context) (bool, error) {
				var err error
				statuses, err = r.statuses(ctx, false, -1)
				if err != nil {
					return false, err
				}
				ready := int64(0)
				for _, s := range statuses {
					ready += s.Ready
				}
				if time.Since(lastPrint) >= 10*time.Second {
					lastPrint = time.Now()
					return ready == int64(n), emit(map[string]any{"target": n, "ready": ready})
				}
				return ready == int64(n), nil
			},
		)
		if err != nil {
			return fmt.Errorf("ramp to %d: %w", n, err)
		}
		elapsed := time.Since(start).Seconds()
		metrics, err := r.metrics(ctx, strconv.Itoa(n)+"-ready")
		if err != nil {
			return err
		}
		r.result.Stages = append(
			r.result.Stages,
			stageResult{Connections: n, RampSeconds: elapsed, Clients: statuses, Metrics: metrics},
		)
		if err = r.snapshot(ctx, strconv.Itoa(n)+"-ready"); err != nil {
			return err
		}
		if err = r.save("results.json", r.result); err != nil {
			return err
		}
		rounds, err := r.scenario.Rounds(r.cfg.Rounds)
		if err != nil {
			return err
		}
		for _, parameters := range rounds {
			if err = r.update(ctx, n, parameters); err != nil {
				return err
			}
		}
		previous = n
	}
	if err := r.hold(ctx, previous); err != nil {
		return err
	}
	if err := r.snapshot(ctx, "final"); err != nil {
		return err
	}
	r.result.Complete = true
	return nil
}

func (r *runner) hold(ctx context.Context, connections int) error {
	end := time.Now().Add(seconds(r.cfg.HoldSeconds))
	for time.Now().Before(end) {
		if _, err := r.statuses(ctx, false, connections); err != nil {
			return err
		}
		if err := sleep(ctx, min(time.Second, time.Until(end))); err != nil {
			return err
		}
	}
	_, err := r.statuses(ctx, false, connections)
	return err
}

func (r *runner) execute(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			r.result.Error = err.Error()
			if r.namespaceAttempted {
				diagCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				pods, diagErr := r.kube.CoreV1().Pods(r.id).List(diagCtx, metav1.ListOptions{})
				cancel()
				if diagErr == nil {
					diagErr = r.save("failure-pods.json", pods)
				}
				if diagErr != nil {
					r.result.DiagnosticError = diagErr.Error()
				}
			}
		}
		// Cleanup must work after Ctrl-C or the operation's context deadline.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		cleanupErr := r.cleanup(cleanupCtx)
		cancel()
		r.result.Cleanup = cleanupResult{
			KeptResources:          r.cfg.KeepResources,
			Errors:                 []string{},
			NamespaceDeletionAsync: true,
		}
		if cleanupErr != nil {
			r.result.Cleanup.Errors = append(r.result.Cleanup.Errors, cleanupErr.Error())
			err = errors.Join(err, fmt.Errorf("cleanup: %w", cleanupErr))
		}
		prefix := []string{"kubectl", "--context", r.cfg.Context}
		if r.cfg.Kubeconfig != "" {
			prefix = append(prefix, "--kubeconfig", r.cfg.Kubeconfig)
		}
		saveErr := r.save(
			"cleanup.json",
			map[string]any{
				"kubectl_prefix":              prefix,
				"namespace":                   r.id,
				"resources":                   r.resources,
				"kept_resources":              r.cfg.KeepResources,
				"errors":                      r.result.Cleanup.Errors,
				"namespace_deletion_is_async": true,
			},
		)
		err = errors.Join(err, saveErr, r.save("results.json", r.result))
		fmt.Println("Results:", r.out)
	}()
	return r.run(ctx)
}
