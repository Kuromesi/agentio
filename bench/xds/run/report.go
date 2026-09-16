// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/openkruise/agentio/bench/xds/loadapi"
)

type calibration struct {
	RTTNS    int64 `json:"rtt_ns"`
	OffsetNS int64 `json:"offset_ns"`
}
type recordedSample struct {
	loadapi.Sample
	Pod                string `json:"pod"`
	ReceiveCorrectedNS int64  `json:"receive_corrected_ns"`
	AckCorrectedNS     int64  `json:"ack_corrected_ns"`
}
type stageResult struct {
	Connections int                `json:"connections"`
	RampSeconds float64            `json:"ramp_seconds"`
	Clients     []loadapi.Status   `json:"clients"`
	Metrics     map[string]float64 `json:"metrics"`
}
type roundResult struct {
	Connections          int                `json:"connections"`
	RoundID              uint64             `json:"round_id"`
	Parameters           json.RawMessage    `json:"parameters"`
	Checks               map[string]any     `json:"checks"`
	StartNS              int64              `json:"start_ns"`
	SampleCount          int                `json:"sample_count"`
	ReceiveMS            map[string]float64 `json:"receive_ms"`
	AckSubmitMS          map[string]float64 `json:"ack_submit_ms"`
	AllClientsObservedMS float64            `json:"all_clients_observed_ms"`
	ServerACKObservedMS  *float64           `json:"server_ack_observed_ms"`
	ClockCalibration     []calibration      `json:"clock_calibration"`
	ClockUncertaintyMS   float64            `json:"clock_uncertainty_ms"`
	Failures             int64              `json:"failures"`
}
type cleanupResult struct {
	KeptResources          bool     `json:"kept_resources"`
	Errors                 []string `json:"errors"`
	NamespaceDeletionAsync bool     `json:"namespace_deletion_is_async"`
}
type result struct {
	RunID           string        `json:"run_id"`
	Parameters      config        `json:"parameters"`
	Stages          []stageResult `json:"stages"`
	Rounds          []roundResult `json:"rounds"`
	Complete        bool          `json:"complete"`
	Error           string        `json:"error,omitempty"`
	DiagnosticError string        `json:"diagnostic_error,omitempty"`
	Cleanup         cleanupResult `json:"cleanup"`
}

func quantiles(values []float64) map[string]float64 {
	slices.Sort(values)
	out := map[string]float64{}
	for name, q := range map[string]float64{"min": 0, "p50": .5, "p95": .95, "p99": .99, "max": 1} {
		out[name] = values[int(float64(len(values)-1)*q)]
	}
	return out
}

func collectSamples(n int, pods []string, statuses []loadapi.Status, clocks []calibration) ([]recordedSample, error) {
	if len(pods) == 0 || len(statuses) != len(pods) || len(clocks) != len(pods) {
		return nil, fmt.Errorf("missing Pod statuses or clock calibrations")
	}
	out := make([]recordedSample, 0, n)
	for i, s := range statuses {
		expected := targetFor(n, len(pods), i)
		if s.Failures != 0 || s.Target != expected || s.Ready != int64(expected) || len(s.Samples) != expected {
			return nil, fmt.Errorf("%s: incomplete/unhealthy sample set", pods[i])
		}
		seen := make(map[int]bool, len(s.Samples))
		for _, sample := range s.Samples {
			if sample.ID < 0 || sample.ID >= expected || seen[sample.ID] {
				return nil, fmt.Errorf("%s: duplicate/out-of-range client ID %d", pods[i], sample.ID)
			}
			seen[sample.ID] = true
			if sample.Bytes < 0 || sample.ReceiveNS <= 0 || sample.AckNS < sample.ReceiveNS {
				return nil, fmt.Errorf("%s: invalid sample", pods[i])
			}
			out = append(out, recordedSample{Sample: sample, Pod: pods[i], ReceiveCorrectedNS: sample.ReceiveNS - clocks[i].OffsetNS, AckCorrectedNS: sample.AckNS - clocks[i].OffsetNS})
		}
	}
	if len(out) != n {
		return nil, fmt.Errorf("sample count %d, expected %d", len(out), n)
	}
	return out, nil
}
