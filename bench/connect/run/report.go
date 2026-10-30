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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
)

type measurement struct {
	Event           string  `json:"event"`
	Mode            string  `json:"mode"`
	Streams         int     `json:"streams"`
	Direction       string  `json:"direction"`
	Limit           int     `json:"concurrency_limit"`
	Errors          int     `json:"errors"`
	Throughput      float64 `json:"mib_per_s"`
	CPU             float64 `json:"envoy_cpu_cores"`
	RSS             float64 `json:"envoy_rss_peak_mib"`
	ResidentBuckets int     `json:"resident_buckets"`
	ResidentMode    string  `json:"resident_mode"`
}

func analyze(path string, w io.Writer) (result error) {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	groups := map[string][]measurement{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var m measurement
		if err := json.Unmarshal(scanner.Bytes(), &m); err != nil {
			return err
		}
		if m.Event != "result" {
			continue
		}
		if m.Errors != 0 {
			return fmt.Errorf("measurement contains %d errors", m.Errors)
		}
		key := fmt.Sprintf("%s / %s / %d / %d", m.Mode, m.Direction, m.Streams, m.Limit)
		if m.ResidentMode != "" {
			key += fmt.Sprintf(" / %s:%d", m.ResidentMode, m.ResidentBuckets)
		}
		groups[key] = append(groups[key], m)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(groups) == 0 {
		return fmt.Errorf("no result rows")
	}
	if _, err := fmt.Fprintln(
		w,
		"| Mode / direction / streams / concurrency cap / background (if set) | Runs | MiB/s median [min, max] | Envoy cores median | RSS MiB median |\n| --- | ---: | ---: | ---: | ---: |",
	); err != nil {
		return err
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		rows := groups[key]
		rates, cpu, rss := make([]float64, len(rows)), make([]float64, len(rows)), make([]float64, len(rows))
		for i, m := range rows {
			rates[i] = m.Throughput
			cpu[i] = m.CPU
			rss[i] = m.RSS
		}
		slices.Sort(rates)
		slices.Sort(cpu)
		slices.Sort(rss)
		if _, err := fmt.Fprintf(
			w,
			"| %s | %d | %.2f [%.2f, %.2f] | %.3f | %.2f |\n",
			key,
			len(rows),
			median(rates),
			rates[0],
			rates[len(rates)-1],
			median(cpu),
			median(rss),
		); err != nil {
			return err
		}
	}
	return nil
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}
