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
	"fmt"
	"os"
	"strconv"
	"strings"
)

type proc struct {
	CPU float64
	RSS uint64
}

func sample(pid int, ticks float64) (proc, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return proc{}, err
	}
	return parseSample(string(raw), ticks, uint64(os.Getpagesize()))
}

func parseSample(raw string, ticks float64, pageSize uint64) (proc, error) {
	end := strings.LastIndex(raw, ")")
	if end < 0 {
		return proc{}, fmt.Errorf("invalid proc stat command")
	}
	fields := strings.Fields(raw[end+1:])
	if len(fields) < 22 || ticks <= 0 {
		return proc{}, fmt.Errorf("invalid proc stat fields or clock frequency")
	}
	values := make([]uint64, 3)
	for j, i := range []int{11, 12, 21} {
		n, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return proc{}, err
		}
		values[j] = n
	}
	return proc{CPU: float64(values[0]+values[1]) / ticks, RSS: values[2] * pageSize}, nil
}

func samples(pids []int, ticks float64) ([]proc, error) {
	values := make([]proc, len(pids))
	for i, pid := range pids {
		value, err := sample(pid, ticks)
		if err != nil {
			return nil, err
		}
		values[i] = value
	}
	return values, nil
}
