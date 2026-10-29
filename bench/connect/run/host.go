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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func physicalCPUs() ([]int, error) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil, err
	}
	var allowed string
	for line := range strings.SplitSeq(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "Cpus_allowed_list:"); ok {
			allowed = strings.TrimSpace(value)
		}
	}
	cpus, err := parseCPUs(allowed)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(cpus, func(a, b int) int { return b - a })
	seen := map[string]bool{}
	var selected []int
	for _, cpu := range cpus {
		topology := fmt.Sprintf("/sys/devices/system/cpu/cpu%d/topology/", cpu)
		pkg, err := os.ReadFile(topology + "physical_package_id")
		if err != nil {
			return nil, err
		}
		core, err := os.ReadFile(topology + "core_id")
		if err != nil {
			return nil, err
		}
		key := strings.TrimSpace(string(pkg)) + "/" + strings.TrimSpace(string(core))
		if !seen[key] {
			selected = append(selected, cpu)
			seen[key] = true
		}
		if len(selected) == 8 {
			return selected, nil
		}
	}
	return nil, fmt.Errorf("benchmark needs eight available physical cores; found %d", len(selected))
}

func parseCPUs(value string) ([]int, error) {
	var cpus []int
	for item := range strings.SplitSeq(value, ",") {
		start, end, rangeValue := strings.Cut(item, "-")
		first, err := strconv.Atoi(start)
		if err != nil || first < 0 {
			return nil, fmt.Errorf("invalid CPU range %q", item)
		}
		last := first
		if rangeValue {
			last, err = strconv.Atoi(end)
			if err != nil || last < first {
				return nil, fmt.Errorf("invalid CPU range %q", item)
			}
		}
		for i := first; i <= last; i++ {
			cpus = append(cpus, i)
		}
	}
	return cpus, nil
}

func pinnedCommand(ctx context.Context, cpus []int, binary string, args ...string) *exec.Cmd {
	values := make([]string, len(cpus))
	for i, cpu := range cpus {
		values[i] = strconv.Itoa(cpu)
	}
	return exec.CommandContext(ctx, "taskset", append([]string{"-c", strings.Join(values, ","), binary}, args...)...)
}

type process struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func startProcess(cpus []int, binary string, args []string, env []string, log io.Writer) (*process, error) {
	// Runner cancellation is handled by bounded graceful teardown, not immediate SIGKILL.
	cmd := pinnedCommand(context.Background(), cpus, binary, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &process{cmd: cmd, done: make(chan struct{})}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	return p, nil
}

func (p *process) ready(ctx context.Context, address string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		select {
		case <-p.done:
			return errors.Join(fmt.Errorf("process exited before %s was ready", address), p.err)
		default:
		}
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			return conn.Close()
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-p.done:
			timer.Stop()
			return errors.Join(fmt.Errorf("process exited before readiness"), p.err)
		case <-timer.C:
		}
	}
}

func (p *process) stop() error {
	select {
	case <-p.done:
		return p.err
	default:
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-p.done:
		return p.err
	case <-timer.C:
		killErr := p.cmd.Process.Kill()
		<-p.done
		return errors.Join(fmt.Errorf("process %d did not stop within 10s", p.cmd.Process.Pid), killErr, p.err)
	}
}
