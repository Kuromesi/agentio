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

package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/openkruise/agentio/test/e2e/artifacts"
)

const defaultMaxOutputBytes = 4 << 20

type Request struct {
	Name      string
	Args      []string
	Dir       string
	Env       []string
	Sensitive []string
	Artifact  string
}

type Result struct {
	StartedAt time.Time     `json:"startedAt"`
	Duration  time.Duration `json:"duration"`
	ExitCode  int           `json:"exitCode"`
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
}

type Runner struct {
	Artifacts      *artifacts.Store
	Redactor       *Redactor
	MaxOutputBytes int
}

type Interface interface {
	Run(context.Context, Request) (Result, error)
}

type commandRecord struct {
	Name      string        `json:"name"`
	Args      []string      `json:"args"`
	Dir       string        `json:"dir,omitempty"`
	StartedAt time.Time     `json:"startedAt"`
	Duration  time.Duration `json:"duration"`
	ExitCode  int           `json:"exitCode"`
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
	Error     string        `json:"error,omitempty"`
}

func (r Runner) Run(ctx context.Context, req Request) (Result, error) {
	if strings.TrimSpace(req.Name) == "" {
		return Result{}, errors.New("command name is required")
	}
	redactor := r.Redactor
	if redactor == nil {
		redactor = NewRedactor(nil)
	}
	redactor = redactor.With(req.Sensitive)
	maxBytes := r.MaxOutputBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxOutputBytes
	}

	stdout := &limitedBuffer{limit: maxBytes}
	stderr := &limitedBuffer{limit: maxBytes}
	cmd := exec.Command(req.Name, req.Args...)
	cmd.Dir = req.Dir
	if req.Env != nil {
		cmd.Env = append([]string(nil), req.Env...)
	} else {
		cmd.Env = os.Environ()
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	configureProcess(cmd)

	result := Result{StartedAt: time.Now().UTC(), ExitCode: -1}
	if err := cmd.Start(); err != nil {
		result.Duration = time.Since(result.StartedAt)
		runErr := fmt.Errorf("start command %q: %w", req.Name, err)
		r.record(req, result, runErr, redactor)
		return result, runErr
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()

	var waitErr error
	var runErr error
	select {
	case waitErr = <-wait:
	case <-ctx.Done():
		terminateProcessGroup(cmd.Process.Pid)
		timer := time.NewTimer(2 * time.Second)
		select {
		case waitErr = <-wait:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			killProcessGroup(cmd.Process.Pid)
			waitErr = <-wait
		}
		runErr = fmt.Errorf("run command %q: %w", req.Name, ctx.Err())
	}
	result.Duration = time.Since(result.StartedAt)
	result.ExitCode = exitCode(cmd.ProcessState)
	result.Stdout = redactor.Redact(stdout.String())
	result.Stderr = redactor.Redact(stderr.String())
	if runErr == nil && waitErr != nil {
		runErr = fmt.Errorf("run command %q: %w", req.Name, waitErr)
	}
	if err := r.record(req, result, runErr, redactor); err != nil && runErr == nil {
		runErr = err
	}
	return result, runErr
}

func (r *Runner) record(req Request, result Result, runErr error, redactor *Redactor) error {
	if r.Artifacts == nil {
		return nil
	}
	record := commandRecord{
		Name:      redactor.Redact(req.Name),
		Args:      make([]string, len(req.Args)),
		Dir:       redactor.Redact(req.Dir),
		StartedAt: result.StartedAt,
		Duration:  result.Duration,
		ExitCode:  result.ExitCode,
		Stdout:    result.Stdout,
		Stderr:    result.Stderr,
	}
	for i, arg := range req.Args {
		record.Args[i] = redactor.Redact(arg)
	}
	if runErr != nil {
		record.Error = redactor.Redact(runErr.Error())
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(record); err != nil {
		return fmt.Errorf("marshal command record: %w", err)
	}
	path := "commands.jsonl"
	if req.Artifact != "" {
		path = filepath.Join(req.Artifact, path)
	}
	if err := r.Artifacts.Append(path, encoded.Bytes()); err != nil {
		return fmt.Errorf("record command: %w", err)
	}
	return nil
}

type Redactor struct {
	secrets []string
}

func NewRedactor(secrets []string) *Redactor {
	r := &Redactor{}
	return r.With(secrets)
}

func (r *Redactor) With(secrets []string) *Redactor {
	combined := append([]string(nil), r.secrets...)
	for _, secret := range secrets {
		if secret != "" {
			combined = append(combined, secret)
		}
	}
	return &Redactor{secrets: combined}
}

func (r *Redactor) Redact(value string) string {
	for _, secret := range r.secrets {
		value = strings.ReplaceAll(value, secret, "<redacted>")
	}
	return value
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := b.limit - b.Len()
	if remaining > 0 {
		if len(data) > remaining {
			data = data[:remaining]
		}
		_, _ = b.Buffer.Write(data)
	}
	return original, nil
}
