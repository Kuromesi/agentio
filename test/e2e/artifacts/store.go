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

package artifacts

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Store struct {
	root string
	mu   sync.Mutex
}

type Writer interface {
	Path(parts ...string) string
	Writer(parts ...string) (io.WriteCloser, error)
	WriteJSON(path string, value any) error
	Append(path string, data []byte) error
}

func New(root, runID string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("artifact root is required")
	}
	if err := validatePart(runID); err != nil {
		return nil, fmt.Errorf("invalid run ID: %w", err)
	}
	runRoot := filepath.Join(root, runID)
	if err := os.MkdirAll(runRoot, 0o750); err != nil {
		return nil, fmt.Errorf("create artifact root %q: %w", runRoot, err)
	}
	abs, err := filepath.Abs(runRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve artifact root %q: %w", runRoot, err)
	}
	return &Store{root: abs}, nil
}

func (s *Store) Root() string { return s.root }

func (s *Store) Path(parts ...string) string {
	all := append([]string{s.root}, parts...)
	return filepath.Join(all...)
}

func (s *Store) Writer(parts ...string) (io.WriteCloser, error) {
	path, err := s.resolve(parts...)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create artifact directory for %q: %w", path, err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open artifact %q: %w", path, err)
	}
	return file, nil
}

func (s *Store) WriteJSON(path string, value any) error {
	target, err := s.resolve(path)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal artifact %q: %w", path, err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return fmt.Errorf("create artifact directory for %q: %w", target, err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".*")
	if err != nil {
		return fmt.Errorf("create temporary artifact for %q: %w", target, err)
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary artifact %q: %w", temporaryName, err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write temporary artifact %q: %w", temporaryName, err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary artifact %q: %w", temporaryName, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary artifact %q: %w", temporaryName, err)
	}
	if err := os.Rename(temporaryName, target); err != nil {
		return fmt.Errorf("commit artifact %q: %w", target, err)
	}
	committed = true
	return nil
}

func (s *Store) Append(path string, data []byte) error {
	target, err := s.resolve(path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return fmt.Errorf("create artifact directory for %q: %w", target, err)
	}
	file, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open append artifact %q: %w", target, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("append artifact %q: %w", target, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close append artifact %q: %w", target, err)
	}
	return nil
}

func (s *Store) resolve(parts ...string) (string, error) {
	if len(parts) == 0 {
		return "", errors.New("artifact path is required")
	}
	for _, part := range parts {
		if err := validatePart(part); err != nil {
			return "", err
		}
	}
	target := s.Path(parts...)
	relative, err := filepath.Rel(s.root, target)
	if err != nil {
		return "", fmt.Errorf("resolve artifact path %q: %w", target, err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact path %q escapes run root", target)
	}
	return target, nil
}

func validatePart(part string) error {
	if strings.TrimSpace(part) == "" {
		return errors.New("artifact path contains an empty part")
	}
	if filepath.IsAbs(part) {
		return fmt.Errorf("artifact path %q is absolute", part)
	}
	clean := filepath.Clean(part)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("artifact path %q escapes run root", part)
	}
	return nil
}
