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

package e2e

import (
	"sync"

	"github.com/openkruise/agentio/test/e2e/kube"
)

type EnvironmentState struct {
	mu sync.RWMutex

	RunID       string                          `json:"runId"`
	ClusterName string                          `json:"clusterName"`
	Context     string                          `json:"context"`
	Owned       bool                            `json:"owned"`
	Resources   []kube.ResourceRecord           `json:"resources"`
	Components  map[string]ComponentFingerprint `json:"components"`
	Retain      RetainPolicy                    `json:"retain"`
	FinalStatus string                          `json:"finalStatus"`
	ExitCode    int                             `json:"exitCode"`
}

type ComponentFingerprint struct {
	Fingerprint string            `json:"fingerprint"`
	Images      map[string]string `json:"images,omitempty"`
}

type StateSnapshot struct {
	RunID       string                          `json:"runId"`
	ClusterName string                          `json:"clusterName"`
	Context     string                          `json:"context"`
	Owned       bool                            `json:"owned"`
	Resources   []kube.ResourceRecord           `json:"resources"`
	Components  map[string]ComponentFingerprint `json:"components"`
	Retain      RetainPolicy                    `json:"retain"`
	FinalStatus string                          `json:"finalStatus"`
	ExitCode    int                             `json:"exitCode"`
}

func newEnvironmentState(runID string, config Config) *EnvironmentState {
	return &EnvironmentState{
		RunID:      runID,
		Components: make(map[string]ComponentFingerprint),
		Retain:     config.Lifecycle.Retain,
	}
}

func (s *EnvironmentState) RecordComponent(name, fingerprint string, images map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Components[name] = ComponentFingerprint{Fingerprint: fingerprint, Images: cloneStrings(images)}
}

func (s *EnvironmentState) setCluster(name, contextName string, owned bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ClusterName = name
	s.Context = contextName
	s.Owned = owned
}

func (s *EnvironmentState) finish(resources []kube.ResourceRecord, status string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Resources = append([]kube.ResourceRecord(nil), resources...)
	s.FinalStatus = status
	s.ExitCode = code
}

func (s *EnvironmentState) Snapshot() StateSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := StateSnapshot{
		RunID:       s.RunID,
		ClusterName: s.ClusterName,
		Context:     s.Context,
		Owned:       s.Owned,
		Resources:   append([]kube.ResourceRecord(nil), s.Resources...),
		Components:  make(map[string]ComponentFingerprint, len(s.Components)),
		Retain:      s.Retain,
		FinalStatus: s.FinalStatus,
		ExitCode:    s.ExitCode,
	}
	for name, component := range s.Components {
		component.Images = cloneStrings(component.Images)
		result.Components[name] = component
	}
	return result
}

func cloneStrings(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
