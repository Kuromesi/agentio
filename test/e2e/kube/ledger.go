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

package kube

import (
	"context"
	"errors"
	"sync"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

type ResourceRecord struct {
	GVR          schema.GroupVersionResource `json:"gvr"`
	Namespace    string                      `json:"namespace,omitempty"`
	Name         string                      `json:"name"`
	UID          types.UID                   `json:"uid"`
	RunID        string                      `json:"runId"`
	Labels       map[string]string           `json:"labels,omitempty"`
	ManifestHash string                      `json:"manifestHash"`
	Namespaced   bool                        `json:"namespaced"`
}

type Ledger struct {
	mu      sync.RWMutex
	records []ResourceRecord
	index   map[resourceKey]int
}

func NewLedger() *Ledger {
	return &Ledger{index: make(map[resourceKey]int)}
}

func (l *Ledger) Record(record ResourceRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.index == nil {
		l.index = make(map[resourceKey]int)
	}
	record.Labels = cloneLabels(record.Labels)
	key := keyFor(record.GVR, record.Namespace, record.Name)
	if index, found := l.index[key]; found {
		l.records[index] = record
		return
	}
	l.index[key] = len(l.records)
	l.records = append(l.records, record)
}

func (l *Ledger) Find(gvr schema.GroupVersionResource, namespace, name string) (ResourceRecord, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	index, found := l.index[keyFor(gvr, namespace, name)]
	if !found {
		return ResourceRecord{}, false
	}
	record := l.records[index]
	record.Labels = cloneLabels(record.Labels)
	return record, true
}

func (l *Ledger) Snapshot() []ResourceRecord {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]ResourceRecord, len(l.records))
	copy(result, l.records)
	for i := range result {
		result[i].Labels = cloneLabels(result[i].Labels)
	}
	return result
}

func (l *Ledger) DeleteReverse(ctx context.Context, client *Client) error {
	records := l.Snapshot()
	var errs []error
	for i := len(records) - 1; i >= 0; i-- {
		if err := client.DeleteOwned(ctx, records[i]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type resourceKey struct {
	group, version, resource, namespace, name string
}

func keyFor(gvr schema.GroupVersionResource, namespace, name string) resourceKey {
	return resourceKey{gvr.Group, gvr.Version, gvr.Resource, namespace, name}
}

func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		result[key] = value
	}
	return result
}
