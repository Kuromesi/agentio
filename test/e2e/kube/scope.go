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

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ResourceScope records the resources created by one short-lived scenario.
// The suite ledger remains the authoritative run-wide ownership record.
type ResourceScope struct {
	client  *Client
	records []ResourceRecord
}

func NewResourceScope(client *Client) *ResourceScope {
	return &ResourceScope{client: client}
}

func (s *ResourceScope) Apply(ctx context.Context, object *unstructured.Unstructured, mode Mode) (ResourceRecord, error) {
	return s.apply(ctx, "", object, mode)
}

func (s *ResourceScope) ApplyInNamespace(ctx context.Context, namespace string, object *unstructured.Unstructured, mode Mode) (ResourceRecord, error) {
	return s.apply(ctx, namespace, object, mode)
}

func (s *ResourceScope) apply(ctx context.Context, namespace string, object *unstructured.Unstructured, mode Mode) (ResourceRecord, error) {
	if s == nil || s.client == nil {
		return ResourceRecord{}, errors.New("resource scope requires a Kubernetes client")
	}
	record, err := s.client.ApplyInNamespace(ctx, namespace, object, mode)
	if err != nil {
		return ResourceRecord{}, err
	}
	s.records = append(s.records, record)
	return record, nil
}

// Delete removes one scope record using the run and live UID ownership checks.
// The record remains in the scope so DeleteReverse stays idempotent.
func (s *ResourceScope) Delete(ctx context.Context, record ResourceRecord) error {
	if s == nil || s.client == nil {
		return errors.New("resource scope requires a Kubernetes client")
	}
	return s.client.DeleteOwned(ctx, record)
}

func (s *ResourceScope) DeleteReverse(ctx context.Context) error {
	if s == nil || s.client == nil {
		return errors.New("resource scope requires a Kubernetes client")
	}
	var errs []error
	for index := len(s.records) - 1; index >= 0; index-- {
		if err := s.client.DeleteOwned(ctx, s.records[index]); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
