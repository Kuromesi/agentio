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
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

var ErrOwnershipMismatch = errors.New("resource ownership mismatch")

func (c *Client) DeleteOwned(ctx context.Context, record ResourceRecord) error {
	resource := c.resource(record.GVR, record.Namespace, record.Namespaced || record.Namespace != "")
	live, err := resource.Get(ctx, record.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("get owned %s %s/%s: %w", record.GVR.Resource, record.Namespace, record.Name, err)
	}
	if err := c.validateOwnership(live, record); err != nil {
		return fmt.Errorf("delete %s %s/%s: %w", record.GVR.Resource, record.Namespace, record.Name, err)
	}
	uid := record.UID
	if err := resource.Delete(ctx, record.Name, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{UID: &uid},
	}); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete %s %s/%s: %w", record.GVR.Resource, record.Namespace, record.Name, err)
	}
	return waitDeleted(ctx, resource, record.Name)
}

func (c *Client) validateOwnership(live *unstructured.Unstructured, record ResourceRecord) error {
	if record.RunID != c.runID {
		return fmt.Errorf("%w: ledger run ID %q does not match current run %q", ErrOwnershipMismatch, record.RunID, c.runID)
	}
	if live.GetUID() != record.UID {
		return fmt.Errorf("%w: live UID %q does not match ledger UID %q", ErrOwnershipMismatch, live.GetUID(), record.UID)
	}
	if live.GetLabels()[RunLabel] != record.RunID {
		return fmt.Errorf("%w: live run label %q does not match ledger run ID %q", ErrOwnershipMismatch, live.GetLabels()[RunLabel], record.RunID)
	}
	return nil
}

func waitDeleted(ctx context.Context, resource dynamic.ResourceInterface, name string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := resource.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
