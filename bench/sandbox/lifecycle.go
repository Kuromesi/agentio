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
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	securityapi "istio.io/api/security/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

// lifecycle checks identity retirement independently of expected churn failures.
func (r *runner) lifecycle(ctx context.Context) (any, error) {
	conn, roots, err := r.credentials(ctx)
	if err != nil {
		return nil, err
	}
	defer closeResource(conn)
	ca := securityapi.NewIstioCertificateServiceClient(conn)
	i := r.Offset
	oldPod, err := r.kube.CoreV1().Pods(r.namespace(i)).Get(ctx, resourceName(i), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	probe := func(cert tls.Certificate) error {
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return r.request(
			requestCtx,
			gatewayTLS(roots, cert, "spiffe://cluster.local/ns/"+r.System+"/sa/egress-gateway"),
			i,
		)
	}
	// A preceding bulk recreation can still be converging through the controllers.
	// Measure baseline readiness separately from retirement of an active identity.
	initialStarted := time.Now()
	initialAttempts := 0
	var old tls.Certificate
	var last error
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 20*time.Second, true,
		func(ctx context.Context) (bool, error) {
			initialAttempts++
			if len(old.Certificate) == 0 {
				old, last = r.issue(ctx, ca, i)
				if last != nil {
					return false, nil
				}
			}
			last = probe(old)
			return last == nil, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("before deletion: %w (last %w)", err, last)
	}
	initialReadySeconds := time.Since(initialStarted).Seconds()
	started := time.Now()
	if err := r.deletePair(ctx, i); err != nil {
		return nil, err
	}
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 20*time.Second, true,
		func(context.Context) (bool, error) {
			last = probe(old)
			var rejection connectError
			return errors.As(last, &rejection) && rejection.status == 403, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("deleted identity did not become denied: %w (last %w)", err, last)
	}
	rejectedAfter := time.Since(started).Seconds()
	if err := r.createPair(ctx, i); err != nil {
		return nil, err
	}
	freshPod, err := r.kube.CoreV1().Pods(r.namespace(i)).Get(ctx, resourceName(i), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if oldPod.UID == freshPod.UID {
		return nil, fmt.Errorf("recreation reused Pod UID")
	}
	var fresh tls.Certificate
	err = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 20*time.Second, true,
		func(ctx context.Context) (bool, error) {
			fresh, last = r.issue(ctx, ca, i)
			return last == nil, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("new identity signing: %w (last %w)", err, last)
	}
	err = wait.PollUntilContextTimeout(ctx, 20*time.Millisecond, 20*time.Second, true,
		func(context.Context) (bool, error) {
			last = probe(fresh)
			return last == nil, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("new identity never recovered: %w (last %w)", err, last)
	}
	for range 20 {
		var rejection connectError
		if err := probe(old); !errors.As(err, &rejection) || rejection.status != 403 {
			return nil, fmt.Errorf("retired identity after recreation: %w", err)
		}
	}
	return map[string]any{
		"initial_ready_seconds":                    initialReadySeconds,
		"initial_ready_attempts":                   initialAttempts,
		"old_uid":                                  oldPod.UID,
		"new_uid":                                  freshPod.UID,
		"deletion_to_denied_seconds":               rejectedAfter,
		"total_recovery_seconds":                   time.Since(started).Seconds(),
		"old_certificate_denials_after_recreation": 20,
	}, nil
}
