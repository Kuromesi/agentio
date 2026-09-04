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

package ca

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/openkruise/agentio/pkg/metrics"
	"github.com/openkruise/agentio/pkg/security/internal/casecret"
)

// publishRoot upserts the trust bundle ConfigMap, retrying on create/update conflicts.
func publishRoot(ctx context.Context, client kubernetes.Interface, namespace, name string, root []byte) error {
	const attempts = 5
	configMaps := client.CoreV1().ConfigMaps(namespace)
	var err error
	for range attempts {
		var current *corev1.ConfigMap
		current, err = configMaps.Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			_, err = configMaps.Create(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
				Data:       map[string]string{"root-cert.pem": string(root)},
			}, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(err) {
				// Another replica created it first; re-read and update instead.
				continue
			}
		case err == nil:
			if current.Data == nil {
				current.Data = map[string]string{}
			}
			if current.Data["root-cert.pem"] == string(root) {
				return nil
			}
			current.Data["root-cert.pem"] = string(root)
			_, err = configMaps.Update(ctx, current, metav1.UpdateOptions{})
			if apierrors.IsConflict(err) {
				continue
			}
		}
		if err == nil {
			return nil
		}
		break
	}
	return fmt.Errorf("publish root certificate ConfigMap %s/%s: %w", namespace, name, err)
}

func (a *Authority) runLeaderElection(ctx context.Context) {
	runLeaseElection(ctx, a.client.Kube(), a.options.Namespace, a.options.LeaseName, "CA",
		func(leaderCtx context.Context) {
			metrics.Default.SetCALeader(true)
			defer metrics.Default.SetCALeader(false)
			a.runCAMaintenance(leaderCtx)
		})
}

func (a *Authority) runCAMaintenance(ctx context.Context) {
	reconcile := func() {
		if err := a.reconcileCA(ctx, time.Now()); err != nil {
			log.Error("reconcile workload CA Secret as leader", "error", err)
		}
	}
	reconcile()
	ticker := time.NewTicker(a.options.RotationCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcile()
		}
	}
}

func (a *Authority) runServerCertificateMaintenance(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	var lastErrorLog time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Retry applying an already-observed valid KRT state if serving
			// certificate generation failed in its event callback. This reads no
			// Kubernetes API and does not poll the Secret.
			if a.caSingleton != nil {
				if state := a.caSingleton.Get(); state != nil {
					if err := a.installCAState(*state); err != nil && time.Since(lastErrorLog) >= 30*time.Second {
						log.Error("install workload CA state", "error", err)
						lastErrorLog = time.Now()
					}
				}
			}
			if _, err := a.renewServerCertificate(time.Now()); err != nil &&
				time.Since(lastErrorLog) >= 30*time.Second {
				log.Error("renew xDS server certificate", "error", err)
				lastErrorLog = time.Now()
			}
		}
	}
}

// renewServerCertificate re-issues the xDS serving certificate once it is within
// LeafRenewBefore of expiry, reporting whether it issued a new one.
func (a *Authority) renewServerCertificate(now time.Time) (bool, error) {
	a.mu.RLock()
	leaf := a.serverCert.Leaf
	ca := a.ca
	rootPEM := append([]byte(nil), a.rootPEM...)
	a.mu.RUnlock()

	if !ca.Available() {
		return false, fmt.Errorf("CA is not loaded")
	}
	if leaf != nil && now.Add(a.leafRenewBefore).Before(leaf.NotAfter) {
		return false, nil
	}
	fresh, err := issueServerCertificate(ca, rootPEM, a.serverNames, a.leafLifetime, now)
	if err != nil {
		return false, err
	}
	a.mu.Lock()
	// Re-check under the write lock: a concurrent KRT CA update may have installed a
	// newer certificate while this one was being signed.
	if a.serverCert.Leaf == nil || !a.serverCert.Leaf.NotAfter.After(now.Add(a.leafRenewBefore)) {
		a.serverCert = fresh
	}
	a.mu.Unlock()
	log.Info("renewed xDS server certificate", "valid_until", fresh.Leaf.NotAfter.UTC().Format(time.RFC3339))
	return true, nil
}

func (a *Authority) reconcileCA(ctx context.Context, now time.Time) error {
	return casecret.Rotate(ctx, a.client.Kube(), a.options.Namespace, a.options.SecretName, workloadCAKeys,
		a.options.RootLifetime, a.options.RenewBefore, now)
}
