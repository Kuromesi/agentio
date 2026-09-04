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
	"bytes"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/pkg/ptr"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	"github.com/openkruise/agentio/pkg/security/pki"
)

type caState struct {
	ca        pki.SigningCA
	rootPEM   []byte
	secretUID types.UID
}

// TrustBundle is the immutable, committed workload root consumed by
// distributors and webhook CA-bundle patchers.
type TrustBundle struct {
	PEM string
}

func (TrustBundle) ResourceName() string {
	return "workload-trust-bundle"
}

func (b TrustBundle) Equals(other TrustBundle) bool {
	return b.PEM == other.PEM
}

func (caState) ResourceName() string {
	return "workload-ca-state"
}

func (c caState) Equals(other caState) bool {
	return c.secretUID == other.secretUID && c.ca.Equal(other.ca) && bytes.Equal(c.rootPEM, other.rootPEM)
}

func newCASecretSingleton(client kube.Client, options AuthorityOptions) krt.Singleton[caState] {
	secretClient := kclient.NewFiltered[*corev1.Secret](client, kclient.Filter{
		Namespace:     options.Namespace,
		FieldSelector: "metadata.name=" + options.SecretName,
	})
	secrets := krt.WrapClient(secretClient, options.KrtOptions.WithName("Workload_CA_Secret_"+options.SecretName)...)
	secretClient.Start(options.KrtOptions.Stop())

	secretKey := types.NamespacedName{Namespace: options.Namespace, Name: options.SecretName}.String()
	return krt.NewSingleton(func(ctx krt.HandlerContext) *caState {
		secret := ptr.Flatten(krt.FetchOne(ctx, secrets, krt.FilterKey(secretKey)))
		if secret == nil {
			log.Warn("workload CA Secret not found", "namespace", options.Namespace, "secret", options.SecretName)
			return nil
		}
		state, err := parseCASecret(secret, time.Now())
		if err != nil {
			log.Error("parse workload CA Secret", "namespace", options.Namespace, "secret", options.SecretName, "error", err)
			return nil
		}
		return &state
	}, options.KrtOptions.WithName("Workload_CA")...)
}

func parseCASecret(secret *corev1.Secret, now time.Time) (caState, error) {
	ca, err := pki.ParseSigningCA(secret.Data[caCertKey], secret.Data[caKeyKey], now)
	if err != nil {
		return caState{}, err
	}
	rootPEM := secret.Data[caBundleKey]
	if len(rootPEM) == 0 {
		rootPEM = secret.Data[caCertKey]
	}
	if err := pki.ValidateTrustBundle(rootPEM, ca, now); err != nil {
		return caState{}, fmt.Errorf("validate trust bundle: %w", err)
	}
	return caState{
		ca:        ca,
		rootPEM:   append([]byte(nil), rootPEM...),
		secretUID: secret.UID,
	}, nil
}

func (a *Authority) handleCAEvent(event krt.Event[caState]) {
	if event.New == nil {
		a.caInstallMu.Lock()
		defer a.caInstallMu.Unlock()
		// A newer add may already have replaced this queued removal.
		if a.caSingleton.Get() != nil {
			return
		}
		a.mu.Lock()
		wasAvailable := a.ca.Available()
		a.ca = pki.SigningCA{}
		a.mu.Unlock()
		if wasAvailable {
			log.Warn("workload CA Secret is unavailable; new certificate signing is disabled",
				"namespace", a.options.Namespace, "secret", a.options.SecretName)
		}
		return
	}
	if err := a.installCAState(*event.New); err != nil {
		log.Error("install workload CA Secret", "namespace", a.options.Namespace, "secret", a.options.SecretName, "error", err)
	}
}

func (a *Authority) installCAState(state caState) error {
	a.caInstallMu.Lock()
	defer a.caInstallMu.Unlock()
	if current := a.caSingleton.Get(); current == nil || !current.Equals(state) {
		return nil
	}

	a.mu.Lock()
	caChanged := !a.ca.Equal(state.ca)
	rootChanged := !bytes.Equal(a.rootPEM, state.rootPEM)
	changed := caChanged || rootChanged
	if !changed {
		a.mu.Unlock()
		return nil
	}
	if caChanged {
		// The Secret collection is authoritative. Do not continue issuing from
		// the previous CA while the replacement serving certificate is built.
		a.ca = pki.SigningCA{}
	}
	a.mu.Unlock()

	serverCert, err := issueServerCertificate(state.ca, state.rootPEM, a.serverNames, a.leafLifetime, time.Now())
	if err != nil {
		return err
	}
	if current := a.caSingleton.Get(); current == nil || !current.Equals(state) {
		return nil
	}
	a.mu.Lock()
	a.ca = state.ca
	a.rootPEM = append([]byte(nil), state.rootPEM...)
	a.serverCert = serverCert
	a.mu.Unlock()

	if err := publishRoot(a.ctx, a.client.Kube(), a.options.Namespace, a.options.ConfigMapName, state.rootPEM); err != nil {
		log.Error("publish workload root bundle", "error", err)
	}
	if rootChanged {
		a.trustBundles.Set(&TrustBundle{PEM: string(state.rootPEM)})
	}
	return nil
}
