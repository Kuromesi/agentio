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

package casecret

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/openkruise/agentio/pkg/security/pki"
)

type Keys struct {
	Certificate           string
	PrivateKey            string
	Bundle                string
	AllowCertificateChain bool
}

func (k Keys) validate() error {
	if k.Certificate == "" || k.PrivateKey == "" {
		return fmt.Errorf("CA Secret certificate and private-key keys are required")
	}
	return nil
}

func New(namespace, name string, keys Keys, commonName string, lifetime time.Duration, now time.Time) (*corev1.Secret, error) {
	if err := keys.validate(); err != nil {
		return nil, err
	}
	ca, err := pki.NewSelfSignedCA(commonName, lifetime, now)
	if err != nil {
		return nil, err
	}
	data := map[string][]byte{
		keys.Certificate: ca.CertificatePEM(),
		keys.PrivateKey:  ca.PrivateKeyPEM(),
	}
	if keys.Bundle != "" {
		data[keys.Bundle] = ca.BundlePEM()
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}, nil
}

func LoadOrCreate(
	ctx context.Context,
	client kubernetes.Interface,
	namespace, name string,
	keys Keys,
	commonName string,
	lifetime time.Duration,
) (*corev1.Secret, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		secret, err = New(namespace, name, keys, commonName, lifetime, time.Now())
		if err == nil {
			secret, err = client.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
			if apierrors.IsAlreadyExists(err) {
				secret, err = client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("load CA Secret %s/%s: %w", namespace, name, err)
	}
	return secret, nil
}

func Rotate(
	ctx context.Context,
	client kubernetes.Interface,
	namespace, name string,
	keys Keys,
	lifetime, renewBefore time.Duration,
	now time.Time,
) error {
	if err := keys.validate(); err != nil {
		return err
	}
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	ca, err := parse(secret.Data[keys.Certificate], secret.Data[keys.PrivateKey], keys.AllowCertificateChain, now)
	if err != nil {
		return err
	}
	if ca.NotAfter().Sub(now) > renewBefore {
		return nil
	}
	renewed, err := pki.RenewSelfSignedCA(ca, lifetime, now)
	if err != nil {
		return err
	}
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	if keys.AllowCertificateChain {
		secret.Data[keys.Certificate] = renewed.BundlePEM()
	} else {
		secret.Data[keys.Certificate] = renewed.CertificatePEM()
	}
	secret.Data[keys.PrivateKey] = renewed.PrivateKeyPEM()
	if keys.Bundle != "" {
		secret.Data[keys.Bundle] = renewed.BundlePEM()
	}
	_, err = client.CoreV1().Secrets(namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

func parse(certPEM, keyPEM []byte, allowCertificateChain bool, now time.Time) (pki.SigningCA, error) {
	if allowCertificateChain {
		return pki.ParseSigningCABundle(certPEM, keyPEM, now)
	}
	return pki.ParseSigningCA(certPEM, keyPEM, now)
}
