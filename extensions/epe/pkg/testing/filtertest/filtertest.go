// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package filtertest provides shared fakes and builders for filter tests.
//
// These are regular (non _test.go) declarations on purpose: internal test
// packages of the filter implementations (tokentransform and its signers,
// ...) and external scenario test packages both import them, and _test.go
// symbols are not visible across packages.
//
// The package must stay a leaf — fake Kubernetes clients and nothing else.
// It is imported by the filters' own internal test packages, so any edge
// from here to the chain or to the enginetest harness (which imports the
// chain) would be an import cycle.
package filtertest

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// APIKeySecret builds the Secret shape the ApiKey signer reads for
// CredentialRef Kind=Secret: a single "apiKey" data key.
func APIKeySecret(namespace, name, apiKey string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Data:       map[string][]byte{"apiKey": []byte(apiKey)},
	}
}

// STSSecret builds the Secret shape an STS signer reads for
// CredentialRef Kind=Secret: the accessKeyId/accessKeySecret/securityToken
// triplet.
func STSSecret(namespace, name, ak, sk, token string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Data: map[string][]byte{
			"accessKeyId":     []byte(ak),
			"accessKeySecret": []byte(sk),
			"securityToken":   []byte(token),
		},
	}
}

// SecretGetErrorClientset returns a fake clientset whose Secret reads always
// fail with the given error (e.g. a Forbidden error simulating missing RBAC,
// or a plain error simulating an apiserver outage).
func SecretGetErrorClientset(err error) kubernetes.Interface {
	cs := k8sfake.NewClientset()
	cs.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, err
	})
	return cs
}
