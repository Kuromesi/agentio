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

package securityprofile

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newAPIKeySecret(namespace, name, apiKey string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Data:       map[string][]byte{"apiKey": []byte(apiKey)},
	}
}

func newSTSSecret(namespace, name, ak, sk, token string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Data: map[string][]byte{
			"accessKeyId":     []byte(ak),
			"accessKeySecret": []byte(sk),
			"securityToken":   []byte(token),
		},
	}
}

func newSecretGetErrorClientset(err error) kubernetes.Interface {
	cs := k8sfake.NewClientset()
	cs.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, err
	})
	return cs
}
