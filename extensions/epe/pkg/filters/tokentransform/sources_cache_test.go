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
package tokentransform

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kwatch "k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/testing/testsupport"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
)

func TestSecretCacheScopeRotationAndDeletion(t *testing.T) {
	for _, namespace := range []string{"system", metav1.NamespaceAll} {
		t.Run("scope="+namespace, func(t *testing.T) {
			client := kube.NewFakeClient(
				secretObj("system", "key", map[string][]byte{"apiKey": []byte("initial")}),
				secretObj("business", "key", map[string][]byte{"apiKey": []byte("other")}),
			)
			secrets := krt.NewFilteredInformer[*corev1.Secret](client, kclient.Filter{Namespace: namespace},
				krt.WithStop(t.Context().Done()))
			source := NewSecretSource(secrets, namespace)
			client.Run(t.Context().Done())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if !secrets.WaitUntilSynced(ctx.Done()) {
				t.Fatal("Secret cache did not sync")
			}
			if namespace != metav1.NamespaceAll && secrets.GetKey("business/key") != nil {
				t.Fatal("out-of-scope Secret entered cache")
			}
			ref := Ref{Kind: CredentialKindToken, Namespace: "system", Name: "key"}
			for range 1000 {
				cred, err := source.Fetch(t.Context(), ref)
				if err != nil || cred.Token != "initial" {
					t.Fatalf("cached fetch failed: %v", err)
				}
			}
			other, err := source.Fetch(t.Context(), Ref{Kind: CredentialKindToken, Namespace: "business", Name: "key"})
			if namespace == metav1.NamespaceAll {
				if err != nil || other.Token != "other" {
					t.Fatalf("cross-namespace cached fetch failed: %v", err)
				}
			} else if !errors.Is(err, ErrNoPermission) {
				t.Fatalf("expected out-of-scope denial, got %v", err)
			}
			for _, action := range client.Kube().(*k8sfake.Clientset).Actions() {
				if action.GetResource().Resource == "secrets" &&
					(action.GetNamespace() != namespace || (action.GetVerb() != "list" && action.GetVerb() != "watch")) {
					t.Fatalf("unexpected Secret API action: %s %s", action.GetVerb(), action.GetNamespace())
				}
			}
			updated := secretObj("system", "key", map[string][]byte{"apiKey": []byte("rotated")})
			if _, err := client.Kube().
				CoreV1().
				Secrets("system").
				Update(t.Context(), updated, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			testsupport.Eventually(t, 5*time.Second, func() error {
				cred, err := source.Fetch(t.Context(), ref)
				if err != nil {
					return err
				}
				if cred.Token != "rotated" {
					return errors.New("rotation not observed")
				}
				return nil
			})
			if err := client.Kube().
				CoreV1().
				Secrets("system").
				Delete(t.Context(), "key", metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
			testsupport.Eventually(t, 5*time.Second, func() error {
				_, err := source.Fetch(t.Context(), ref)
				if err == nil {
					return errors.New("deletion not observed")
				}
				if !strings.Contains(err.Error(), "not found") {
					return fmt.Errorf("unexpected deletion error: %w", err)
				}
				return nil
			})
		})
	}
}

func TestSecretCacheForbiddenStaysUnavailable(t *testing.T) {
	for _, namespace := range []string{"system", metav1.NamespaceAll} {
		t.Run("scope="+namespace, func(t *testing.T) {
			client := kube.NewFakeClient()
			fake := client.Kube().(*k8sfake.Clientset)
			requested := make(chan struct{}, 1)
			denied := apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "", errors.New("denied"))
			fake.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
				select {
				case requested <- struct{}{}:
				default:
				}
				return true, nil, denied
			})
			fake.PrependWatchReactor("secrets", func(k8stesting.Action) (bool, kwatch.Interface, error) {
				select {
				case requested <- struct{}{}:
				default:
				}
				return true, nil, denied
			})
			secrets := krt.NewFilteredInformer[*corev1.Secret](client, kclient.Filter{Namespace: namespace},
				krt.WithStop(t.Context().Done()))
			client.Run(t.Context().Done())
			select {
			case <-requested:
			case <-time.After(5 * time.Second):
				t.Fatal("informer did not request Secrets")
			}
			if secrets.HasSynced() {
				t.Fatal("Forbidden cache must not report synced")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			if secrets.WaitUntilSynced(ctx.Done()) {
				t.Fatal("Forbidden cache must not allow startup")
			}
		})
	}
}
