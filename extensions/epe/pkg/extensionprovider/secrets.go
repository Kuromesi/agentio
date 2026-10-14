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
package extensionprovider

import (
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	kwatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
)

// secretDependencies watches only referenced Secrets. Its already-synced trigger
// lets the initial configuration apply even when Secret access is denied; the
// informer retries in the background and publishes material when it is available.
// These informers are independent of the process-wide shared informer lifecycle
// so removed references can be stopped and later watched again.
type secretDependencies struct {
	client  kube.Client
	ctx     context.Context
	trigger *krt.RecomputeTrigger
	watches map[string]secretWatch
}

type secretWatch struct {
	store  cache.Store
	cancel context.CancelFunc
}

func newSecretDependencies(client kube.Client, stop <-chan struct{}, opts ...krt.CollectionOption) *secretDependencies {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-stop
		cancel()
	}()
	return &secretDependencies{
		client:  client,
		ctx:     ctx,
		trigger: krt.NewRecomputeTrigger(true, opts...),
		watches: map[string]secretWatch{},
	}
}

// watch is called by the single effective-configuration transformation. Each
// snapshot keeps a shared CA/client reference consistent during resolution.
func (s *secretDependencies) watch(ctx krt.HandlerContext, refs map[string]struct{}) map[string]*corev1.Secret {
	if len(refs) != 0 {
		s.trigger.MarkDependant(ctx)
	}
	for key, w := range s.watches {
		if _, needed := refs[key]; !needed {
			w.cancel()
			delete(s.watches, key)
		}
	}
	snapshot := make(map[string]*corev1.Secret, len(refs))
	for key := range refs {
		w, exists := s.watches[key]
		if !exists {
			w = s.start(key)
			s.watches[key] = w
		}
		for _, obj := range w.store.List() {
			secret := obj.(*corev1.Secret)
			if secret.Namespace+"/"+secret.Name == key {
				snapshot[key] = secret
			}
		}
	}
	return snapshot
}

func (s *secretDependencies) start(key string) secretWatch {
	namespace, name, _ := strings.Cut(key, "/")
	client := s.client.Kube().CoreV1().Secrets(namespace)
	selector := fields.OneTermEqualSelector("metadata.name", name).String()
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = selector
			return client.List(ctx, options)
		},
		WatchFuncWithContext: func(ctx context.Context, options metav1.ListOptions) (kwatch.Interface, error) {
			options.FieldSelector = selector
			return client.Watch(ctx, options)
		},
	}
	store, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: cache.ToListWatcherWithWatchListSemantics(lw, s.client.Kube()),
		ObjectType:    &corev1.Secret{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    func(any) { s.trigger.TriggerRecomputation() },
			UpdateFunc: func(any, any) { s.trigger.TriggerRecomputation() },
			DeleteFunc: func(any) { s.trigger.TriggerRecomputation() },
		},
	})
	ctx, cancel := context.WithCancel(s.ctx)
	go controller.RunWithContext(ctx)
	return secretWatch{store: store, cancel: cancel}
}
