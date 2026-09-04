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
	"reflect"
	"sync"

	"istio.io/istio/pkg/util/sets"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

// InformerOptions identifies one shared informer view. Selectors and namespace
// are applied by the API server; ObjectTransform is applied before cache storage.
type InformerOptions struct {
	LabelSelector   string
	FieldSelector   string
	Namespace       string
	ObjectTransform func(any) (any, error)
}

// InformerRegistration describes the typed List/Watch contract for one GVR.
// Core registrations are supplied by kclient; external APIs can provide the
// same contract without becoming fields on Client.
type InformerRegistration struct {
	Resource schema.GroupVersionResource
	Object   runtime.Object
	List     func(context.Context, string, metav1.ListOptions) (runtime.Object, error)
	Watch    func(context.Context, string, metav1.ListOptions) (watch.Interface, error)
}

// StartableInformer is a shared informer plus its per-informer start function.
// Starting an informer more than once is safe.
type StartableInformer struct {
	Informer cache.SharedIndexInformer
	start    func(stop <-chan struct{})
}

// NewStartableInformer constructs a StartableInformer for alternate Client
// implementations such as client-go fakes.
func NewStartableInformer(
	informer cache.SharedIndexInformer,
	start func(stop <-chan struct{}),
) StartableInformer {
	var once sync.Once
	return StartableInformer{
		Informer: informer,
		start: func(stop <-chan struct{}) {
			once.Do(func() { start(stop) })
		},
	}
}

func (s StartableInformer) Start(stop <-chan struct{}) {
	if s.start != nil {
		s.start(stop)
	}
}

type informerKey struct {
	resource      schema.GroupVersionResource
	labelSelector string
	fieldSelector string
	namespace     string
}

type informerFactory struct {
	mu                       sync.Mutex
	informers                map[informerKey]builtInformer
	started                  sets.Set[informerKey]
	unsupportedWatchListMode bool
}

type builtInformer struct {
	informer  cache.SharedIndexInformer
	transform func(any) (any, error)
}

func newInformerFactory() *informerFactory {
	return &informerFactory{
		informers: make(map[informerKey]builtInformer),
		started:   sets.New[informerKey](),
	}
}

func (f *informerFactory) informerFor(
	registration InformerRegistration,
	options InformerOptions,
) StartableInformer {
	transform := options.ObjectTransform
	if transform == nil {
		transform = stripUnusedFields
	}
	key := informerKey{
		resource:      registration.Resource,
		labelSelector: options.LabelSelector,
		fieldSelector: options.FieldSelector,
		namespace:     options.Namespace,
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, found := f.informers[key]; found {
		if reflect.ValueOf(existing.transform).Pointer() != reflect.ValueOf(transform).Pointer() {
			log.Warn("Kubernetes informer registered with conflicting object transform; keeping the first transform",
				"resource", registration.Resource)
		}
		return f.startable(existing.informer, key)
	}
	listWatch := &cache.ListWatch{
		ListFunc: func(listOptions metav1.ListOptions) (runtime.Object, error) {
			listOptions.LabelSelector = options.LabelSelector
			listOptions.FieldSelector = options.FieldSelector
			return registration.List(context.Background(), options.Namespace, listOptions)
		},
		WatchFunc: func(listOptions metav1.ListOptions) (watch.Interface, error) {
			listOptions.LabelSelector = options.LabelSelector
			listOptions.FieldSelector = options.FieldSelector
			return registration.Watch(context.Background(), options.Namespace, listOptions)
		},
	}
	informer := cache.NewSharedIndexInformer(
		cache.ToListWatcherWithWatchListSemantics(listWatch, f),
		registration.Object,
		0,
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	_ = informer.SetTransform(transform)
	f.informers[key] = builtInformer{
		informer:  informer,
		transform: transform,
	}
	return f.startable(informer, key)
}

func (f *informerFactory) IsWatchListSemanticsUnSupported() bool {
	return f.unsupportedWatchListMode
}

func (f *informerFactory) startable(informer cache.SharedIndexInformer, key informerKey) StartableInformer {
	return StartableInformer{
		Informer: informer,
		start: func(stop <-chan struct{}) {
			f.startOne(stop, key)
		},
	}
}

func (f *informerFactory) startOne(stop <-chan struct{}, key informerKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started.Contains(key) {
		return
	}
	built, found := f.informers[key]
	if !found {
		return
	}
	f.started.Insert(key)
	go built.informer.Run(stop)
}

func (f *informerFactory) start(stop <-chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for key, built := range f.informers {
		if f.started.Contains(key) {
			continue
		}
		f.started.Insert(key)
		go built.informer.Run(stop)
	}
}

func stripUnusedFields(obj any) (any, error) {
	if accessor, ok := obj.(metav1.ObjectMetaAccessor); ok {
		accessor.GetObjectMeta().SetManagedFields(nil)
	}
	return obj, nil
}
