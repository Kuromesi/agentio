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

package kclient

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openkruise/agentio/pkg/kube/controllers"
)

// Writer performs writes for a single resource type.
type Writer[T controllers.Object] interface {
	Create(obj T) (T, error)
	Update(obj T) (T, error)
	UpdateStatus(obj T) (T, error)
	Delete(name, namespace string) error
}

// Client is a read-write handle: the Informer contract plus writes.
type Client[T controllers.Object] interface {
	Informer[T]
	Writer[T]
}

// StartableClient combines a shared informer lifecycle with typed writes.
// Starting it more than once is safe because the underlying shared informer
// factory owns the once-only start semantics.
type StartableClient[T controllers.ComparableObject] interface {
	Client[T]
	Start(stop <-chan struct{})
}

// resourceInterface is the method shape shared by generated typed clientsets.
type resourceInterface[T any] interface {
	Create(ctx context.Context, obj T, opts metav1.CreateOptions) (T, error)
	Update(ctx context.Context, obj T, opts metav1.UpdateOptions) (T, error)
	UpdateStatus(ctx context.Context, obj T, opts metav1.UpdateOptions) (T, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

// resourceInterfaceWithoutStatus matches the subset of resourceInterface needed
// for types that lack a status subresource (e.g. corev1.ServiceAccount).
// UpdateStatus returns a descriptive error.
type resourceInterfaceWithoutStatus[T any] interface {
	Create(ctx context.Context, obj T, opts metav1.CreateOptions) (T, error)
	Update(ctx context.Context, obj T, opts metav1.UpdateOptions) (T, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

type writableClient[T controllers.Object, R resourceInterface[T]] struct {
	Informer[T]
	resource func(namespace string) R
}

type statuslessClient[T controllers.Object, R resourceInterfaceWithoutStatus[T]] struct {
	Informer[T]
	resource func(namespace string) R
}

type startableClient[T controllers.ComparableObject] struct {
	Client[T]
	informer StartableInformer[T]
}

func (s *startableClient[T]) Start(stop <-chan struct{}) {
	s.informer.Start(stop)
}

// NewWritable wraps an informer and a typed clientset accessor into a Client.
// Namespaced types pass the namespace through the accessor; cluster-scoped
// accessors ignore it.
func NewWritable[T controllers.Object, R resourceInterface[T]](
	informer cache.SharedIndexInformer,
	resource func(namespace string) R,
) Client[T] {
	return &writableClient[T, R]{
		Informer: New[T](informer),
		resource: resource,
	}
}

// NewWritableStatusless is NewWritable for types without a status subresource; UpdateStatus returns an error.
func NewWritableStatusless[T controllers.Object, R resourceInterfaceWithoutStatus[T]](
	informer cache.SharedIndexInformer,
	resource func(namespace string) R,
) Client[T] {
	return &statuslessClient[T, R]{
		Informer: New[T](informer),
		resource: resource,
	}
}

// NewWritableFromInformer adds typed writes to an informer obtained from the
// process-wide kube.Client without creating a second informer factory.
func NewWritableFromInformer[T controllers.ComparableObject, R resourceInterface[T]](
	informer StartableInformer[T],
	resource func(namespace string) R,
) StartableClient[T] {
	return &startableClient[T]{
		Client: &writableClient[T, R]{
			Informer: informer,
			resource: resource,
		},
		informer: informer,
	}
}

// NewWritableStatuslessFromInformer is NewWritableFromInformer for resources
// without a status subresource.
func NewWritableStatuslessFromInformer[T controllers.ComparableObject, R resourceInterfaceWithoutStatus[T]](
	informer StartableInformer[T],
	resource func(namespace string) R,
) StartableClient[T] {
	return &startableClient[T]{
		Client: &statuslessClient[T, R]{
			Informer: informer,
			resource: resource,
		},
		informer: informer,
	}
}

func (w *writableClient[T, R]) Create(obj T) (T, error) {
	return w.resource(obj.GetNamespace()).Create(context.Background(), obj, metav1.CreateOptions{})
}

func (w *writableClient[T, R]) Update(obj T) (T, error) {
	return w.resource(obj.GetNamespace()).Update(context.Background(), obj, metav1.UpdateOptions{})
}

func (w *writableClient[T, R]) UpdateStatus(obj T) (T, error) {
	return w.resource(obj.GetNamespace()).UpdateStatus(context.Background(), obj, metav1.UpdateOptions{})
}

func (w *writableClient[T, R]) Delete(name, namespace string) error {
	return w.resource(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
}

func (s *statuslessClient[T, R]) Create(obj T) (T, error) {
	return s.resource(obj.GetNamespace()).Create(context.Background(), obj, metav1.CreateOptions{})
}

func (s *statuslessClient[T, R]) Update(obj T) (T, error) {
	return s.resource(obj.GetNamespace()).Update(context.Background(), obj, metav1.UpdateOptions{})
}

func (s *statuslessClient[T, R]) UpdateStatus(obj T) (T, error) {
	var zero T
	return zero, fmt.Errorf("type %T does not support status subresource", zero)
}

func (s *statuslessClient[T, R]) Delete(name, namespace string) error {
	return s.resource(namespace).Delete(context.Background(), name, metav1.DeleteOptions{})
}
