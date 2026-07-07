// Copyright Istio Authors
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

package krt

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/kubetypes"
	istiolog "istio.io/istio/pkg/log"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
)

type informer[I controllers.ComparableObject] struct {
	inf            kclient.Informer[I]
	log            *istiolog.Scope
	collectionName string
	id             collectionUID

	// eventHandlers is non-nil only when debounce is enabled. In that mode
	// a single shared K8s handler fans events through the debouncer to all
	// registered listeners. With debounce off we bypass it entirely and
	// register handlers directly on the K8s informer (legacy path).
	eventHandlers *handlerSet[I]
	augmentation  func(a any) any
	synced        chan struct{}
	stop          <-chan struct{}
	baseSyncer    Syncer
	metadata      Metadata
}

// nolint: unused // (not true, its to implement an interface)
func (i *informer[I]) augment(a any) any {
	if i.augmentation != nil {
		return i.augmentation(a)
	}
	return a
}

var _ internalCollection[controllers.Object] = &informer[controllers.Object]{}

// nolint: unused // (not true, its to implement an interface)
func (i *informer[I]) _internalHandler() {}

func (i *informer[I]) Synced() Syncer {
	return channelSyncer{
		name:   i.collectionName,
		synced: i.synced,
	}
}

func (i *informer[I]) HasSynced() bool {
	return i.baseSyncer.HasSynced()
}

func (i *informer[I]) WaitUntilSynced(stop <-chan struct{}) bool {
	return i.baseSyncer.WaitUntilSynced(stop)
}

// nolint: unused // (not true, its to implement an interface)
func (i *informer[I]) dump() CollectionDump {
	return CollectionDump{
		Outputs: eraseMap(slices.GroupUnique(i.inf.List(metav1.NamespaceAll, klabels.Everything()), getTypedKey)),
		Synced:  i.HasSynced(),
	}
}

func (i *informer[I]) name() string {
	return i.collectionName
}

// nolint: unused // (not true, its to implement an interface)
func (i *informer[I]) uid() collectionUID {
	return i.id
}

func (i *informer[I]) List() []I {
	res := i.inf.List(metav1.NamespaceAll, klabels.Everything())
	return res
}

func (i *informer[I]) GetKey(k string) *I {
	// ns, n := splitKeyFunc(string(k))
	// Internal optimization: we know kclient will eventually lookup "ns/name"
	// We also have a key in this format.
	// Rather than split and rejoin it later, just pass it as the name
	// This is depending on "unstable" implementation details, but we own both libraries and tests would catch any issues.
	if got := i.inf.Get(k, ""); !controllers.IsNil(got) {
		return &got
	}
	return nil
}

func (i *informer[I]) Metadata() Metadata {
	return i.metadata
}

func (i *informer[I]) Register(f func(o Event[I])) HandlerRegistration {
	return registerHandlerAsBatched[I](i, f)
}

func (i *informer[I]) RegisterBatch(f func(o []Event[I]), runExistingState bool) HandlerRegistration {
	// Note: runExistingState is NOT respected here.
	// Informer doesn't expose a way to opt-out; K8s always replays cached items to a newly-registered handler.
	_ = runExistingState

	if i.eventHandlers == nil {
		// Debounce off: register directly on the K8s informer. Each handler
		// gets its own per-handler syncTracker via cache.ResourceEventHandlerRegistration.
		synced := i.inf.AddEventHandler(informerEventHandler[I](func(o Event[I], initialSync bool) {
			f([]Event[I]{o})
		}))
		handlerSyncer := pollSyncer{
			name: fmt.Sprintf("%v handler", i.name()),
			f:    synced.HasSynced,
		}
		return informerHandlerRegistration{
			Syncer: multiSyncer{syncers: []Syncer{i.baseSyncer, handlerSyncer}},
			remove: func() {
				i.inf.ShutdownHandler(synced)
			},
		}
	}

	// Debounce on: snapshot the current cache as initialEvents and route
	// through handlerSet. This can race the shared K8s handler: an item may
	// be visible in inf.List() (K8s processDeltas writes the indexer before
	// invoking handlers) while still in flight toward the debouncer, so the
	// same item may later be flushed to the new listener — producing a
	// duplicate Add. Downstream consumers (manyCollection/join/mergejoin and
	// the like) are idempotent under duplicate Add (state-diff absorbs it),
	// so we accept this in exchange for the simpler design.
	existing := i.inf.List(metav1.NamespaceAll, klabels.Everything())
	initial := make([]Event[I], 0, len(existing))
	for _, obj := range existing {
		o := obj
		initial = append(initial, Event[I]{
			New:   &o,
			Event: controllers.EventAdd,
		})
	}

	return i.eventHandlers.Insert(f, i.baseSyncer, initial, i.stop)
}

type informerHandlerRegistration struct {
	Syncer
	remove func()
}

func (i informerHandlerRegistration) UnregisterHandler() {
	i.remove()
}

// nolint: unused // (not true)
type informerIndex[I any] struct {
	idx kclient.RawIndexer
}

// nolint: unused // (not true)
func (ii *informerIndex[I]) Lookup(key string) []I {
	return slices.Map(ii.idx.Lookup(key), func(i any) I {
		return i.(I)
	})
}

// nolint: unused // (not true)
func (i *informer[I]) index(name string, extract func(o I) []string) indexer[I] {
	idx := i.inf.Index(name, extract)
	return &informerIndex[I]{
		idx: idx,
	}
}

func informerEventHandler[I controllers.ComparableObject](handler func(o Event[I], initialSync bool)) cache.ResourceEventHandler {
	return controllers.EventHandler[I]{
		AddExtendedFunc: func(obj I, initialSync bool) {
			handler(Event[I]{
				New:   &obj,
				Event: controllers.EventAdd,
			}, initialSync)
		},
		UpdateFunc: func(oldObj, newObj I) {
			handler(Event[I]{
				Old:   &oldObj,
				New:   &newObj,
				Event: controllers.EventUpdate,
			}, false)
		},
		DeleteFunc: func(obj I) {
			handler(Event[I]{
				Old:   &obj,
				Event: controllers.EventDelete,
			}, false)
		},
	}
}

// WrapClient is the base entrypoint that enables the creation
// of a collection from an API Server client.
//
// Generic types can use kclient.NewDynamic to create an
// informer for a Collection of type controllers.Object
func WrapClient[I controllers.ComparableObject](c kclient.Informer[I], opts ...CollectionOption) Collection[I] {
	o := buildCollectionOptions(opts...)
	if o.name == "" {
		o.name = fmt.Sprintf("Informer[%v]", ptr.TypeName[I]())
	}
	h := &informer[I]{
		inf:            c,
		log:            log.WithLabels("owner", o.name),
		collectionName: o.name,
		id:             nextUID(),
		augmentation:   o.augmentation,
		synced:         make(chan struct{}),
		stop:           o.stop,
	}
	h.baseSyncer = channelSyncer{
		name:   h.collectionName,
		synced: h.synced,
	}

	if o.metadata != nil {
		h.metadata = o.metadata
	}

	if o.debounceInterval > 0 {
		// Debounce mode: install a single shared K8s handler that fans every
		// event through the handlerSet's debouncer to all listeners. Without
		// this, RegisterBatch attaches handlers directly to the K8s informer
		// (legacy path) and skips handlerSet entirely.
		h.eventHandlers = newHandlerSet[I]()
		h.eventHandlers.WithDebounce(o.debounceInterval, o.debounceMaxInterval, o.stop)
		c.AddEventHandler(informerEventHandler[I](func(e Event[I], initialSync bool) {
			h.eventHandlers.Distribute([]Event[I]{e}, initialSync)
		}))
	}

	go func() {
		defer c.ShutdownHandlers()
		// First, wait for the informer to populate. We ignore handlers which have their own syncing
		if !kube.WaitForCacheSync(o.name, o.stop, c.HasSyncedIgnoringHandlers) {
			return
		}

		// Under debounce, defer closing h.synced until the debouncer has
		// flushed its initial backlog at least once. By construction the K8s
		// shared handler delivers every initial-list item before any later
		// event and synchronously calls debouncer.Enqueue, so the after-window
		// naturally batches the entire initial backlog into a single flush;
		// the first debouncer flush therefore implies "all initial events
		// delivered". If the cache is empty no events will ever flow, so we
		// close immediately. We CANNOT use c.HasSynced for this gating: for
		// handlers added before the informer started, the K8s
		// SingleFileTracker's count transiently fluctuates 0→1→0 during the
		// initial-list drain.
		if h.eventHandlers != nil {
			if debSynced := h.eventHandlers.DebouncerSynced(); debSynced != nil &&
				len(c.List(metav1.NamespaceAll, klabels.Everything())) > 0 {
				select {
				case <-debSynced:
				case <-o.stop:
					return
				}
			}
		}
		close(h.synced)
		h.log.Infof("%v synced", h.name())

		<-o.stop
	}()
	maybeRegisterCollectionForDebugging(h, o.debugger)
	return h
}

// NewInformer creates a Collection[I] sourced from
// the results of kube.Client querying resources of type I
// from the API Server.
//
// Resources must have their GVR and GVK registered in the
// kube.Client before this method is called, otherwise
// NewInformer will panic.
func NewInformer[I controllers.ComparableObject](c kube.Client, opts ...CollectionOption) Collection[I] {
	return NewFilteredInformer[I](c, kubetypes.Filter{}, opts...)
}

// NewFilteredInformer takes an argument that filters the
// results from the kube.Client. Otherwise, behaves
// the same as NewInformer
func NewFilteredInformer[I controllers.ComparableObject](c kube.Client, filter kubetypes.Filter, opts ...CollectionOption) Collection[I] {
	return WrapClient[I](kclient.NewFiltered[I](c, filter), opts...)
}
