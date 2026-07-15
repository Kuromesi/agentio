// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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

package krt_test

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/kube/kclient/clienttest"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test"
)

type Workload struct {
	krt.Named
	ServiceNames []string
	IP           string
}

// GetLabelSelector defaults to using Reflection which is slow. Provide a specialized implementation that does it more efficiently.
type ServiceWrapper struct{ *v1.Service }

func (s ServiceWrapper) GetLabelSelector() map[string]string {
	return s.Spec.Selector
}

var _ krt.LabelSelectorer = ServiceWrapper{}

func NewModern(c kube.Client, events chan string, _ <-chan struct{}) {
	Pods := krt.NewInformer[*v1.Pod](c)
	Services := krt.NewInformer[*v1.Service](c, krt.WithObjectAugmentation(func(o any) any {
		return ServiceWrapper{o.(*v1.Service)}
	}))
	ServicesByNamespace := krt.NewNamespaceIndex(Services)

	Workloads := krt.NewCollection(Pods, func(ctx krt.HandlerContext, p *v1.Pod) *Workload {
		if p.Status.PodIP == "" {
			return nil
		}
		services := krt.Fetch(ctx, Services, krt.FilterIndex(ServicesByNamespace, p.Namespace), krt.FilterSelectsNonEmpty(p.GetLabels()))
		return &Workload{
			Named:        krt.NewNamed(p),
			IP:           p.Status.PodIP,
			ServiceNames: slices.Map(services, func(e *v1.Service) string { return e.Name }),
		}
	})
	Workloads.Register(func(e krt.Event[Workload]) {
		events <- fmt.Sprintf(e.Latest().Name, e.Event)
	})
}

type legacy struct {
	pods      kclient.Client[*v1.Pod]
	services  kclient.Client[*v1.Service]
	queue     controllers.Queue
	workloads map[types.NamespacedName]*Workload
	handler   func(event krt.Event[Workload])
}

func getPodServices(allServices []*v1.Service, pod *v1.Pod) []*v1.Service {
	var services []*v1.Service
	for _, service := range allServices {
		if labels.Instance(service.Spec.Selector).Match(pod.Labels) {
			services = append(services, service)
		}
	}

	return services
}

func (l *legacy) Reconcile(key types.NamespacedName) error {
	pod := l.pods.Get(key.Name, key.Namespace)
	if pod == nil || pod.Status.PodIP == "" {
		old := l.workloads[key]
		if old != nil {
			ev := krt.Event[Workload]{
				Old:   old,
				Event: controllers.EventDelete,
			}
			l.handler(ev)
			delete(l.workloads, key)
		}

		return nil
	}
	allServices := l.services.List(pod.Namespace, klabels.Everything())
	services := getPodServices(allServices, pod)
	wl := &Workload{
		Named:        krt.NewNamed(pod),
		IP:           pod.Status.PodIP,
		ServiceNames: slices.Map(services, func(e *v1.Service) string { return e.Name }),
	}
	old := l.workloads[key]
	if reflect.DeepEqual(old, wl) {
		// No changes, NOP
		return nil
	}
	// Changed. Update and call handlers
	l.workloads[key] = wl
	if old == nil {
		l.handler(krt.Event[Workload]{
			New:   wl,
			Event: controllers.EventAdd,
		})
	} else {
		l.handler(krt.Event[Workload]{
			Old:   old,
			New:   wl,
			Event: controllers.EventUpdate,
		})
	}
	return nil
}

func NewLegacy(cl kube.Client, events chan string, stop <-chan struct{}) {
	c := &legacy{
		workloads: map[types.NamespacedName]*Workload{},
	}
	c.pods = kclient.New[*v1.Pod](cl)
	c.services = kclient.New[*v1.Service](cl)
	c.queue = controllers.NewQueue("pods", controllers.WithReconciler(c.Reconcile))
	c.pods.AddEventHandler(controllers.ObjectHandler(c.queue.AddObject))
	c.services.AddEventHandler(controllers.FromEventHandler(func(e controllers.Event) {
		o := e.Latest()
		for _, pod := range c.pods.List(o.GetNamespace(), klabels.SelectorFromValidatedSet(o.(*v1.Service).Spec.Selector)) {
			c.queue.AddObject(pod)
		}
	}))
	c.handler = func(e krt.Event[Workload]) {
		events <- fmt.Sprintf(e.Latest().Name, e.Event)
	}
	go c.queue.Run(stop)
}

var nextIP = net.ParseIP("10.0.0.10")

func GetIP() string {
	i := nextIP.To4()
	ret := i.String()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v++
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	nextIP = net.IPv4(v0, v1, v2, v3)
	return ret
}

func drainN(c chan string, n int) {
	for n > 0 {
		n--
		<-c
	}
}

func BenchmarkControllers(b *testing.B) {
	log.FindScope("krt").SetOutputLevel(log.InfoLevel)
	watch.DefaultChanSize = 100_000
	initialPods := []*v1.Pod{}
	for i := 0; i < 1000; i++ {
		initialPods = append(initialPods, &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("pod-%d", i),
				Namespace: fmt.Sprintf("ns-%d", i%2),
				Labels: map[string]string{
					"app": fmt.Sprintf("app-%d", i%25),
				},
			},
			Spec: v1.PodSpec{
				ServiceAccountName: "fake-sa",
			},
			Status: v1.PodStatus{
				Phase: v1.PodRunning,
				PodIP: GetIP(),
			},
		})
	}
	initialServices := []*v1.Service{}
	for i := 0; i < 50; i++ {
		initialServices = append(initialServices, &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("pod-%d", i),
				Namespace: fmt.Sprintf("ns-%d", i%2),
			},
			Spec: v1.ServiceSpec{
				Selector: map[string]string{
					"app": fmt.Sprintf("app-%d", i%25),
				},
			},
		})
	}
	benchmark := func(b *testing.B, fn func(client kube.Client, events chan string, stop <-chan struct{})) {
		c := kube.NewFakeClient()
		events := make(chan string, 1000)
		stop := test.NewStop(b)
		fn(c, events, stop)
		pods := clienttest.NewWriter[*v1.Pod](b, c)
		services := clienttest.NewWriter[*v1.Service](b, c)
		for _, p := range initialPods {
			pods.Create(p)
		}
		for _, p := range initialServices {
			services.Create(p)
		}
		b.ResetTimer()
		c.RunAndWait(test.NewStop(b))
		drainN(events, 1000)
		for n := 0; n < b.N; n++ {
			for i := 0; i < 1000; i++ {
				pods.Update(&v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("pod-%d", i),
						Namespace: fmt.Sprintf("ns-%d", i%2),
						Labels: map[string]string{
							"app": fmt.Sprintf("app-%d", i%25),
						},
					},
					Spec: v1.PodSpec{
						ServiceAccountName: "fake-sa",
					},
					Status: v1.PodStatus{
						Phase: v1.PodRunning,
						PodIP: GetIP(),
					},
				})
			}
			drainN(events, 1000)
		}
	}
	b.Run("krt", func(b *testing.B) {
		benchmark(b, NewModern)
	})
	b.Run("legacy", func(b *testing.B) {
		benchmark(b, NewLegacy)
	})
}

// MatchedPod models a PodWorkloads-style derived value: how many
// "policies" (Services here, used as a stand-in for AuthorizationPolicy)
// currently match a given pod via label selector.
type MatchedPod struct {
	krt.Named
	PolicyCount int
}

// stormTracker is a thread-safe map of pod name -> latest PolicyCount,
// plus a cond var to wait for "all pods at expected count".
type stormTracker struct {
	mu     sync.Mutex
	cond   *sync.Cond
	counts map[string]int
}

func newStormTracker() *stormTracker {
	t := &stormTracker{counts: map[string]int{}}
	t.cond = sync.NewCond(&t.mu)
	return t
}

func (t *stormTracker) update(name string, count int, deleted bool) {
	t.mu.Lock()
	if deleted {
		delete(t.counts, name)
	} else {
		t.counts[name] = count
	}
	t.mu.Unlock()
	t.cond.Broadcast()
}

// waitFor blocks until exactly numPods entries are present and every one
// reports expected. Returns when both conditions hold.
func (t *stormTracker) waitFor(numPods, expected int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for {
		if len(t.counts) == numPods {
			ok := true
			for _, v := range t.counts {
				if v != expected {
					ok = false
					break
				}
			}
			if ok {
				return
			}
		}
		t.cond.Wait()
	}
}

func envIntOr(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// BenchmarkSecondaryEventStorm reproduces the perf-pathological topology
// where N selector-based "policies" all match the same M target pods.
// A single policy change is a secondary event affecting every matched
// pod; without coalescing, a burst of policy changes causes N*M
// recomputes (the user-reported case: 500 policies x 10000 pods ->
// 5M recomputes that never converged).
//
// This mirrors the ambient PodWorkloads collection's
// krt.Fetch(authorizationPolicies, FilterSelects(podLabels)) pattern.
//
// Model: Pods are pre-loaded and the collection is brought to a quiet
// steady state (all pods report PolicyCount=0). Then each iteration
// bursts N services into the fake client back-to-back; the krt
// informer goroutine reads them out of the watch channel and
// dispatches them. WithDebounce(after) on the Services informer holds
// outbound dispatch open for `after` so the burst collapses into a
// single secondary-event batch at PodWorkloads, which dedups affected
// pods and runs the transformation once per pod instead of once per
// (policy, pod) pair. The delete half is symmetric.
//
// Scale knobs (default small enough for CI):
//
//	KRT_BENCH_POLICIES   number of "policies" (default 50)
//	KRT_BENCH_PODS       number of target pods (default 500)
//
// To reproduce the production scenario set
// KRT_BENCH_POLICIES=500 KRT_BENCH_PODS=10000 and use -benchtime=1x
// (this will be slow without debounce — that is the point).
//
// Sub-benchmarks:
//
//	baseline       no debouncing — each policy event is its own
//	               secondary batch; recomputes/op grows ~ N*M
//	debounce-50ms  WithDebounce(50ms, 500ms) on the Services
//	               collection; the burst is coalesced into one
//	               secondary batch; recomputes/op stays ~ 2*M
//	               (add + delete halves)
//
// The win signal is the "recomputes/op" metric, not wall-clock —
// wall-clock at small scale is dominated by fake-client event
// delivery and the fixed debounce wait, but recomputes/op shows the
// coalescing factor that drives the production perf cliff.
func BenchmarkSecondaryEventStorm(b *testing.B) {
	log.FindScope("krt").SetOutputLevel(log.WarnLevel)
	watch.DefaultChanSize = 1_000_000

	numPolicies := envIntOr("KRT_BENCH_POLICIES", 50)
	numPods := envIntOr("KRT_BENCH_PODS", 500)

	initialPods := make([]*v1.Pod, 0, numPods)
	for i := 0; i < numPods; i++ {
		initialPods = append(initialPods, &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("pod-%d", i),
				Namespace: "default",
				Labels:    map[string]string{"app": "foo"},
			},
			Spec: v1.PodSpec{ServiceAccountName: "fake-sa"},
			Status: v1.PodStatus{
				Phase: v1.PodRunning,
				PodIP: GetIP(),
			},
		})
	}

	bench := func(b *testing.B, sourceDebounce time.Duration) {
		c := kube.NewFakeClient()
		stop := test.NewStop(b)

		// WithStop must be threaded through every collection: after the
		// informer->handlerSet pivot, every Register spins a
		// processorListener goroutine that only exits on this signal.
		baseOpts := []krt.CollectionOption{krt.WithStop(stop)}

		sourceOpts := append([]krt.CollectionOption{}, baseOpts...)
		if sourceDebounce > 0 {
			sourceOpts = append(sourceOpts, krt.WithDebounce(sourceDebounce, 10*sourceDebounce))
		}

		Pods := krt.NewInformer[*v1.Pod](c, baseOpts...)
		Services := krt.NewInformer[*v1.Service](
			c,
			append([]krt.CollectionOption{
				krt.WithObjectAugmentation(func(o any) any { return ServiceWrapper{o.(*v1.Service)} }),
			}, sourceOpts...)...,
		)

		var recomputes atomic.Int64
		PodWorkloads := krt.NewCollection(Pods, func(ctx krt.HandlerContext, p *v1.Pod) *MatchedPod {
			recomputes.Add(1)
			matched := krt.Fetch(ctx, Services, krt.FilterSelectsNonEmpty(p.GetLabels()))
			return &MatchedPod{
				Named:       krt.NewNamed(p),
				PolicyCount: len(matched),
			}
		}, baseOpts...)

		tracker := newStormTracker()
		PodWorkloads.Register(func(e krt.Event[MatchedPod]) {
			name := e.Latest().Name
			if e.Event == controllers.EventDelete {
				tracker.update(name, 0, true)
				return
			}
			tracker.update(name, e.Latest().PolicyCount, false)
		})

		podsW := clienttest.NewWriter[*v1.Pod](b, c)
		servicesW := clienttest.NewWriter[*v1.Service](b, c)
		for _, p := range initialPods {
			podsW.Create(p)
		}
		c.RunAndWait(stop)
		// Steady state: every pod has fired once with PolicyCount=0.
		// The initial-sync recomputes (one per pod) are not counted in
		// the storm metric.
		tracker.waitFor(numPods, 0)
		recomputes.Store(0)

		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			// Storm: add N policies as fast as the fake client accepts
			// them. WithDebounce on Services should coalesce these into
			// a single outbound batch at the dispatch layer.
			for i := 0; i < numPolicies; i++ {
				servicesW.Create(&v1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      fmt.Sprintf("svc-%d-%d", n, i),
						Namespace: "default",
					},
					Spec: v1.ServiceSpec{
						Selector: map[string]string{"app": "foo"},
					},
				})
			}
			tracker.waitFor(numPods, numPolicies)

			// Reset to a clean state. Deletion exercises the same
			// dispatch path with the inverse selector effect, so the
			// metric reflects both halves of a full add+delete cycle.
			for i := 0; i < numPolicies; i++ {
				servicesW.Delete(fmt.Sprintf("svc-%d-%d", n, i), "default")
			}
			tracker.waitFor(numPods, 0)
		}
		b.StopTimer()
		b.ReportMetric(float64(recomputes.Load())/float64(b.N), "recomputes/op")

		// Drain: at large scale (500x10000) the manyCollection queue may
		// still hold late secondary events that won't change any pod's
		// PolicyCount but are still CPU-bound on Equal/Fetch. tracker
		// returns as soon as the *visible* state matches, so we wait
		// for the recompute counter to stabilize before letting b's
		// stop chan close. Otherwise the leak detector catches the
		// queue goroutine mid-task.
		for {
			before := recomputes.Load()
			time.Sleep(50 * time.Millisecond)
			if recomputes.Load() == before {
				break
			}
		}
	}

	b.Run("baseline", func(b *testing.B) {
		bench(b, 0)
	})
	b.Run("debounce-50ms", func(b *testing.B) {
		bench(b, 50*time.Millisecond)
	})
}
