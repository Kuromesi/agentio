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

package krt

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	acmetav1 "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openkruise/agentio/pkg/kube/controllers"
	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/ptr"
)

type ObjectWithCluster[T any] struct {
	ClusterID cluster.ID
	Object    *T
}

// Don't include the cluster in the key so that mapped collections aren't affected.
// This is really just a performance optimization so we don't have to coppy the inner
// object by doing NewCollection.
func (o ObjectWithCluster[T]) ResourceName() string {
	if o.Object == nil {
		return ""
	}
	return GetKey(*o.Object)
}

func (o *ObjectWithCluster[T]) Equals(o2 *ObjectWithCluster[T]) bool {
	if o.ClusterID != o2.ClusterID {
		return false
	}

	if o.Object == nil && o2.Object == nil {
		return true
	}

	if (o.Object == nil && o2.Object != nil) || (o.Object != nil && o2.Object == nil) {
		return false
	}

	a := *o.Object
	b := *o2.Object
	return Equal(a, b)
}

func getTypedKey[O any](a O) Key[O] {
	return Key[O](GetKey(a))
}

// GetKey returns the key for the provided object.
// If there is none, this will panic.
func GetKey[O any](a O) string {
	as, ok := any(a).(string)
	if ok {
		return as
	}
	ao, ok := any(a).(controllers.Object)
	if ok {
		k, _ := cache.MetaNamespaceKeyFunc(ao)
		return k
	}
	arn, ok := any(a).(ResourceNamer)
	if ok {
		return arn.ResourceName()
	}
	auid, ok := any(a).(uidable)
	if ok {
		return strconv.FormatUint(uint64(auid.uid()), 10)
	}

	ack := GetApplyConfigKey(a)
	if ack != nil {
		return *ack
	}
	panic(fmt.Sprintf("Cannot get Key, got %T", a))
}

// Named is a convenience struct. It is ideal to be embedded into a type that has a name and namespace,
// and will automatically implement the various interfaces to return the name, namespace, and a key based on these two.
type Named struct {
	Name, Namespace string
}

// NewNamed builds a Named object from a Kubernetes object type.
func NewNamed(o metav1.Object) Named {
	return Named{Name: o.GetName(), Namespace: o.GetNamespace()}
}

func (n Named) ResourceName() string {
	return n.Namespace + "/" + n.Name
}

func (n Named) GetName() string {
	return n.Name
}

func (n Named) GetNamespace() string {
	return n.Namespace
}

func (n Named) String() string {
	return n.ResourceName()
}

// GetApplyConfigKey returns the key for the ApplyConfig.
// If there is none, this will return nil.
func GetApplyConfigKey[O any](a O) *string {
	// Reflection is expensive; short circuit here
	if !strings.HasSuffix(ptr.TypeName[O](), "ApplyConfiguration") {
		return nil
	}
	val := reflect.ValueOf(a)

	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	if val.Kind() != reflect.Struct {
		return nil
	}

	specField := val.FieldByName("ObjectMetaApplyConfiguration")
	if !specField.IsValid() {
		return nil
	}
	meta := specField.Interface().(*acmetav1.ObjectMetaApplyConfiguration)
	if meta.Namespace != nil && len(*meta.Namespace) > 0 {
		return ptr.Of(*meta.Namespace + "/" + *meta.Name)
	}
	return meta.Name
}

// keyFunc is the internal API key function that returns "namespace"/"name" or
// "name" if "namespace" is empty
func keyFunc(name, namespace string) string {
	if len(namespace) == 0 {
		return name
	}
	return namespace + "/" + name
}

func waitForCacheSync(name string, stop <-chan struct{}, collections ...<-chan struct{}) (r bool) {
	t := time.NewTicker(time.Second * 5)
	defer t.Stop()
	t0 := time.Now()
	defer func() {
		if r {
			log.Debug("sync complete", "name", name, "elapsed", time.Since(t0))
		} else {
			log.Error("sync failed", "name", name, "elapsed", time.Since(t0))
		}
	}()
	for _, col := range collections {
		for {
			select {
			case <-t.C:
				log.Debug("waiting for sync", "name", name, "elapsed", time.Since(t0))
				continue
			case <-stop:
				return false
			case <-col:
			}
			break
		}
	}
	return true
}
