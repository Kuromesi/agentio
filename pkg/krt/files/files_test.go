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

package files_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"

	v1 "k8s.io/api/core/v1"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"

	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/test/util/file"

	"github.com/openkruise/agentio/pkg/krt"
	krtfiles "github.com/openkruise/agentio/pkg/krt/files"
	"github.com/openkruise/agentio/pkg/kube/controllers"
)

func TestFilesCollection(t *testing.T) {
	stop := test.NewStop(t)
	root := t.TempDir()

	file.WriteOrFail(t, filepath.Join(root, "cm.yaml"), []byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: test
  namespace: default`))

	fw, err := krtfiles.NewFolderWatch[controllers.Object](root, func(b []byte) ([]controllers.Object, error) {
		return parseInputs(bytes.NewReader(b))
	}, stop)
	assert.NoError(t, err)

	col := newKubernetesFromFiles[*v1.ConfigMap](fw, krt.WithStop(stop))
	col.WaitUntilSynced(test.NewStop(t))
	tt := assert.NewTracker[string](t)
	col.Register(TrackerHandler[*v1.ConfigMap](tt))
	tt.WaitOrdered("add/default/test")

	file.WriteOrFail(t, filepath.Join(root, "cm2.yaml"), []byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: test2
  namespace: default`))
	tt.WaitOrdered("add/default/test2")

	file.WriteOrFail(t, filepath.Join(root, "cm.yaml"), []byte(``))
	tt.WaitOrdered("delete/default/test")
}

func newKubernetesFromFiles[T controllers.Object](
	fw *krtfiles.FolderWatch[controllers.Object],
	opts ...krt.CollectionOption,
) krt.Collection[T] {
	return krtfiles.NewFileCollection[controllers.Object, T](fw, func(f controllers.Object) *T {
		if t, ok := f.(T); ok {
			return &t
		}
		return nil
	}, opts...)
}

// The upstream scenario uses only ConfigMaps; decode those fixtures without
// importing Istio's Kubernetes client and complete resource schema registry.
func parseInputs(f io.Reader) ([]controllers.Object, error) {
	decoder := yamlutil.NewYAMLOrJSONDecoder(f, 4096)
	var objects []controllers.Object
	for {
		var cm v1.ConfigMap
		if err := decoder.Decode(&cm); err != nil {
			if errors.Is(err, io.EOF) {
				return objects, nil
			}
			return nil, err
		}
		if cm.Name != "" {
			objects = append(objects, &cm)
		}
	}
}

func TrackerHandler[T any](tracker *assert.Tracker[string]) func(krt.Event[T]) {
	return func(o krt.Event[T]) {
		tracker.Record(fmt.Sprintf("%v/%v", o.Event, krt.GetKey(o.Latest())))
	}
}
