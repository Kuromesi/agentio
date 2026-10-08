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

package compiler

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	workloadv1 "github.com/openkruise/agentio/api/workload/v1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

func TestWDSIdentityProjectionChecksNamespace(t *testing.T) {
	principal := mustTestPrincipal("cluster.local", "ns/demo/sa/app")
	for _, tc := range []struct {
		namespace string
		wantErr   bool
	}{
		{"demo", false}, {"other", true},
	} {
		input := wdsProjection{
			Workload: model.Workload{UID: "pod", Namespace: tc.namespace, Principal: principal},
		}
		domain, account, err := projectWorkloadIdentity(input)
		if (err != nil) != tc.wantErr {
			t.Fatalf("%+v: %v", tc, err)
		}
		if err == nil && (domain != "cluster.local" || account != "app") {
			t.Fatalf("projection: %s/%s", domain, account)
		}
	}
}

func TestWDSIncludesWorkloadIdentityFieldsAndDiscoveryAccount(t *testing.T) {
	for _, path := range []string{"ns/demo/sa/app", "cluster/test/ns/demo/workload/app"} {
		t.Run(path, func(t *testing.T) {
			principal := mustTestPrincipal("cluster.local", path)
			source := model.SourceRef{Registry: "kubernetes/test", Key: "pod-a"}
			resource, err := buildWDSAddress(wdsProjection{
				ClusterID:      "test",
				ServiceAccount: "app",
				Workload: model.Workload{
					UID:       "test//Pod/demo/app",
					Name:      "app",
					Namespace: "demo",
					Principal: principal,
					Source:    source,
					Addresses: []string{"10.0.0.1"},
				},
			})
			if err != nil || resource == nil {
				t.Fatalf("resource=%v err=%v", resource, err)
			}
			var address workloadv1.Address
			if err := resource.Value.UnmarshalTo(&address); err != nil {
				t.Fatal(err)
			}
			wire := address.GetWorkload()
			if wire.ClusterId != "test" || wire.Name != "app" {
				t.Fatalf("workload identity fields=%v", wire)
			}
			if wire.TrustDomain != "cluster.local" || wire.Namespace != "demo" || wire.ServiceAccount != "app" {
				t.Fatalf("discovery metadata changed: %v", wire)
			}
		})
	}
}

func TestWorkloadIdentityPreservesPodDiscoveryAccount(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: "app", UID: "pod-a"},
		Spec:       corev1.PodSpec{ServiceAccountName: "backend"},
	}
	pods := krt.NewStaticCollection(nil, []*corev1.Pod{pod}, krt.WithStop(t.Context().Done()))
	fixture := newIncrementalFixture(t, func(inputs *Inputs) { inputs.Pods = pods })
	workload := workloadWithSourceUID("demo", "app", "10.0.0.1", "pod-a")
	workload.Principal = mustTestPrincipal("cluster.local", "cluster/cluster/ns/demo/workload/app")
	fixture.workloads.ConditionalUpdateObject(workload)
	assertAccount := func(account string) {
		t.Helper()
		eventually(t, func() bool {
			resource := fixture.compiler.graph.resources.GetKey(addressResourceName("demo", "app"))
			if resource == nil {
				return false
			}
			var address workloadv1.Address
			if err := resource.Value.UnmarshalTo(&address); err != nil {
				return false
			}
			wire := address.GetWorkload()
			return wire.TrustDomain == "cluster.local" && wire.ClusterId == "cluster" &&
				wire.Namespace == "demo" && wire.Name == "app" && wire.ServiceAccount == account
		}, "WDS contains workload identity fields and Pod discovery account")
	}
	assertAccount("backend")
	// A replacement Pod must not supply metadata for the previous incarnation.
	replacement := pod.DeepCopy()
	replacement.UID = "pod-b"
	replacement.Spec.ServiceAccountName = "other"
	pods.ConditionalUpdateObject(replacement)
	assertAccount("")
}
