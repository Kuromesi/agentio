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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e/cluster"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
)

func TestReadyPodsFiltersAndSorts(t *testing.T) {
	client := &Client{kube: fake.NewSimpleClientset(
		readyPod("b", "10.0.0.2"),
		podWithReady("a", v1.ConditionFalse, "10.0.0.1"),
		readyPod("c", "10.0.0.3"),
		readyPod("no-ip", ""),
	)}

	pods, err := client.ReadyPods(context.Background(), "sandbox", "app=server")
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 2 {
		t.Fatalf("len(pods) = %d, want 2", len(pods))
	}
	if got := []string{pods[0].Name, pods[1].Name}; fmt.Sprint(got) != "[b c]" {
		t.Fatalf("pods = %v", got)
	}
}

func TestWaitReadyPodsObservesLaterReadiness(t *testing.T) {
	unready := podWithReady("server", v1.ConditionFalse, "10.0.0.1")
	clientset := fake.NewSimpleClientset(unready)
	listCalls := 0
	clientset.PrependReactor("list", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		listCalls++
		if listCalls == 1 {
			ready := unready.DeepCopy()
			ready.Status.Conditions[0].Status = v1.ConditionTrue
			if err := clientset.Tracker().Update(v1.SchemeGroupVersion.WithResource("pods"), ready, "sandbox"); err != nil {
				return true, nil, err
			}
			return true, &v1.PodList{Items: []v1.Pod{*unready}}, nil
		}
		return false, nil, nil
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	pods, err := (&Client{kube: clientset}).WaitReadyPods(ctx, "sandbox", "app=server", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(pods) != 1 || pods[0].Name != "server" || listCalls < 2 {
		t.Fatalf("pods = %v, list calls = %d", pods, listCalls)
	}
}

func TestReadyPodsValidatesClient(t *testing.T) {
	for name, client := range map[string]*Client{"nil receiver": nil, "nil kubernetes client": {}} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.ReadyPods(context.Background(), "sandbox", ""); err == nil {
				t.Fatal("ReadyPods() succeeded with nil client")
			}
			if _, err := client.WaitReadyPods(context.Background(), "sandbox", "", 1); err == nil {
				t.Fatal("WaitReadyPods() succeeded with nil client")
			}
		})
	}
}

func TestWaitReadyPodsValidatesMinimum(t *testing.T) {
	client := &Client{kube: fake.NewSimpleClientset()}
	for _, minimum := range []int{0, -1} {
		if _, err := client.WaitReadyPods(context.Background(), "sandbox", "", minimum); err == nil {
			t.Fatalf("WaitReadyPods() succeeded with minimum %d", minimum)
		}
	}
}

func readyPod(name, ip string) *v1.Pod { return podWithReady(name, v1.ConditionTrue, ip) }

func podWithReady(name string, status v1.ConditionStatus, ip string) *v1.Pod {
	return &v1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "sandbox", Labels: map[string]string{"app": "server"}}, Status: v1.PodStatus{PodIP: ip, Conditions: []v1.PodCondition{{Type: v1.PodReady, Status: status}}}}
}

func TestLogsUsesTypedPodLogRequest(t *testing.T) {
	var gotPath string
	var gotQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		gotPath = request.URL.Path
		gotQuery = request.URL.Query()
		_, _ = io.WriteString(response, "line one\nline two\n")
	}))
	defer server.Close()
	client := podClient(t, server.URL)
	tail := int64(25)

	logs, err := client.Logs(context.Background(), "sandbox", "client", "app", &tail)
	if err != nil {
		t.Fatal(err)
	}
	if logs != "line one\nline two\n" {
		t.Fatalf("logs = %q", logs)
	}
	if gotPath != "/api/v1/namespaces/sandbox/pods/client/log" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotQuery.Get("container") != "app" || gotQuery.Get("tailLines") != "25" {
		t.Fatalf("query = %v", gotQuery)
	}
}

func TestExecBuildsSPDYRequestWithoutKubectl(t *testing.T) {
	called := false
	var gotPath string
	var gotQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		called = true
		gotPath = request.URL.Path
		gotQuery = request.URL.Query()
		http.Error(response, "SPDY unavailable in unit test", http.StatusInternalServerError)
	}))
	defer server.Close()
	client := podClient(t, server.URL)

	_, _, err := client.Exec(context.Background(), "sandbox", "client", "app", []string{"echo", "hello"}, nil)
	if err == nil || !strings.Contains(err.Error(), "exec pod sandbox/client") {
		t.Fatalf("Exec() error = %v", err)
	}
	if !called || gotPath != "/api/v1/namespaces/sandbox/pods/client/exec" {
		t.Fatalf("called = %v, path = %q", called, gotPath)
	}
	if gotQuery.Get("container") != "app" || strings.Join(gotQuery["command"], " ") != "echo hello" {
		t.Fatalf("query = %v", gotQuery)
	}
}

func podClient(t *testing.T, host string) *Client {
	t.Helper()
	config := &rest.Config{Host: host}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	return NewClient("run-1", &cluster.Cluster{RESTConfig: config, Kube: kube}, NewLedger())
}
