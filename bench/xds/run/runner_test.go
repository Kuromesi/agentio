// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openkruise/agentio/bench/xds/loadapi"
	"github.com/openkruise/agentio/bench/xds/scenario/driver"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func testConfig(t *testing.T) config {
	t.Helper()
	c, err := parseConfig([]string{"--context=test", "--image=test", "--xds-address=cp:15012", "--server-name=cp", "--ca-namespace=system"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCanceledCreateStillCleansPersistedNamespace(t *testing.T) {
	c := testConfig(t)
	k := kubefake.NewClientset(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: c.CAConfigMap, Namespace: c.CANamespace}, Data: map[string]string{c.CAKey: "test-ca"}})
	r := &runner{cfg: c, id: "ads-bench-test", out: t.TempDir(), kube: k, dynamic: dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())}
	k.PrependReactor("create", "namespaces", func(action ktesting.Action) (bool, runtime.Object, error) {
		ns := action.(ktesting.CreateAction).GetObject().(*corev1.Namespace).DeepCopy()
		ns.UID = "persisted-uid"
		if err := k.Tracker().Add(ns); err != nil {
			t.Fatal(err)
		}
		return true, nil, context.Canceled // API persisted the object before cancellation reached the client.
	})
	var deleteUID string
	k.PrependReactor("delete", "namespaces", func(action ktesting.Action) (bool, runtime.Object, error) {
		options := action.(ktesting.DeleteAction).GetDeleteOptions()
		if options.Preconditions != nil && options.Preconditions.UID != nil {
			deleteUID = string(*options.Preconditions.UID)
		}
		return false, nil, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.execute(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if deleteUID != "persisted-uid" {
		t.Fatalf("missing UID precondition: %q", deleteUID)
	}
	if _, err := k.CoreV1().Namespaces().Get(context.Background(), r.id, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("namespace leaked: %v", err)
	}
	if len(r.result.Cleanup.Errors) != 0 {
		t.Fatal(r.result.Cleanup.Errors)
	}
	if _, err := os.Stat(filepath.Join(r.out, "results.json")); err != nil {
		t.Fatal(err)
	}
}

func TestCleanupPreservesForeignNamespaceAndStillDeletesTrackedResource(t *testing.T) {
	c := testConfig(t)
	id := "ads-bench-test"
	k := kubefake.NewClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: id, UID: "foreign", Labels: map[string]string{runLabel: "different-run"}}})
	gvr := schema.GroupVersionResource{Group: "example.io", Version: "v1", Resource: "testresources"}
	p := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "example.io/v1", "kind": "TestResource", "metadata": map[string]any{"name": id, "labels": map[string]any{runLabel: id}}}}
	p.SetUID("resource-uid")
	d := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme(), p)
	r := &runner{cfg: c, id: id, kube: k, dynamic: d, namespaceAttempted: true, resources: []driver.Resource{{GVR: gvr, Name: id}}}
	if err := r.cleanup(context.Background()); err == nil {
		t.Fatal("expected ownership error")
	}
	if _, err := k.CoreV1().Namespaces().Get(context.Background(), id, metav1.GetOptions{}); err != nil {
		t.Fatal("deleted foreign namespace", err)
	}
	if _, err := d.Resource(gvr).Get(context.Background(), id, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("owned resource was not cleaned", err)
	}
}

func TestKeepResourcesStopsForwardWithoutDeletingNamespace(t *testing.T) {
	c := testConfig(t)
	c.KeepResources = true
	k := kubefake.NewClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ads-bench-test", Labels: map[string]string{runLabel: "ads-bench-test"}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { <-ctx.Done(); close(done) }()
	r := &runner{cfg: c, id: "ads-bench-test", kube: k, namespaceAttempted: true, forwards: []forwardHandle{{cancel: cancel, done: done}}}
	if err := r.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := k.CoreV1().Namespaces().Get(context.Background(), r.id, metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestWaitDeadlineCancelsBlockedHTTPRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { <-req.Context().Done() }))
	defer server.Close()
	r := &runner{http: server.Client()}
	started := time.Now()
	err := waitFor(context.Background(), 100*time.Millisecond, func(ctx context.Context) (bool, error) { return false, r.request(ctx, server.URL, nil, nil) })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("operation did not respect round deadline")
	}
}

func sampleStatuses() []loadapi.Status {
	result := make([]loadapi.Status, 2)
	for i := range result {
		n := targetFor(5, 2, i)
		result[i] = loadapi.Status{Target: n, Ready: int64(n)}
		for id := 0; id < n; id++ {
			result[i].Samples = append(result[i].Samples, loadapi.Sample{ID: id, Version: "v1", Bytes: 10, ReceiveNS: 100, AckNS: 120})
		}
	}
	return result
}
func TestSamplesRequireCompletePerPodCoverage(t *testing.T) {
	pods := []string{"one", "two"}
	clocks := []calibration{{OffsetNS: 10}, {OffsetNS: -10}}
	samples, err := collectSamples(5, pods, sampleStatuses(), clocks)
	if err != nil {
		t.Fatal(err)
	}
	if samples[0].ReceiveCorrectedNS != 90 || samples[3].AckCorrectedNS != 130 {
		t.Fatal("clock correction incorrect")
	}
	for name, corrupt := range map[string]func([]loadapi.Status){
		"duplicate": func(s []loadapi.Status) { s[0].Samples[1].ID = 0 },
		"missing":   func(s []loadapi.Status) { s[1].Samples = s[1].Samples[:1] },
		"timestamp": func(s []loadapi.Status) { s[0].Samples[0].AckNS = 99 },
	} {
		t.Run(name, func(t *testing.T) {
			s := sampleStatuses()
			corrupt(s)
			if _, err := collectSamples(5, pods, s, clocks); err == nil {
				t.Fatal("corrupt samples accepted")
			}
		})
	}
}
