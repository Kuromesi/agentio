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

package namespace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openkruise/agentio/test/e2e"
	"github.com/openkruise/agentio/test/e2e/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type Config struct {
	Prefix     string
	StableName bool
	Timeout    time.Duration
	Labels     map[string]string
}

type Instance struct {
	name   string
	record kube.ResourceRecord
}

func (i Instance) Name() string { return i.name }

func Create(t testing.TB, environment *e2e.Environment, config Config) Instance {
	t.Helper()
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := testContext(t, timeout)
	defer cancel()
	instance, cleanup, err := apply(ctx, environment, environmentClient(environment, t.Name()), t.Name(), config)
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}
	t.Cleanup(func() {
		if environment.DefersResourceCleanup() || environment.Retaining() {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cleanupCancel()
		if err := cleanup(cleanupCtx); err != nil {
			t.Errorf("delete namespace %q: %v", instance.Name(), err)
		}
	})
	return instance
}

func Apply(ctx context.Context, environment *e2e.Environment, config Config) (Instance, e2e.CleanupFunc, error) {
	return apply(ctx, environment, environmentClient(environment, ""), "", config)
}

func apply(ctx context.Context, environment *e2e.Environment, client *kube.Client, testID string, config Config) (Instance, e2e.CleanupFunc, error) {
	if environment == nil || client == nil {
		return Instance{}, nil, fmt.Errorf("namespace creation requires an e2e Kubernetes environment")
	}
	name, err := namespaceName(config)
	if err != nil {
		return Instance{}, nil, fmt.Errorf("create namespace name: %w", err)
	}
	metadata := map[string]any{"name": name}
	labels := make(map[string]any, len(config.Labels)+1)
	for key, value := range config.Labels {
		labels[key] = value
	}
	if testID != "" {
		labels[kube.TestLabel] = sanitizeLabel(testID)
	}
	if len(labels) != 0 {
		metadata["labels"] = labels
	}
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata":   metadata,
	}}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	record, err := client.Apply(waitCtx, object, kube.CreateOnly)
	if err != nil {
		return Instance{}, nil, fmt.Errorf("create namespace %q: %w", name, err)
	}
	if err := client.Wait(waitCtx, record.GVR, "", name, func(live *unstructured.Unstructured) (bool, error) {
		phase, found, err := unstructured.NestedString(live.Object, "status", "phase")
		return found && phase == "Active", err
	}); err != nil {
		return Instance{}, nil, fmt.Errorf("wait for namespace %q: %w", name, err)
	}
	instance := Instance{name: name, record: record}
	cleanup := func(cleanupCtx context.Context) error {
		if environment.Retaining() {
			return nil
		}
		return client.DeleteOwned(cleanupCtx, record)
	}
	return instance, cleanup, nil
}

func environmentClient(environment *e2e.Environment, testID string) *kube.Client {
	if environment == nil || environment.Kube == nil {
		return nil
	}
	if testID == "" {
		return environment.Kube
	}
	return environment.Kube.WithTestID(testID)
}

func namespaceName(config Config) (string, error) {
	prefix := sanitizeDNS(config.Prefix)
	if prefix == "" {
		prefix = "e2e"
	}
	if config.StableName {
		return prefix, nil
	}
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	suffix := "-" + hex.EncodeToString(random)
	if len(prefix)+len(suffix) > 63 {
		prefix = strings.TrimRight(prefix[:63-len(suffix)], "-")
	}
	return prefix + suffix, nil
}

func sanitizeDNS(value string) string {
	value = strings.ToLower(value)
	var result strings.Builder
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' {
			result.WriteRune(char)
		} else {
			result.WriteByte('-')
		}
	}
	return strings.Trim(result.String(), "-")
}

func sanitizeLabel(value string) string {
	var result strings.Builder
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_' || char == '.' {
			result.WriteRune(char)
		} else {
			result.WriteByte('-')
		}
	}
	clean := strings.Trim(result.String(), "-_.")
	if len(clean) > 63 {
		clean = strings.TrimRight(clean[:63], "-_.")
	}
	return clean
}

func testContext(t testing.TB, timeout time.Duration) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(timeout)
	if deadlineProvider, ok := t.(interface{ Deadline() (time.Time, bool) }); ok {
		if testDeadline, hasDeadline := deadlineProvider.Deadline(); hasDeadline && testDeadline.Before(deadline) {
			deadline = testDeadline
		}
	}
	return context.WithDeadline(context.Background(), deadline)
}
