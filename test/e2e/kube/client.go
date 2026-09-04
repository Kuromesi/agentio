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
	"strings"

	"github.com/openkruise/agentio/test/e2e/cluster"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	RunLabel  = "e2e.agentio.io/run"
	TestLabel = "e2e.agentio.io/test"
)

type Client struct {
	runID        string
	testID       string
	dynamic      dynamic.Interface
	kube         kubernetes.Interface
	restConfig   *rest.Config
	mapper       meta.RESTMapper
	discovery    discovery.CachedDiscoveryInterface
	ledger       *Ledger
	fieldManager string
}

func NewClient(runID string, source *cluster.Cluster, ledger *Ledger) *Client {
	if ledger == nil {
		ledger = NewLedger()
	}
	return &Client{
		runID:        runID,
		dynamic:      source.Dynamic,
		kube:         source.Kube,
		restConfig:   source.RESTConfig,
		mapper:       source.Mapper,
		discovery:    source.Discovery,
		ledger:       ledger,
		fieldManager: "agentio-e2e",
	}
}

func (c *Client) WithTestID(testID string) *Client {
	copy := *c
	copy.testID = labelValue(testID)
	return &copy
}

func (c *Client) Ledger() *Ledger { return c.ledger }

func (c *Client) Get(ctx context.Context, gvr schema.GroupVersionResource, namespace, name string) (*unstructured.Unstructured, error) {
	return c.resource(gvr, namespace, namespace != "").Get(ctx, name, metav1.GetOptions{})
}

func labelValue(value string) string {
	var result strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9', char == '.', char == '_', char == '-':
			result.WriteRune(char)
		default:
			result.WriteByte('-')
		}
	}
	clean := strings.Trim(result.String(), "-._")
	if len(clean) > 63 {
		clean = strings.TrimRight(clean[:63], "-._")
	}
	return clean
}
