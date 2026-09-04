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
	"errors"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

func (c *Client) Wait(
	ctx context.Context,
	gvr schema.GroupVersionResource,
	namespace, name string,
	predicate func(*unstructured.Unstructured) (bool, error),
) error {
	if predicate == nil {
		return errors.New("wait predicate is required")
	}
	resource := c.resource(gvr, namespace, namespace != "")
	live, err := resource.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get %s %s/%s while waiting: %w", gvr.Resource, namespace, name, err)
	}
	done, err := predicate(live)
	if err != nil || done {
		return err
	}
	watcher, err := resource.Watch(ctx, metav1.ListOptions{
		FieldSelector:   fields.OneTermEqualSelector("metadata.name", name).String(),
		ResourceVersion: live.GetResourceVersion(),
	})
	if err == nil {
		defer watcher.Stop()
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("wait for %s %s/%s: %w", gvr.Resource, namespace, name, ctx.Err())
			case event, open := <-watcher.ResultChan():
				if !open {
					return c.poll(ctx, resource, gvr, namespace, name, predicate)
				}
				if event.Type == watch.Error {
					return c.poll(ctx, resource, gvr, namespace, name, predicate)
				}
				object, ok := event.Object.(*unstructured.Unstructured)
				if !ok || object.GetName() != name {
					continue
				}
				done, err := predicate(object)
				if err != nil || done {
					return err
				}
			}
		}
	}
	return c.poll(ctx, resource, gvr, namespace, name, predicate)
}

func (c *Client) poll(
	ctx context.Context,
	resource dynamic.ResourceInterface,
	gvr schema.GroupVersionResource,
	namespace, name string,
	predicate func(*unstructured.Unstructured) (bool, error),
) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for %s %s/%s: %w", gvr.Resource, namespace, name, ctx.Err())
		case <-ticker.C:
			object, err := resource.Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			done, err := predicate(object)
			if err != nil || done {
				return err
			}
		}
	}
}
