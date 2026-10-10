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

package trafficpolicy

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	ext "github.com/openkruise/agentio/api/extensions/v1"
	sec "github.com/openkruise/agentio/api/security/v1"
	workload "github.com/openkruise/agentio/api/workload/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
	"github.com/openkruise/agentio/extensions/epe/pkg/store"
	"github.com/openkruise/agentio/pkg/model"
)

// NamedPolicy preserves the resource name and binding order for compilation.
type NamedPolicy struct {
	Name   string
	Policy *sec.TrafficPolicy
}

// Resources is the request-side store contract; backend transport is not exposed.
type Resources interface {
	Snapshot() *store.Snapshot
	Fetch(context.Context, store.Key) (*store.Resource, error)
}

type policySnapshot struct {
	Workload        *workload.Workload
	TrafficPolicies []NamedPolicy
	entry           *indexedWorkload
}

// lookup holds one view. Only an unresolved dependency requires another view,
// after Fetch has immediately published the newly acquired resource.
func lookup(ctx context.Context, source Resources, pod inputs.Pod) (policySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return policySnapshot{}, err
	}
	result, err := lookupSnapshot(source.Snapshot(), pod)
	if err == nil {
		return result, nil
	}
	var missing *store.MissingResource
	if !errors.As(err, &missing) {
		return policySnapshot{}, err
	}
	err = wait.PollUntilContextTimeout(
		ctx,
		10*time.Millisecond,
		time.Second,
		true,
		func(ctx context.Context) (bool, error) {
			resource, err := source.Fetch(ctx, missing.Key)
			if err != nil {
				return false, err
			}
			if resource == nil {
				return false, missing
			}
			result, err = lookupSnapshot(source.Snapshot(), pod)
			if errors.As(err, &missing) {
				return false, nil
			}
			return err == nil, err
		},
	)
	return result, err
}

func lookupSnapshot(view *store.Snapshot, pod inputs.Pod) (policySnapshot, error) {
	if !view.Ready() {
		return policySnapshot{}, fmt.Errorf("egress resources are not synchronized")
	}
	index := view.Query(store.TrafficPolicy).(*queryIndex)
	entry, err := index.forSubject(store.Subject{Namespace: pod.Namespace, Name: pod.Name})
	if err != nil {
		return policySnapshot{}, err
	}
	return policySnapshot{
		Workload:        entry.workload.Value.(*workload.Workload),
		TrafficPolicies: entry.named,
		entry:           entry,
	}, nil
}

func references(w *workload.Workload) ([]string, error) {
	var found *ext.PolicyReference
	for _, e := range w.Extensions {
		if e.Name != "traffic-policy-reference" {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("duplicate TrafficPolicy reference")
		}
		found = &ext.PolicyReference{}
		if e.Config == nil {
			return nil, fmt.Errorf("missing TrafficPolicy reference payload")
		}
		if err := e.Config.UnmarshalTo(found); err != nil {
			return nil, err
		}
		if found.TypeUrl != model.TrafficPolicyType {
			return nil, fmt.Errorf("unexpected TrafficPolicy reference type %q", found.TypeUrl)
		}
	}
	if found == nil {
		return nil, fmt.Errorf("native TrafficPolicy binding missing")
	}
	seen := map[string]bool{}
	for _, name := range found.ResourceNames {
		if name == "" || seen[name] {
			return nil, fmt.Errorf("invalid TrafficPolicy reference %q", name)
		}
		seen[name] = true
	}
	return found.ResourceNames, nil
}
