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

package xds

import (
	"errors"
	"maps"
	"sort"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/model"
)

// maxSubscriptionNames caps named subscriptions per watch to bound per-connection memory.
const maxSubscriptionNames = 10000

var errTooManySubscribedNames = errors.New("subscription exceeds the resource name limit")

type watchState struct {
	wildcard bool
	names    sets.Set[string]
	sent     map[string]string
	nonce    string
	started  bool
	// denied tracks refused names so each refusal is logged once per stream.
	denied sets.Set[string]
}

func sortedNames(names sets.Set[string]) []string {
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func applySubscription(watch *watchState, request *discoveryv3.DeltaDiscoveryRequest) (bool, error) {
	changed := !watch.started
	insertName := func(name string) error {
		if watch.names.Contains(name) {
			return nil
		}
		if len(watch.names) >= maxSubscriptionNames {
			return errTooManySubscribedNames
		}
		watch.names.Insert(name)
		return nil
	}
	if !watch.started {
		watch.started = true
		watch.wildcard = len(request.GetResourceNamesSubscribe()) == 0 && implicitWildcardTypeURL(request.GetTypeUrl())
		maps.Copy(watch.sent, request.GetInitialResourceVersions())
		if !watch.wildcard {
			for name := range request.GetInitialResourceVersions() {
				if err := insertName(name); err != nil {
					return changed, err
				}
			}
		}
	}
	for _, name := range request.GetResourceNamesSubscribe() {
		if name == "*" {
			if !watch.wildcard {
				changed = true
			}
			watch.wildcard = true
			continue
		}
		if !watch.names.Contains(name) {
			changed = true
		}
		if err := insertName(name); err != nil {
			return changed, err
		}
	}
	for _, name := range request.GetResourceNamesUnsubscribe() {
		if name == "*" {
			if watch.wildcard {
				changed = true
			}
			watch.wildcard = false
			continue
		}
		if watch.names.Contains(name) {
			changed = true
		}
		watch.names.Delete(name)
	}
	return changed, nil
}

func implicitWildcardTypeURL(typeURL string) bool {
	switch typeURL {
	case model.SecretType, model.EndpointType, model.RouteType, model.ExtensionConfigurationType:
		return false
	default:
		return true
	}
}
