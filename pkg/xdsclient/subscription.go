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

package xdsclient

import (
	"context"
	"errors"
	"fmt"
	"sort"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
)

// DeleteAction controls the lifetime of a named subscription after deletion.
type DeleteAction uint8

const (
	// KeepSubscription continues watching for the resource to reappear.
	KeepSubscription DeleteAction = iota
	// ReleaseSubscription ends this demand; a future Demand subscribes again.
	ReleaseSubscription
)

// Each subscription is a generation. Waiters keep their generation even after
// the name has been released and reused, so they cannot miss its deletion.
type subscription struct {
	deleted bool
}

func (c *Client) wakeSubscriptions() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// deletedSubscription is called while applying a validated response under mu.
func (c *Client) deletedSubscription(st *typeState, name string) {
	sub := st.names[name]
	if sub == nil {
		return
	}
	if st.watch.OnDelete == nil || st.watch.OnDelete(name) == KeepSubscription {
		st.removed[name] = true
		return
	}
	sub.deleted = true
	delete(st.names, name)
	delete(st.removed, name)
	c.wakeSubscriptions()
}

// Demand returns a read-only resource, waiting for publication or removal. Successful
// subscriptions remain watched so later policy changes are observed. All
// concurrent waiters are notified; cancellation does not cancel other waiters.
// A released deletion ends existing waiters with ErrNotFound; a later call
// creates a new subscription, even before the old unsubscribe has been sent.
func (c *Client) Demand(ctx context.Context, typ, name string) (*Resource, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name == "" || name == "*" {
		return nil, errors.New("demand requires an exact resource name")
	}
	c.mu.Lock()
	st := c.types[typ]
	if st == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("unregistered type %q", typ)
	}
	sub := st.names[name]
	if sub == nil {
		sub = &subscription{}
		st.names[name] = sub
		delete(st.removed, name)
		c.wakeSubscriptions()
	}
	for {
		if sub.deleted {
			c.mu.Unlock()
			return nil, ErrNotFound
		}
		if st.synced {
			canonical := name
			if target, alias := st.aliases[name]; alias {
				if target == "" {
					c.mu.Unlock()
					return nil, fmt.Errorf("ambiguous resource alias %q", name)
				}
				canonical = target
			}
			if value := st.resources[canonical]; value != nil {
				result := value
				c.mu.Unlock()
				return result, nil
			}
			if st.removed[name] {
				c.mu.Unlock()
				return nil, ErrNotFound
			}
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
		c.mu.Lock()
	}
}

func (c *Client) initialRequests(sent map[string]map[string]*subscription) []*discovery.DeltaDiscoveryRequest {
	c.mu.Lock()
	initial := make([]*discovery.DeltaDiscoveryRequest, 0, len(c.types))
	for typ, st := range c.types {
		req := &discovery.DeltaDiscoveryRequest{Node: c.cfg.Node, TypeUrl: typ}
		sent[typ] = map[string]*subscription{}
		for name, sub := range st.names {
			req.ResourceNamesSubscribe = append(req.ResourceNamesSubscribe, name)
			sent[typ][name] = sub
		}
		sort.Strings(req.ResourceNamesSubscribe)
		if st.watch.Wildcard {
			req.ResourceNamesSubscribe = append(req.ResourceNamesSubscribe, "*")
		} else if len(req.ResourceNamesSubscribe) == 0 {
			// The same subscribe/unsubscribe handshake used by ztunnel prevents an
			// empty initial request from becoming an implicit wildcard subscription.
			req.ResourceNamesSubscribe = []string{"*"}
			req.ResourceNamesUnsubscribe = []string{"*"}
		}
		initial = append(initial, req)
	}
	c.mu.Unlock()
	sort.Slice(initial, func(i, j int) bool { return initial[i].TypeUrl < initial[j].TypeUrl })
	return initial
}

func (c *Client) pendingRequests(sent map[string]map[string]*subscription) []*discovery.DeltaDiscoveryRequest {
	c.mu.Lock()
	requests := []*discovery.DeltaDiscoveryRequest{}
	for typ, st := range c.types {
		req := &discovery.DeltaDiscoveryRequest{TypeUrl: typ}
		for name, sub := range st.names {
			// A new generation supersedes a pending unsubscribe. Resubscribe
			// explicitly: Delta xDS requires a response even if the server
			// still considers the old generation subscribed.
			if sent[typ][name] != sub {
				req.ResourceNamesSubscribe = append(req.ResourceNamesSubscribe, name)
				sent[typ][name] = sub
			}
		}
		for name := range sent[typ] {
			if st.names[name] == nil {
				req.ResourceNamesUnsubscribe = append(req.ResourceNamesUnsubscribe, name)
				delete(sent[typ], name)
			}
		}
		if len(req.ResourceNamesSubscribe)+len(req.ResourceNamesUnsubscribe) > 0 {
			sort.Strings(req.ResourceNamesSubscribe)
			sort.Strings(req.ResourceNamesUnsubscribe)
			requests = append(requests, req)
		}
	}
	c.mu.Unlock()

	return requests
}
