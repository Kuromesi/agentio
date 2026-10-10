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

// Package xdsclient implements reusable Delta ADS watches and on-demand lookups.
// The subscription and publication ordering follows ztunnel/src/xds/client.rs.
// Unlike Istio adsc, it accepts explicit wire type URLs (including aliases) and
// concurrent demand callers. Transport credentials belong to the caller.
package xdsclient

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"k8s.io/apimachinery/pkg/util/wait"

	agentlog "github.com/openkruise/agentio/pkg/log"
)

var log = agentlog.New("xdsclient")

// ErrNotFound indicates an explicitly removed resource.
var ErrNotFound = errors.New("xDS resource removed or unavailable")

// Watch with Wildcard=false starts with no resources; Demand adds named watches.
// Validate is called before publishing the entire response. It must not mutate value.
type Watch struct {
	TypeURL  string
	Wildcard bool
	Validate func(value *anypb.Any) error
}

// Config defines the node identity and initial watches.
type Config struct {
	Node    *core.Node
	Watches []Watch
	// MaxNames bounds retained on-demand subscriptions per type. Default: 10000.
	MaxNames int
}

// Snapshot is a caller-owned, consistent view across types. Synced is reset on
// disconnect or NACK. Resource versions are not resumed: reconnect obtains a
// fresh snapshot, avoiding authorization from stale state after an outage.
type Snapshot struct {
	Resources map[string]map[string]*anypb.Any
	Synced    map[string]bool
	Changed   <-chan struct{}
}
type typeState struct {
	watch           Watch
	names           map[string]bool
	removed         map[string]bool
	aliases         map[string]string
	resourceAliases map[string][]string
	resources       map[string]*anypb.Any
	synced          bool
}

// Client maintains synchronized Delta ADS resources and named subscriptions.
type Client struct {
	ads     discovery.AggregatedDiscoveryServiceClient
	cfg     Config
	mu      sync.Mutex
	types   map[string]*typeState
	changed chan struct{}
	wake    chan struct{}
	running atomic.Bool
}

// New creates a client; call Run to start receiving resources.
func New(conn grpc.ClientConnInterface, cfg Config) (*Client, error) {
	if conn == nil || cfg.Node == nil || cfg.Node.Id == "" || len(cfg.Watches) == 0 {
		return nil, errors.New("xDS connection, node ID and watches are required")
	}
	if cfg.MaxNames <= 0 {
		cfg.MaxNames = 10000
	}
	cfg.Node = proto.Clone(cfg.Node).(*core.Node)
	c := &Client{
		ads:     discovery.NewAggregatedDiscoveryServiceClient(conn),
		cfg:     cfg,
		types:   map[string]*typeState{},
		changed: make(chan struct{}),
		wake:    make(chan struct{}, 1),
	}
	for _, w := range cfg.Watches {
		if w.TypeURL == "" || c.types[w.TypeURL] != nil {
			return nil, fmt.Errorf("invalid or duplicate watch %q", w.TypeURL)
		}
		c.types[w.TypeURL] = &typeState{
			watch:           w,
			names:           map[string]bool{},
			removed:         map[string]bool{},
			aliases:         map[string]string{},
			resourceAliases: map[string][]string{},
			resources:       map[string]*anypb.Any{},
		}
	}
	return c, nil
}

func (c *Client) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

// Observe returns readiness and the signal closed by the next cache update.
// Both are captured under the same lock, without copying resource payloads.
func (c *Client) Observe(types ...string) (<-chan struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, typ := range types {
		st := c.types[typ]
		if st == nil || !st.synced {
			return c.changed, false
		}
	}
	return c.changed, true
}

// Snapshot returns a deep copy of the currently published resources.
func (c *Client) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Snapshot{
		Resources: map[string]map[string]*anypb.Any{},
		Synced:    map[string]bool{},
		Changed:   c.changed,
	}
	for typ, st := range c.types {
		s.Synced[typ] = st.synced
		s.Resources[typ] = map[string]*anypb.Any{}
		for name, r := range st.resources {
			s.Resources[typ][name] = proto.Clone(r).(*anypb.Any)
		}
	}
	return s
}

// Demand subscribes once and waits for publication or removal. Successful
// subscriptions remain watched so later policy changes are observed. All
// concurrent waiters are notified; cancellation does not cancel other waiters.
func (c *Client) Demand(ctx context.Context, typ, name string) (*anypb.Any, error) {
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
	if !st.names[name] {
		if len(st.names) >= c.cfg.MaxNames {
			c.mu.Unlock()
			return nil, errors.New("xDS demand subscription limit reached")
		}
		st.names[name] = true
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
	for {
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
				result := proto.Clone(value).(*anypb.Any)
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

func (c *Client) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range c.types {
		st.synced = false
		st.resources = map[string]*anypb.Any{}
		st.removed = map[string]bool{}
		st.aliases = map[string]string{}
		st.resourceAliases = map[string][]string{}
	}
	c.notifyLocked()
}

// Run owns the stream until cancellation, reconnecting with bounded backoff.
// Only one Run may be active. The caller retains ownership of the gRPC connection.
func (c *Client) Run(ctx context.Context) error {
	if !c.running.CompareAndSwap(false, true) {
		return errors.New("xDS client already running")
	}
	defer c.running.Store(false)
	defer c.reset()
	initialBackoff := wait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   2,
		Jitter:   0.2,
		Cap:      5 * time.Second,
		// Steps bounds growth, not reconnect attempts. Growth stops at Cap.
		Steps: math.MaxInt,
	}
	backoff := initialBackoff
	for ctx.Err() == nil {
		started := time.Now()
		received, err := c.runStream(ctx)
		c.reset()
		if ctx.Err() != nil {
			break
		}
		if received && time.Since(started) > time.Second {
			backoff = initialBackoff
		}
		delay := backoff.Step()
		log.Warn("xDS stream disconnected", "error", err, "retry", delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

type response struct {
	value *discovery.DeltaDiscoveryResponse
	err   error
}

func (c *Client) runStream(parent context.Context) (bool, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stream, err := c.ads.DeltaAggregatedResources(ctx, grpc.MaxCallRecvMsgSize(16<<20))
	if err != nil {
		return false, err
	}
	sent := map[string]map[string]bool{}
	initial := c.initialRequests(sent)
	for _, req := range initial {
		if err := stream.Send(req); err != nil {
			return false, err
		}
	}
	replies := make(chan response)
	go func() {
		for {
			r, err := stream.Recv()
			select {
			case replies <- response{r, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	received := false
	for {
		select {
		case <-ctx.Done():
			return received, ctx.Err()
		case <-c.wake:
			requests := c.pendingRequests(sent)
			for _, req := range requests {
				if err := stream.Send(req); err != nil {
					return received, err
				}
			}
		case reply := <-replies:
			if reply.err != nil {
				return received, reply.err
			}
			r := reply.value
			ack := &discovery.DeltaDiscoveryRequest{TypeUrl: r.TypeUrl, ResponseNonce: r.Nonce}
			if err := c.apply(r); err != nil {
				ack.ErrorDetail = &rpcstatus.Status{Code: int32(codes.InvalidArgument), Message: err.Error()}
			} else {
				received = true
			}
			if err := stream.Send(ack); err != nil {
				return received, err
			}
			if ack.ErrorDetail != nil {
				return received, fmt.Errorf("xDS response rejected: %s", ack.ErrorDetail.Message)
			}
		}
	}
}

func (c *Client) apply(r *discovery.DeltaDiscoveryResponse) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.types[r.TypeUrl]
	if st == nil {
		return fmt.Errorf("unregistered response type %q", r.TypeUrl)
	}
	fail := func(err error) error {
		st.synced = false
		c.notifyLocked()
		return err
	}
	if err := validateResponse(r, st.watch); err != nil {
		return fail(err)
	}
	// Workloads sharing a host-network IP can legitimately share an alias.
	// Keep canonical resources; demanding an ambiguous alias fails closed.
	resourceAliases := maps.Clone(st.resourceAliases)
	for _, res := range r.Resources {
		resourceAliases[res.Name] = append([]string(nil), res.Aliases...)
	}
	for _, name := range r.RemovedResources {
		delete(resourceAliases, name)
	}
	aliases := map[string]string{}
	for name, values := range resourceAliases {
		for _, alias := range values {
			if existing, ok := aliases[alias]; ok && existing != name {
				aliases[alias] = ""
			} else {
				aliases[alias] = name
			}
		}
	}
	for alias := range st.aliases {
		if _, exists := aliases[alias]; !exists && st.names[alias] {
			st.removed[alias] = true
		}
	}
	st.aliases = aliases
	for _, res := range r.Resources {
		st.resources[res.Name] = proto.Clone(res.Resource).(*anypb.Any)
		st.resourceAliases[res.Name] = append([]string(nil), res.Aliases...)
		for _, alias := range res.Aliases {
			delete(st.removed, alias)
		}
		delete(st.removed, res.Name)
	}
	for _, name := range r.RemovedResources {
		delete(st.resources, name)
		delete(st.resourceAliases, name)
		if st.names[name] {
			st.removed[name] = true
		}
	}
	st.synced = true
	c.notifyLocked()
	return nil
}

func (c *Client) initialRequests(sent map[string]map[string]bool) []*discovery.DeltaDiscoveryRequest {
	c.mu.Lock()
	initial := make([]*discovery.DeltaDiscoveryRequest, 0, len(c.types))
	for typ, st := range c.types {
		req := &discovery.DeltaDiscoveryRequest{Node: c.cfg.Node, TypeUrl: typ}
		sent[typ] = map[string]bool{}
		for name := range st.names {
			req.ResourceNamesSubscribe = append(req.ResourceNamesSubscribe, name)
			sent[typ][name] = true
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

func (c *Client) pendingRequests(sent map[string]map[string]bool) []*discovery.DeltaDiscoveryRequest {
	c.mu.Lock()
	requests := []*discovery.DeltaDiscoveryRequest{}
	for typ, st := range c.types {
		req := &discovery.DeltaDiscoveryRequest{TypeUrl: typ}
		for name := range st.names {
			if !sent[typ][name] {
				req.ResourceNamesSubscribe = append(req.ResourceNamesSubscribe, name)
				sent[typ][name] = true
			}
		}
		if len(req.ResourceNamesSubscribe) > 0 {
			sort.Strings(req.ResourceNamesSubscribe)
			requests = append(requests, req)
		}
	}
	c.mu.Unlock()

	return requests
}

func validateResponse(r *discovery.DeltaDiscoveryResponse, watch Watch) error {
	seen := map[string]bool{}
	for _, res := range r.Resources {
		if res == nil || res.Name == "" || res.Resource == nil || res.Resource.TypeUrl != r.TypeUrl || res.Ttl != nil {
			return errors.New("invalid resource or unsupported TTL")
		}
		if seen[res.Name] {
			return fmt.Errorf("duplicate resource %q", res.Name)
		}
		for _, alias := range res.Aliases {
			if alias == "" || alias == "*" {
				return fmt.Errorf("invalid alias %q", alias)
			}
		}
		seen[res.Name] = true
		if watch.Validate != nil {
			if err := watch.Validate(res.Resource); err != nil {
				return err
			}
		}
	}
	for _, name := range r.RemovedResources {
		if name == "" || seen[name] {
			return errors.New("invalid or conflicting removed resource")
		}
		seen[name] = true
	}
	return nil
}
