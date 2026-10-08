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

package dns

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"istio.io/istio/pkg/util/sets"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/log"
)

func refreshDelay(host string, ttl, fallback time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = fallback
	}
	base := ttl - 5*time.Second
	if ttl < 10*time.Second {
		// Refresh short-lived records before expiry too; a fixed five-second
		// minimum would otherwise create a gap in valid policy addresses.
		base = max(time.Nanosecond, ttl*4/5)
	}
	jitterLimit := min(base/5, 3*time.Second)
	if jitterLimit <= 0 {
		return base
	}
	sum := sha256.Sum256([]byte(host))
	var value uint64
	for i := range 8 {
		value = value<<8 | uint64(sum[i])
	}
	return base + time.Duration(value%uint64(jitterLimit))
}

type Options struct {
	RefreshInterval time.Duration
	LookupTimeout   time.Duration
	MaxConcurrent   int
	DNSServers      []string
}

// Lookup queries one RR type. A and AAAA have independent refreshes and deadlines.
type Lookup func(context.Context, string, uint16) (LookupResult, error)

var dnsLog = log.New("dns")

var queryTypes = [2]uint16{mdns.TypeA, mdns.TypeAAAA}

// Result is the cached DNS answer published into the krt graph, keyed by hostname.
type Result struct {
	Hostname      string
	Addresses     []netip.Addr
	IPv4Error     string
	IPv6Error     string
	IPv4NameError bool
	IPv6NameError bool
}

func (r Result) ResourceName() string { return r.Hostname }

func (r Result) Equals(other Result) bool {
	return r.Hostname == other.Hostname && slices.Equal(r.Addresses, other.Addresses) &&
		r.IPv4Error == other.IPv4Error && r.IPv6Error == other.IPv6Error &&
		r.IPv4NameError == other.IPv4NameError && r.IPv6NameError == other.IPv6NameError
}

type familyCache struct {
	next      time.Time
	resolving bool
	queried   bool
	addresses []netip.Addr
	expires   time.Time
	err       string
	nameError bool
}

type entry struct {
	hostname  string
	families  [2]familyCache
	next      time.Time
	published bool
	refs      int
	index     int
	inHeap    bool
}

type lookupJob struct {
	item   *entry
	family int
}

type Resolver struct {
	ctx     context.Context
	options Options
	lookup  Lookup
	results krt.StaticCollection[Result]
	jobs    chan lookupJob
	wake    chan struct{}

	mu       sync.RWMutex
	entries  map[string]*entry
	schedule entryHeap
}

func New(ctx context.Context, options Options, lookup Lookup, collectionOptions ...krt.CollectionOption) (*Resolver, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if options.RefreshInterval <= 0 {
		options.RefreshInterval = 30 * time.Second
	}
	if options.LookupTimeout <= 0 {
		options.LookupTimeout = 5 * time.Second
	}
	if options.MaxConcurrent <= 0 {
		options.MaxConcurrent = 32
	}
	if lookup == nil {
		servers := append([]string(nil), options.DNSServers...)
		if len(servers) == 0 {
			servers = systemDNSServers()
		}
		lookup = newProtocolLookup(servers, options.LookupTimeout)
	}
	resolver := &Resolver{
		ctx:     ctx,
		options: options,
		lookup:  lookup,
		entries: make(map[string]*entry),
		results: krt.NewStaticCollection[Result](nil, nil, collectionOptions...),
		jobs:    make(chan lookupJob, options.MaxConcurrent),
		wake:    make(chan struct{}, 1),
	}
	for range options.MaxConcurrent {
		go resolver.worker()
	}
	go resolver.run()
	return resolver, nil
}

// Results exposes the hostname-keyed DNS cache for diagnostics and composition.
func (r *Resolver) Results() krt.Collection[Result] {
	return r.results
}

// HandleAdd retains a hostname while at least one policy/config object refers to
// it. Repeated references are counted so deleting one policy does not stop
// refreshes needed by another.
func (r *Resolver) HandleAdd(host string) {
	host = normalizeHostname(host)
	if host == "" {
		return
	}
	r.mu.Lock()
	item := r.entries[host]
	if item == nil {
		item = &entry{hostname: host, next: time.Now(), index: -1}
		r.entries[host] = item
	}
	item.refs++
	r.scheduleLocked(item)
	r.mu.Unlock()
	r.signalScheduler()
}

// HandleDelete releases one policy/config reference to a hostname.
func (r *Resolver) HandleDelete(host string) {
	host = normalizeHostname(host)
	if host == "" {
		return
	}
	r.mu.Lock()
	item := r.entries[host]
	if item == nil {
		r.mu.Unlock()
		return
	}
	item.refs--
	if item.refs > 0 {
		r.mu.Unlock()
		return
	}
	r.removeScheduledLocked(item)
	delete(r.entries, host)
	r.results.DeleteObject(host)
	r.mu.Unlock()
	r.signalScheduler()
}

// Resolve fetches one hostname from the krt collection and starts an
// asynchronous lookup on a cold miss. FetchOne registers a key-scoped reverse
// dependency even when the result is not present yet.
func (r *Resolver) Resolve(ctx krt.HandlerContext, host string) []netip.Addr {
	host = normalizeHostname(host)
	if host == "" {
		return nil
	}
	resolved := krt.FetchOne(ctx, r.results, krt.FilterKey(host))

	r.mu.Lock()
	item := r.entries[host]
	if item == nil {
		// Reference tracking and krt transforms run asynchronously. Make a cold
		// lookup self-starting even if the reference event has not arrived yet.
		item = &entry{hostname: host, next: time.Now(), index: -1}
		r.entries[host] = item
		r.scheduleLocked(item)
	}
	r.mu.Unlock()
	r.signalScheduler()
	if resolved == nil {
		return nil
	}
	return append([]netip.Addr(nil), resolved.Addresses...)
}

func (r *Resolver) refresh(job lookupJob) {
	r.mu.RLock()
	current := r.entries[job.item.hostname] == job.item
	r.mu.RUnlock()
	if !current {
		return
	}
	ctx, cancel := context.WithTimeout(r.ctx, r.options.LookupTimeout)
	defer cancel()
	result, err := r.lookup(ctx, job.item.hostname, queryTypes[job.family])
	r.applyAnswer(job.item, job.family, result, err, time.Now())
}

func (r *Resolver) applyAnswer(item *entry, family int, result LookupResult, err error, received time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries[item.hostname] != item {
		return
	}
	cached := &item.families[family]
	cached.resolving = false
	cached.queried = true
	delay := refreshDelay(item.hostname, time.Minute, r.options.RefreshInterval)
	if err != nil {
		// A failed refresh never extends the previous answer's expiration.
		cached.err = err.Error()
		dnsLog.Warn("DNS address family refresh failed", "hostname", item.hostname,
			"type", mdns.TypeToString[queryTypes[family]], "error", err)
	} else {
		cached.addresses = normalizeAddresses(result.Addresses)
		cached.err = ""
		cached.nameError = result.NameError
		ttl := result.TTL
		// Empty answers without an SOA use the configured negative-cache fallback.
		// Positive zero-TTL answers must not become persistent policy permissions.
		if ttl <= 0 && len(cached.addresses) == 0 {
			ttl = r.options.RefreshInterval
		}
		cached.expires = received.Add(ttl)
		delay = refreshDelay(item.hostname, ttl, r.options.RefreshInterval)
	}
	cached.next = received.Add(delay)
	if item.refs == 0 && item.families[0].err != "" && item.families[1].err != "" {
		r.removeScheduledLocked(item)
		delete(r.entries, item.hostname)
		r.results.DeleteObject(item.hostname)
		return
	}
	r.expireLocked(item, time.Now())
	r.publishLocked(item)
	r.scheduleLocked(item)
	r.signalScheduler()
}

// Expiration is also driven by the scheduler while a lookup is queued or in flight.
func (r *Resolver) expireLocked(item *entry, now time.Time) bool {
	expired := false
	for family := range item.families {
		cached := &item.families[family]
		if cached.expires.IsZero() || cached.expires.After(now) {
			continue
		}
		cached.addresses = nil
		cached.expires = time.Time{}
		cached.nameError = false
		if cached.err == "" {
			cached.err = "DNS answer expired before a successful refresh"
		}
		dnsLog.Warn("DNS address family cache expired", "hostname", item.hostname,
			"type", mdns.TypeToString[queryTypes[family]])
		expired = true
	}
	return expired
}

func (r *Resolver) publishLocked(item *entry) {
	addresses := append(slices.Clone(item.families[0].addresses), item.families[1].addresses...)
	item.published = true
	// Serialize publication with removal so a completed lookup cannot resurrect a deleted result.
	r.results.ConditionalUpdateObject(Result{
		Hostname:      item.hostname,
		Addresses:     normalizeAddresses(addresses),
		IPv4Error:     item.families[0].err,
		IPv6Error:     item.families[1].err,
		IPv4NameError: item.families[0].nameError,
		IPv6NameError: item.families[1].nameError,
	})
}

func normalizeHostname(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func normalizeAddresses(addresses []netip.Addr) []netip.Addr {
	seen := sets.NewWithLength[netip.Addr](len(addresses))
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() {
			continue
		}
		if seen.Contains(address) {
			continue
		}
		seen.Insert(address)
		result = append(result, address)
	}
	slices.SortFunc(result, func(a, b netip.Addr) int { return a.Compare(b) })
	return result
}
