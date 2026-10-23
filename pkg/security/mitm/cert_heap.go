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

package mitm

import "time"

// certificateCacheEntry couples a local cache entry to its heap position.
// This deadline has no effect on certificates already sent through SDS.
type certificateCacheEntry struct {
	domain      string
	certificate SignedCertificate
	deadline    time.Time
	index       int
}

func newCertificateCacheEntry(
	domain string,
	certificate SignedCertificate,
	insertedAt time.Time,
	options OnDemandOptions,
) *certificateCacheEntry {
	deadline := certificate.NotAfter.Add(-options.RenewBefore)
	if options.CacheMaxAge > 0 && insertedAt.Add(options.CacheMaxAge).Before(deadline) {
		deadline = insertedAt.Add(options.CacheMaxAge)
	}
	return &certificateCacheEntry{domain: domain, certificate: certificate, deadline: deadline, index: -1}
}

// certHeap orders cache entries by their next effective eviction deadline.
type certHeap []*certificateCacheEntry

func (h certHeap) Len() int { return len(h) }
func (h certHeap) Less(i, j int) bool {
	if h[i].deadline.Equal(h[j].deadline) {
		return h[i].domain < h[j].domain
	}
	return h[i].deadline.Before(h[j].deadline)
}
func (h certHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *certHeap) Push(value any) {
	entry := value.(*certificateCacheEntry)
	entry.index = len(*h)
	*h = append(*h, entry)
}

func (h *certHeap) Pop() any {
	old := *h
	last := len(old) - 1
	entry := old[last]
	entry.index = -1
	old[last] = nil
	*h = old[:last]
	return entry
}
