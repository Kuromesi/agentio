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

const (
	// Agentio floors max-age reaper wakes to batch close-spaced SDS pushes.
	// Certificate renewal and expiry deadlines are never floored.
	minCertificateEvictionInterval = 30 * time.Second
)

type certificateEvictionReason uint8

const (
	certificateEvictionRenewal certificateEvictionReason = iota
	certificateEvictionExpiry
	certificateEvictionMaxAge
)

// certificateCacheEntry couples a cached certificate to its heap position.
// The issuer mutex owns entries and their indexes.
type certificateCacheEntry struct {
	domain              string
	certificate         SignedCertificate
	insertedAt          time.Time
	deadline            time.Time
	reason              certificateEvictionReason
	certificateDeadline time.Time
	certificateReason   certificateEvictionReason
	maxAgeDeferred      bool
	index               int
}

func newCertificateCacheEntry(
	domain string,
	certificate SignedCertificate,
	insertedAt time.Time,
	options OnDemandOptions,
) *certificateCacheEntry {
	certificateDeadline, certificateReason := certificateEvictionDeadline(certificate, options.RenewBefore)
	entry := &certificateCacheEntry{
		domain:              domain,
		certificate:         certificate,
		insertedAt:          insertedAt,
		deadline:            certificateDeadline,
		reason:              certificateReason,
		certificateDeadline: certificateDeadline,
		certificateReason:   certificateReason,
		index:               -1,
	}
	if options.CacheMaxAge > 0 {
		maxAgeDeadline := insertedAt.Add(options.CacheMaxAge)
		if maxAgeDeadline.Before(entry.deadline) {
			entry.deadline = maxAgeDeadline
			entry.reason = certificateEvictionMaxAge
		}
	}
	return entry
}

func certificateEvictionDeadline(certificate SignedCertificate, renewBefore time.Duration) (time.Time, certificateEvictionReason) {
	fullLifetime := certificate.NotAfter.Sub(certificate.SignedAt)
	if fullLifetime > 0 && fullLifetime < renewBefore {
		return certificate.NotAfter, certificateEvictionExpiry
	}
	return certificate.NotAfter.Add(-renewBefore), certificateEvictionRenewal
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
