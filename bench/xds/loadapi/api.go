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

// Package loadapi defines the management protocol shared by the load application
// and its runner. These types are independent of the fake ADS transport client.
package loadapi

import "encoding/json"

// Round carries a monotonic ID and an opaque, scenario-defined payload.
type Round struct {
	ID         uint64          `json:"id"`
	Parameters json.RawMessage `json:"parameters"`
}

// Sample records the resource version and client-side receive and ACK timestamps.
type Sample struct {
	ID        int    `json:"id"`
	ReceiveNS int64  `json:"receive_ns"`
	AckNS     int64  `json:"ack_ns"`
	Version   string `json:"version"`
	Bytes     int    `json:"bytes"`
}

// Status reports load process health, counters, and optional round samples.
type Status struct {
	NowNS           int64            `json:"now_ns"`
	Target          int              `json:"target"`
	Ramping         bool             `json:"ramping"`
	Connected       int64            `json:"connected"`
	Ready           int64            `json:"ready"`
	Failures        int64            `json:"failures"`
	Errors          map[string]int   `json:"errors"`
	Dials           int64            `json:"dials"`
	Responses       int64            `json:"responses"`
	ResponsesByType map[string]int64 `json:"responses_by_type"`
	Round           Round            `json:"round"`
	Received        int              `json:"received"`
	Samples         []Sample         `json:"samples"`
	HeapAlloc       uint64           `json:"heap_alloc"`
	Goroutines      int              `json:"goroutines"`
}
