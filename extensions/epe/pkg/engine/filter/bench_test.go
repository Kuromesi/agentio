// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package filter

import (
	"strconv"
	"testing"
)

// benchSink defeats dead-code elimination.
var benchSink any

// BenchmarkRecordUnitAction measures the per-stream action recording. The
// engine calls this once per (unit, filter) pair that produced an observable
// action, so an action-heavy request grows with the product of units and
// filters.
//
// Each iteration records nUnits x nFilters actions into a fresh StreamInfo:
// RecordUnitAction scans Matched linearly to find the unit, so the cost of
// the last few calls depends on how many units came before them. Measuring a
// single call against a pre-filled Info would report the tail cost as if it
// were the average.
func BenchmarkRecordUnitAction(b *testing.B) {
	for _, a := range []struct{ units, filters int }{
		{1, 1},
		{4, 4},
		{16, 8},
	} {
		ids := make([]UnitID, a.units)
		for i := range ids {
			ids[i] = UnitID{Scope: "ns/profile", Name: "rule" + strconv.Itoa(i), Ordinal: i}
		}
		names := make([]string, a.filters)
		for i := range names {
			names[i] = "filter" + strconv.Itoa(i)
		}
		name := "units=" + strconv.Itoa(a.units) + "/filters=" + strconv.Itoa(a.filters)
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				info := NewStreamInfo()
				for _, id := range ids {
					for _, fname := range names {
						info.RecordUnitAction(id, fname, "mutate")
					}
				}
				benchSink = info
			}
		})
	}
}

// BenchmarkNewStreamInfo prices the per-stream allocation on its own, so it
// can be subtracted from the numbers above.
func BenchmarkNewStreamInfo(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = NewStreamInfo()
	}
}

// BenchmarkSetHeader prices the Mutation helper every mutating filter calls
// to build its return value.
func BenchmarkSetHeader(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchSink = SetHeader("x-injected-token", "Bearer abcdef0123456789")
	}
}
