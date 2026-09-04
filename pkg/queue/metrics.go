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

package queue

// queueMetric keeps queue instrumentation disabled without branching at call sites.
type queueMetric struct{}

func (queueMetric) Record(float64)  {}
func (queueMetric) RecordInt(int64) {}
func (queueMetric) Increment()      {}
func (queueMetric) Decrement()      {}

type queueMetrics struct {
	depth        queueMetric
	latency      queueMetric
	workDuration queueMetric
	id           string
}

func newQueueMetrics(id string) *queueMetrics {
	return &queueMetrics{id: id}
}
