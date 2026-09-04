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

package e2e

import (
	"sync/atomic"

	"github.com/openkruise/agentio/test/e2e/artifacts"
	"github.com/openkruise/agentio/test/e2e/cluster"
	"github.com/openkruise/agentio/test/e2e/command"
	"github.com/openkruise/agentio/test/e2e/kube"
)

type Environment struct {
	RunID     string
	Cluster   *cluster.Cluster
	Kube      *kube.Client
	Artifacts *artifacts.Store
	Commands  command.Interface
	State     *EnvironmentState

	retaining atomic.Bool
	retain    RetainPolicy
}

func (e *Environment) Retaining() bool {
	return e != nil && e.retaining.Load()
}

// DefersResourceCleanup reports whether per-test cleanup must leave Kubernetes
// resources in the ownership ledger for the Suite to handle after it knows the
// final test result. This is required for on-failure retention: testing.T
// cleanups run before testing.M.Run returns the failure code.
func (e *Environment) DefersResourceCleanup() bool {
	return e != nil && (e.retain == RetainOnFailure || e.retain == RetainAlways)
}

func (e *Environment) setRetaining(value bool) {
	e.retaining.Store(value)
}
