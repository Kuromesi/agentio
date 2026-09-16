// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "github.com/openkruise/agentio/bench/xds/scenario/builtin/driver"
	"github.com/openkruise/agentio/bench/xds/scenario/driver"
)

func (r *runner) environment() driver.Environment {
	return driver.Environment{Namespace: r.id, Pods: r.pods, Kube: r.kube, Dynamic: r.dynamic, Track: func(resource driver.Resource) { r.resources = append(r.resources, resource) }}
}
