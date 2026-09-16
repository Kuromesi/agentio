// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

// Package builtin imports the built-in client scenarios for self-registration.
// Add new client packages here; keep Kubernetes driver imports in builtin/driver.
package builtin

import (
	_ "github.com/openkruise/agentio/bench/xds/scenario/discovery"
	_ "github.com/openkruise/agentio/bench/xds/scenario/trafficpolicy"
)
