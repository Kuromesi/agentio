// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0

// Package driver imports the built-in Kubernetes drivers for self-registration.
package driver

import (
	_ "github.com/openkruise/agentio/bench/xds/scenario/discovery/driver"
	_ "github.com/openkruise/agentio/bench/xds/scenario/trafficpolicy/driver"
)
