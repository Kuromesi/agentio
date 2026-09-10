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

package model

import (
	"fmt"
	"maps"
	"slices"
)

type TunnelProtocol string

const (
	TunnelProtocolNone  TunnelProtocol = "NONE"
	TunnelProtocolHBONE TunnelProtocol = "HBONE"
)

func (p TunnelProtocol) Validate() error {
	switch p {
	case "", TunnelProtocolNone, TunnelProtocolHBONE:
		return nil
	default:
		return fmt.Errorf("unsupported tunnel protocol %q", p)
	}
}

// Workload is a network endpoint with optional attester identity metadata.
// An absent Principal makes it discovery-only; authentication validates the
// Principal independently.
type Workload struct {
	UID       string
	Principal Principal

	// SourceUID identifies the current backing runtime object or activation.
	// Kubernetes supplies the Pod UID; other runtimes supply their equivalent.
	// SandboxManaged endpoints use Sandbox policies exclusively, even before a Sandbox is available.
	SandboxManaged    bool
	SourceUID         string
	Namespace         string
	Name              string
	CanonicalName     string
	CanonicalRevision string
	NodeName          string
	Addresses         []string
	Labels            map[string]string
	GatewayKey        string
	HostNetwork       bool
	TunnelProtocol    TunnelProtocol
	NativeTunnel      bool
	Ready             bool
}

func (w Workload) ResourceName() string { return w.UID }

// Equals compares all fields, preserving the distinction between nil and empty collections.
func (w Workload) Equals(other Workload) bool {
	return w.UID == other.UID &&
		w.Principal == other.Principal &&
		w.SandboxManaged == other.SandboxManaged &&
		w.SourceUID == other.SourceUID &&
		w.Namespace == other.Namespace &&
		w.Name == other.Name &&
		w.CanonicalName == other.CanonicalName &&
		w.CanonicalRevision == other.CanonicalRevision &&
		w.NodeName == other.NodeName &&
		w.GatewayKey == other.GatewayKey &&
		w.HostNetwork == other.HostNetwork &&
		w.TunnelProtocol == other.TunnelProtocol &&
		w.NativeTunnel == other.NativeTunnel &&
		w.Ready == other.Ready &&
		(w.Addresses == nil) == (other.Addresses == nil) &&
		slices.Equal(w.Addresses, other.Addresses) &&
		(w.Labels == nil) == (other.Labels == nil) &&
		maps.Equal(w.Labels, other.Labels)
}
