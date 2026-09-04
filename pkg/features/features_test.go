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

package features

import (
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/test"
)

func TestRegisteredEnvironmentVariablesUseAgentioNamespace(t *testing.T) {
	for _, variable := range env.VarDescriptions() {
		if !strings.HasPrefix(variable.Name, "AGENTIO_") {
			t.Errorf("registered environment variable %q does not use the Agentio namespace", variable.Name)
		}
	}
}

func TestValidateDomains(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*testing.T)
		wantErr string
	}{
		{
			name: "xds",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &KRTDebounceAfter, time.Duration(0))
			},
			wantErr: "KRT debounce quiet period",
		},
		{
			name: "xds max server connection age",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &MaxServerConnectionAge, -time.Second)
			},
			wantErr: "max server connection age",
		},
		{
			name: "networking",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &GatewayRootCAPath, "certs/root.pem")
			},
			wantErr: "gateway root CA path must be absolute",
		},
		{
			name: "ca rotation",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &CARootLifetime, time.Duration(0))
			},
			wantErr: "invalid CA rotation durations",
		},
		{
			name: "mitm",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &MITMSignMode, "unsupported")
			},
			wantErr: "unsupported MITM sign mode",
		},
		{
			name: "workload certificates",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &WorkloadCertRenewBefore, 2*time.Hour)
			},
			wantErr: "invalid workload certificate durations",
		},
		{
			name: "control plane",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &TokenAudience, " ")
			},
			wantErr: "token audience is required",
		},
		{
			name: "gateway deployer",
			mutate: func(t *testing.T) {
				test.SetForTest(t, &EnableGatewayDeployer, true)
				test.SetForTest(t, &GatewayLeaseName, " ")
			},
			wantErr: "gateway deployer lease name is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidFeatures(t)
			tt.mutate(t)
			if err := Validate(); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAllowsDisabledMaxServerConnectionAge(t *testing.T) {
	setValidFeatures(t)
	test.SetForTest(t, &MaxServerConnectionAge, time.Duration(0))
	if err := Validate(); err != nil {
		t.Fatalf("Validate() rejected disabled max server connection age: %v", err)
	}
}

func TestValidatePreservesFirstErrorOrder(t *testing.T) {
	setValidFeatures(t)
	test.SetForTest(t, &KRTDebounceAfter, time.Duration(0))
	test.SetForTest(t, &GatewayConnectTimeout, time.Duration(0))

	if err := Validate(); err == nil || !strings.Contains(err.Error(), "KRT debounce quiet period") {
		t.Fatalf("Validate() error = %v, want KRT validation before networking validation", err)
	}
}

func setValidFeatures(t *testing.T) {
	t.Helper()
	test.SetForTest(t, &KRTDebounceAfter, time.Millisecond)
	test.SetForTest(t, &KRTDebounceMax, 2*time.Millisecond)
	test.SetForTest(t, &PushDebounceAfter, time.Millisecond)
	test.SetForTest(t, &PushDebounceMax, 2*time.Millisecond)
	test.SetForTest(t, &PushConcurrency, 1)
	test.SetForTest(t, &RequestRateLimit, 1)
	test.SetForTest(t, &ClientQueueSize, 1)
	test.SetForTest(t, &MaxServerConnectionAge, 30*time.Minute)
	test.SetForTest(t, &GatewayConnectTimeout, time.Second)
	test.SetForTest(t, &GatewayRootCAPath, "/etc/ssl/certs/ca-certificates.crt")
	test.SetForTest(t, &CARootLifetime, 10*time.Hour)
	test.SetForTest(t, &CARenewBefore, 3*time.Hour)
	test.SetForTest(t, &CARotationCheckInterval, time.Hour)
	test.SetForTest(t, &MITMSignMode, "SELF_SIGN")
	test.SetForTest(t, &MITMRootLifetime, 10*time.Hour)
	test.SetForTest(t, &MITMRootRenewBefore, 3*time.Hour)
	test.SetForTest(t, &MITMRotationCheckInterval, time.Hour)
	test.SetForTest(t, &MITMLeafLifetime, 2*time.Hour)
	test.SetForTest(t, &MITMRenewBefore, time.Hour)
	test.SetForTest(t, &MITMCacheMaxAge, time.Hour)
	test.SetForTest(t, &MITMCacheMaxEntries, 1)
	test.SetForTest(t, &MITMSignConcurrency, 1)
	test.SetForTest(t, &WorkloadCertLifetime, 2*time.Hour)
	test.SetForTest(t, &WorkloadCertRenewBefore, time.Hour)
	test.SetForTest(t, &TokenAudience, "istio-ca")
	test.SetForTest(t, &EnableGatewayDeployer, false)
	test.SetForTest(t, &GatewayLeaseName, "agentiod-gateway-deployer-leader")
}
