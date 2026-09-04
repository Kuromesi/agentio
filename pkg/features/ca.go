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
	"fmt"
	"time"

	"istio.io/istio/pkg/env"
)

var (
	CASecretName = env.Register(
		"AGENTIO_CA_SECRET_NAME",
		"istio-ca-secret",
		"Secret holding the workload root CA.",
	).Get()
	CAConfigMapName = env.Register(
		"AGENTIO_CA_CONFIGMAP_NAME",
		"agentio-ca-certs",
		"ConfigMap publishing the workload trust bundle.",
	).Get()
	CALeaseName = env.Register(
		"AGENTIO_CA_LEASE_NAME",
		"agentiod-ca-leader",
		"Lease electing the single replica allowed to create or rotate workload CA material.",
	).Get()
	TrustBundleConfigMapName = env.Register(
		"AGENTIO_TRUST_BUNDLE_CONFIGMAP_NAME",
		"istio-ca-root-cert",
		"Per-namespace ConfigMap distributing the workload trust bundle to proxies.",
	).Get()
	TrustBundleLeaseName = env.Register(
		"AGENTIO_TRUST_BUNDLE_LEASE_NAME",
		"agentiod-trust-bundle-leader",
		"Lease electing the replica that distributes the trust bundle ConfigMap.",
	).Get()
	CARootLifetime = env.Register(
		"AGENTIO_CA_ROOT_LIFETIME",
		10*365*24*time.Hour,
		"Validity of generated workload CA certificates.",
	).Get()
	CARenewBefore = env.Register(
		"AGENTIO_CA_RENEW_BEFORE",
		365*24*time.Hour,
		"How long before expiry a CA is rotated. Must exceed the workload certificate lifetime, or a leaf could outlive its root.",
	).Get()
	CARotationCheckInterval = env.Register(
		"AGENTIO_CA_ROTATION_CHECK_INTERVAL",
		time.Hour,
		"How often the elected leader checks CA expiry.",
	).Get()
	WorkloadCertLifetime = env.Register(
		"AGENTIO_WORKLOAD_CERT_LIFETIME",
		24*time.Hour,
		"Validity of workload certificates and of the xDS server's own certificate.",
	).Get()
	WorkloadCertRenewBefore = env.Register(
		"AGENTIO_WORKLOAD_CERT_RENEW_BEFORE",
		8*time.Hour,
		"How long before expiry the xDS server re-issues its own certificate.",
	).Get()
)

func validateCARotation() error {
	if CARootLifetime <= 0 || CARenewBefore <= 0 || CARenewBefore >= CARootLifetime || CARotationCheckInterval <= 0 {
		return fmt.Errorf("invalid CA rotation durations")
	}
	return nil
}

func validateWorkloadCertificates() error {
	if WorkloadCertLifetime <= 0 || WorkloadCertRenewBefore <= 0 || WorkloadCertRenewBefore >= WorkloadCertLifetime {
		return fmt.Errorf("invalid workload certificate durations")
	}
	if CARenewBefore <= WorkloadCertLifetime {
		return fmt.Errorf("CA renew-before must exceed the workload certificate lifetime")
	}
	return nil
}
