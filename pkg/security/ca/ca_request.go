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

package ca

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"
	securityapi "istio.io/api/security/v1alpha1"

	"github.com/openkruise/agentio/pkg/model"
	podsource "github.com/openkruise/agentio/pkg/registry/kubernetes/pod"
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/security/pki"
)

// CA request metadata examples (the CSR is sent in request.Csr):
//
// Sidecar self request: omit metadata and authenticate with the Pod-bound token.
// With a source extension OID configured, the CA derives and authorizes the Pod source.
//
// Node ztunnel request for a specific workload instance:
//
//	{
//	  "ImpersonatedIdentity": "spiffe://cluster.local/ns/demo/sa/backend",
//	  "TargetWorkload": {"registry": "kubernetes/cluster-a", "key": "<target Pod UID>"}
//	}
//
// Omitting TargetWorkload from a delegated request requests only the logical identity.
// An explicit TargetWorkload requires authorization and a configured extension OID.
// Any URI SAN in the CSR must match the selected identity.
const (
	impersonatedIdentityMetadata = "ImpersonatedIdentity"
	targetWorkloadMetadata       = "TargetWorkload"
)

func parseCertificateRequest(request *securityapi.IstioCertificateRequest) (*x509.CertificateRequest, error) {
	block, err := pki.DecodeSinglePEMBlock([]byte(request.GetCsr()), "CSR")
	if err != nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("CSR must be PEM encoded")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, fmt.Errorf("CSR signature is invalid")
	}
	return csr, nil
}

// certificateTarget validates the requested target, then authorizes it before
// signing. A CSR confirms the requested identity; it never supplies authorization evidence.
func (a *Authority) certificateTarget(
	ctx context.Context,
	caller model.PeerIdentity,
	request *securityapi.IstioCertificateRequest,
	csr *x509.CertificateRequest,
) (attestation.CertificateTarget, error) {
	impersonated, found, err := impersonatedIdentity(request)
	if err != nil {
		return attestation.CertificateTarget{}, err
	}
	source, err := requestedTargetWorkload(request)
	if err != nil {
		return attestation.CertificateTarget{}, err
	}
	var selected model.Principal
	if found {
		selected, err = model.ParsePrincipal(impersonated, a.options.TrustDomain)
	} else {
		selected, err = callerPrincipal(caller, a.options.TrustDomain)
	}
	if err != nil {
		return attestation.CertificateTarget{}, err
	}

	if len(csr.URIs) > 1 {
		return attestation.CertificateTarget{}, fmt.Errorf("CSR must not contain multiple SPIFFE URIs")
	}
	if len(csr.URIs) == 1 {
		csrIdentity, err := model.ParsePrincipalURL(csr.URIs[0], a.options.TrustDomain)
		if err != nil {
			return attestation.CertificateTarget{}, err
		}
		if csrIdentity != selected {
			return attestation.CertificateTarget{}, fmt.Errorf("CSR identity %s conflicts with selected identity %s",
				csr.URIs[0].String(), selected.String())
		}
	}
	// Self requests can use the authenticated Pod binding as their source.
	if !found && source == (model.SourceRef{}) && len(a.workloadSourceOID) != 0 &&
		caller.AttestedBy == model.AttestationKubernetes && caller.Kubernetes.WorkloadName != "" &&
		caller.Kubernetes.WorkloadUID != "" {
		source = podsource.SourceRef(a.options.ClusterID, caller.Kubernetes.WorkloadUID)
	}
	target := attestation.CertificateTarget{Principal: selected, Source: source}
	if found || source != (model.SourceRef{}) {
		if err := a.authorizeCertificateTarget(ctx, caller, target); err != nil {
			return attestation.CertificateTarget{}, err
		}
	}
	return target, nil
}

// Explicit targets and instance selectors require an installed authorizer.
func (a *Authority) authorizeCertificateTarget(
	ctx context.Context,
	caller model.PeerIdentity,
	target attestation.CertificateTarget,
) error {
	authorizer := a.delegatedAuthorizer()
	if attestation.DelegatedAuthorizerIsNil(authorizer) {
		return fmt.Errorf("authorize certificate identity %s: authorizer is not configured", target.Principal.String())
	}
	if err := authorizer.Authorize(ctx, caller, target); err != nil {
		return fmt.Errorf("authorize certificate identity %s: %w", target.Principal.String(), err)
	}
	return nil
}

// requestedTargetWorkload parses the optional target instance selector.
func requestedTargetWorkload(request *securityapi.IstioCertificateRequest) (model.SourceRef, error) {
	value, found := request.GetMetadata().GetFields()[targetWorkloadMetadata]
	if !found {
		return model.SourceRef{}, nil
	}
	fields := value.GetStructValue().GetFields()
	source := model.SourceRef{
		Registry: fields["registry"].GetStringValue(),
		Key:      fields["key"].GetStringValue(),
	}
	if err := source.Validate(); err != nil {
		return model.SourceRef{}, fmt.Errorf("%s requires nonempty registry and key strings", targetWorkloadMetadata)
	}
	return source, nil
}

func impersonatedIdentity(request *securityapi.IstioCertificateRequest) (string, bool, error) {
	metadata := request.GetMetadata()
	if metadata == nil {
		return "", false, nil
	}
	value, found := metadata.GetFields()[impersonatedIdentityMetadata]
	if !found {
		return "", false, nil
	}
	stringValue, ok := value.GetKind().(*structpb.Value_StringValue)
	if !ok || strings.TrimSpace(stringValue.StringValue) == "" {
		return "", false, fmt.Errorf("%s metadata must contain exactly one identity string", impersonatedIdentityMetadata)
	}
	return stringValue.StringValue, true, nil
}
