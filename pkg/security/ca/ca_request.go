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
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/security/pki"
)

// CA request metadata examples (the CSR is sent in request.Csr):
//
// Sidecar self request: omit metadata and authenticate with the Pod-bound token.
// The CA derives and authorizes the Pod identity and includes it in the certificate extension.
//
// Node ztunnel request for a specific workload instance:
//
//	{
//	  "ImpersonatedIdentity": "spiffe://cluster.local/ns/demo/sa/backend",
//	  "TargetWorkload": {"namespace": "demo", "name": "backend-abc"}
//	}
//
// Omitting TargetWorkload from a delegated request requests only the logical identity.
// An explicit TargetWorkload requires authorization.
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
) (certificateIdentity, error) {
	impersonated, found, err := impersonatedIdentity(request)
	if err != nil {
		return certificateIdentity{}, err
	}
	workload, err := requestedTargetWorkload(request)
	if err != nil {
		return certificateIdentity{}, err
	}
	var selected model.Principal
	if found {
		selected, err = model.ParsePrincipal(impersonated, a.options.TrustDomain)
	} else {
		selected, err = callerPrincipal(caller, a.options.TrustDomain)
	}
	if err != nil {
		return certificateIdentity{}, err
	}

	if len(csr.URIs) > 1 {
		return certificateIdentity{}, fmt.Errorf("CSR must not contain multiple SPIFFE URIs")
	}
	if len(csr.URIs) == 1 {
		csrIdentity, err := model.ParsePrincipalURL(csr.URIs[0], a.options.TrustDomain)
		if err != nil {
			return certificateIdentity{}, err
		}
		if csrIdentity != selected {
			return certificateIdentity{}, fmt.Errorf("CSR identity %s conflicts with selected identity %s",
				csr.URIs[0].String(), selected.String())
		}
	}
	// Self requests select the Pod bound to the authenticated token.
	if !found && workload == nil &&
		caller.AttestedBy == model.AttestationKubernetes && caller.Kubernetes.WorkloadName != "" && caller.Kubernetes.WorkloadUID != "" {
		workload = &attestation.WorkloadReference{
			Namespace: caller.Kubernetes.Namespace,
			Name:      caller.Kubernetes.WorkloadName,
		}
	}
	identity := certificateIdentity{Principal: selected}
	if found || workload != nil {
		authorizer := a.delegatedAuthorizer()
		if attestation.DelegatedAuthorizerIsNil(authorizer) {
			return certificateIdentity{}, fmt.Errorf("certificate authorizer is not configured")
		}
		claims, err := authorizer.Authorize(
			ctx,
			caller,
			attestation.CertificateTarget{Principal: selected, Workload: workload},
		)
		if err != nil {
			return certificateIdentity{}, fmt.Errorf("authorize certificate identity: %w", err)
		}
		if workload != nil {
			if err := claims.Validate(); err != nil {
				return certificateIdentity{}, fmt.Errorf("authorizer returned no workload identity: %w", err)
			}
			identity.Workload = claims
		}
	}
	return identity, nil
}

// certificateIdentity contains the authorized claims to sign.
type certificateIdentity struct {
	Principal model.Principal
	Workload  attestation.WorkloadIdentity
}

// requestedTargetWorkload parses the optional Pod lookup key.
func requestedTargetWorkload(request *securityapi.IstioCertificateRequest) (*attestation.WorkloadReference, error) {
	value, found := request.GetMetadata().GetFields()[targetWorkloadMetadata]
	if !found {
		return nil, nil
	}
	fields := value.GetStructValue().GetFields()
	ref := &attestation.WorkloadReference{
		Namespace: fields["namespace"].GetStringValue(),
		Name:      fields["name"].GetStringValue(),
	}
	if strings.TrimSpace(ref.Namespace) == "" || strings.TrimSpace(ref.Name) == "" ||
		strings.ContainsAny(ref.Namespace+ref.Name, "/") {
		return nil, fmt.Errorf("%s requires namespace and name strings", targetWorkloadMetadata)
	}
	return ref, nil
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
		return "", false, fmt.Errorf(
			"%s metadata must contain exactly one identity string",
			impersonatedIdentityMetadata,
		)
	}
	return stringValue.StringValue, true, nil
}
