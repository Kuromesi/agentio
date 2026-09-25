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

const (
	impersonatedIdentityMetadata = "ImpersonatedIdentity"
	workloadSourceMetadata       = "WorkloadSource"
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
func (a *Authority) certificateTarget(ctx context.Context, caller model.PeerIdentity,
	request *securityapi.IstioCertificateRequest,
	csr *x509.CertificateRequest,
) (attestation.CertificateTarget, error) {
	impersonated, found, err := impersonatedIdentity(request)
	if err != nil {
		return attestation.CertificateTarget{}, err
	}
	source, err := requestedWorkloadSource(request)
	if err != nil {
		return attestation.CertificateTarget{}, err
	}
	var selected model.Principal
	if found {
		selected, err = model.ParsePrincipal(impersonated, a.options.TrustDomain)
	} else {
		selected, err = legacyRequestIdentity(caller, a.options.TrustDomain)
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
	target := attestation.CertificateTarget{Principal: selected, Source: source}
	if err := a.authorizeCertificateTarget(ctx, caller, target); err != nil {
		return attestation.CertificateTarget{}, err
	}
	return target, nil
}

// Every target requires an explicitly installed authorizer, including self issuance.
func (a *Authority) authorizeCertificateTarget(ctx context.Context, caller model.PeerIdentity, target attestation.CertificateTarget) error {
	authorizer := a.delegatedAuthorizer()
	if attestation.DelegatedAuthorizerIsNil(authorizer) {
		return fmt.Errorf("authorize certificate identity %s: authorizer is not configured", target.Principal.String())
	}
	if err := authorizer.Authorize(ctx, caller, target); err != nil {
		return fmt.Errorf("authorize certificate identity %s: %w", target.Principal.String(), err)
	}
	return nil
}

// Only an explicit instance selector opts into an instance-bound certificate.
// Missing metadata preserves principal-only issuance; malformed metadata fails.
func requestedWorkloadSource(request *securityapi.IstioCertificateRequest) (model.SourceRef, error) {
	value, found := request.GetMetadata().GetFields()[workloadSourceMetadata]
	if !found {
		return model.SourceRef{}, nil
	}
	fields := value.GetStructValue().GetFields()
	source := model.SourceRef{
		Registry: fields["registry"].GetStringValue(),
		Key:      fields["key"].GetStringValue(),
	}
	if err := source.Validate(); err != nil {
		return model.SourceRef{}, fmt.Errorf("%s requires nonempty registry and key strings", workloadSourceMetadata)
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
