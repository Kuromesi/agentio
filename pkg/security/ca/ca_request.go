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

const impersonatedIdentityMetadata = "ImpersonatedIdentity"

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

// certificateIdentity selects an identity from the authenticated peer and
// delegated-authorization metadata. The authenticated principal is authoritative
// unless compatible impersonation metadata is present and authorized; CSR URI
// SANs can only confirm that selection.
func (a *Authority) certificateIdentity(ctx context.Context, caller model.PeerIdentity,
	request *securityapi.IstioCertificateRequest,
	csr *x509.CertificateRequest,
) (model.Principal, error) {
	selected, err := model.ParsePrincipal(caller.Principal.String(), caller.Principal.TrustDomain)
	if err != nil || selected != caller.Principal {
		return model.Principal{}, fmt.Errorf("invalid authenticated identity %q", caller.Principal.String())
	}
	impersonated, found, err := impersonatedIdentity(request)
	if err != nil {
		return model.Principal{}, err
	}
	if found {
		selected, err = model.ParsePrincipal(impersonated, caller.Principal.TrustDomain)
		if err != nil {
			return model.Principal{}, err
		}
		authorizer := a.delegatedAuthorizer()
		if attestation.DelegatedAuthorizerIsNil(authorizer) {
			return model.Principal{}, fmt.Errorf("authorize delegated identity %s for %s: authorizer is not configured",
				selected.String(), caller.Principal.String())
		}
		if err := authorizer.Authorize(ctx, caller, selected); err != nil {
			return model.Principal{}, fmt.Errorf("authorize delegated identity %s for %s: %w",
				selected.String(), caller.Principal.String(), err)
		}
	}

	if len(csr.URIs) > 1 {
		return model.Principal{}, fmt.Errorf("CSR must not contain multiple SPIFFE URIs")
	}
	if len(csr.URIs) == 1 {
		csrIdentity, err := model.ParsePrincipalURL(csr.URIs[0], caller.Principal.TrustDomain)
		if err != nil {
			return model.Principal{}, err
		}
		if csrIdentity != selected {
			return model.Principal{}, fmt.Errorf("CSR identity %s conflicts with selected identity %s",
				csr.URIs[0].String(), selected.String())
		}
	}
	return selected, nil
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
