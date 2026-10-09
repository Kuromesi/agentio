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
// Sidecar self request: put the expected SPIFFE ID in the CSR and omit metadata.
// Node ztunnel derives the SPIFFE ID from WDS trust_domain, cluster_id, namespace, and name:
//
//	{"ImpersonatedIdentity": "spiffe://cluster.local/cluster/cluster-a/ns/demo/workload/backend-0"}
//
// Older node proxies request the service-account identity:
//
//	{"ImpersonatedIdentity": "spiffe://cluster.local/ns/demo/sa/backend"}
//
// Any explicit identity or CSR URI SAN must match the authorized principal.
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

// certificatePrincipal validates the requested target, then authorizes it before
// signing. A CSR confirms the requested identity; it never supplies authorization evidence.
func (a *Authority) certificatePrincipal(
	ctx context.Context,
	caller model.PeerIdentity,
	request *securityapi.IstioCertificateRequest,
	csr *x509.CertificateRequest,
) (model.Principal, error) {
	selected, found, err := requestedPrincipal(request, csr, a.options.TrustDomain)
	if err != nil {
		return model.Principal{}, err
	}
	if selected == (model.Principal{}) {
		return callerPrincipal(caller, a.options.TrustDomain)
	}
	// Service-account self requests must match the authenticated caller.
	_, _, serviceAccount := podsource.ServiceAccountFromPrincipal(selected)
	if !found && serviceAccount {
		own, err := callerPrincipal(caller, a.options.TrustDomain)
		if err != nil {
			return model.Principal{}, err
		}
		if selected != own {
			return model.Principal{}, fmt.Errorf("CSR identity does not match caller service account")
		}
		return selected, nil
	}
	authorizer := a.delegatedAuthorizer()
	if attestation.DelegatedAuthorizerIsNil(authorizer) {
		return model.Principal{}, fmt.Errorf("certificate authorizer is not configured")
	}
	if err := authorizer.Authorize(ctx, caller, selected); err != nil {
		return model.Principal{}, fmt.Errorf("authorize certificate identity: %w", err)
	}
	return selected, nil
}

// requestedPrincipal reconciles the CSR URI SAN with ImpersonatedIdentity.
func requestedPrincipal(
	request *securityapi.IstioCertificateRequest,
	csr *x509.CertificateRequest,
	trustDomain string,
) (model.Principal, bool, error) {
	impersonated, found, err := impersonatedIdentity(request)
	if err != nil {
		return model.Principal{}, false, err
	}
	var selected model.Principal
	if found {
		selected, err = model.ParsePrincipal(impersonated, trustDomain)
		if err != nil {
			return model.Principal{}, false, err
		}
	}
	if len(csr.URIs) > 1 {
		return model.Principal{}, false, fmt.Errorf("CSR must not contain multiple SPIFFE URIs")
	}
	if len(csr.URIs) == 1 {
		csrIdentity, err := model.ParsePrincipalURL(csr.URIs[0], trustDomain)
		if err != nil {
			return model.Principal{}, false, err
		}
		if found && selected != csrIdentity {
			return model.Principal{}, false, fmt.Errorf("CSR identity conflicts with ImpersonatedIdentity")
		}
		selected = csrIdentity
	}
	return selected, found, nil
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
