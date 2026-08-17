// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wiring

import (
	"fmt"

	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/certs"
	"istio.io/istio/extensions/epe/pkg/certs/certsource"
	"istio.io/istio/extensions/epe/pkg/credential"
	"istio.io/istio/extensions/epe/pkg/credential/tokencache"
	"istio.io/istio/pkg/env"
)

// Default credential-provider mTLS file paths when the env vars are not set.
// They match the mount point the chart uses for the (optional) mTLS Secret
// volume.
const (
	defaultCredProviderClientCertPath = "/etc/epe/credential-provider/client.crt"
	defaultCredProviderClientKeyPath  = "/etc/epe/credential-provider/client.key"
	defaultCredProviderCACertPath     = "/etc/epe/credential-provider/ca.crt"
)

// Source names for CREDENTIAL_PROVIDER_MTLS_SOURCE.
const (
	credProviderSourceNone   = "none"
	credProviderSourceFiles  = "files"
	credProviderSourceSecret = "secret"
)

// Where the credential provider's mTLS material comes from. This is the
// composition root's concern, which is why the variables live here rather than
// in pkg/credential: that package only consumes a certs.Provider and does not
// know whether the material behind it is a Secret, a file, or nothing.
var (
	credProviderMTLSSource = env.Register("CREDENTIAL_PROVIDER_MTLS_SOURCE", credProviderSourceFiles,
		"Where the credential provider's mTLS material comes from: \"files\" (the "+
			"CREDENTIAL_PROVIDER_*_PATH paths), \"secret\" (the Secret named by "+
			"CREDENTIAL_PROVIDER_SECRET_NAMESPACE and _NAME), or \"none\". Exactly one "+
			"source is used; there is no fallback between them. Material that is absent "+
			"or unusable means no client certificate is presented and the provider's "+
			"certificate is verified against the system trust store").Get()

	credProviderClientCertPath = env.Register("CREDENTIAL_PROVIDER_CLIENT_CERT_PATH", defaultCredProviderClientCertPath,
		"Path to the client certificate presented to the credential provider").Get()
	credProviderClientKeyPath = env.Register("CREDENTIAL_PROVIDER_CLIENT_KEY_PATH", defaultCredProviderClientKeyPath,
		"Path to the private key for CREDENTIAL_PROVIDER_CLIENT_CERT_PATH").Get()
	credProviderCACertPath = env.Register("CREDENTIAL_PROVIDER_CA_CERT_PATH", defaultCredProviderCACertPath,
		"Path to the CA certificate used to verify the credential provider's server certificate").Get()

	// Namespace and name of the Secret holding the credential provider's mTLS
	// material. Both must be set for the Secret source to join the chain at all.
	credProviderSecretNamespace = env.Register("CREDENTIAL_PROVIDER_SECRET_NAMESPACE", "",
		"Namespace of the Secret holding the credential provider mTLS certificate, key, and CA").Get()
	credProviderSecretName = env.Register("CREDENTIAL_PROVIDER_SECRET_NAME", "",
		"Name of the Secret holding the credential provider mTLS certificate, key, and CA").Get()
)

var wiringLog = ctrllog.Log.WithName("plugin-wiring")

// credProviderFor builds the source of the credential provider's mTLS material.
//
// Exactly one source is used, named by CREDENTIAL_PROVIDER_MTLS_SOURCE. There
// is deliberately no fallback between sources: a Secret that is missing its CA
// does not silently borrow the CA from disk. Within the chosen source the client
// identity and the trust anchors are independent — a source may supply anchors
// without an identity, or an identity without anchors.
//
// The source is watched for the lifetime of deps.Stop, so material that appears
// or rotates after startup takes effect without a restart. Material that is
// absent or unusable means no client certificate is presented and the provider
// is verified against the system trust store; it is never a startup failure.
// Only a MISCONFIGURED source is, which is what the error return reports.
func credProviderFor(deps Deps) (certs.Provider, error) {
	switch credProviderMTLSSource {
	case credProviderSourceNone:
		wiringLog.Info("No credential provider mTLS material configured")
		return nil, nil

	case credProviderSourceFiles:
		wiringLog.Info("Watching files for credential provider mTLS material",
			"certPath", credProviderClientCertPath, "keyPath", credProviderClientKeyPath, "caPath", credProviderCACertPath)
		return certsource.FromFilesOptional(credProviderClientCertPath, credProviderClientKeyPath, credProviderCACertPath, deps.Stop), nil

	case credProviderSourceSecret:
		provider, err := certsource.FromSecret(deps.Kube, credProviderSecretNamespace, credProviderSecretName, deps.Stop)
		if err != nil {
			return nil, fmt.Errorf("%s=%s: %w", "CREDENTIAL_PROVIDER_MTLS_SOURCE", credProviderSourceSecret, err)
		}
		wiringLog.Info("Watching Secret for credential provider mTLS material",
			"namespace", credProviderSecretNamespace, "name", credProviderSecretName)
		return provider, nil

	default:
		return nil, fmt.Errorf("%s=%q is not one of %q, %q, or %q",
			"CREDENTIAL_PROVIDER_MTLS_SOURCE", credProviderMTLSSource,
			credProviderSourceNone, credProviderSourceFiles, credProviderSourceSecret)
	}
}

// credClientFor returns the caller-supplied credential client or builds a
// token-cache-backed one. When the provider URL is not configured,
// provider-backed fetches fail through each rule's FailStrategy.
func credClientFor(deps Deps) (*credential.Client, error) {
	if deps.CredentialClient != nil {
		return deps.CredentialClient, nil
	}
	provider, err := credProviderFor(deps)
	if err != nil {
		return nil, err
	}
	tokenCache := tokencache.NewCacheFromEnv()
	wiringLog.Info("Token cache configured", "config", tokencache.ConfigInfo())
	stsTokenCache := tokencache.NewSTSCacheFromEnv()
	wiringLog.Info("STS token cache configured", "config", tokencache.STSCacheConfigInfo())
	return credential.NewClientWithCache(tokenCache, stsTokenCache, provider), nil
}
