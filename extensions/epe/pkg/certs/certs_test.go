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
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// mustErrorContains fails the test when err is nil or does not mention want.
func mustErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not contain %q", err.Error(), want)
	}
}

// staticProvider is a fixed-material Provider used to exercise the
// verification pipeline without touching the filesystem.
type staticProvider struct {
	cert     *tls.Certificate
	roots    *x509.CertPool
	rootsErr error
}

func (p *staticProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.cert, nil
}

func (p *staticProvider) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if p.cert == nil {
		// An empty certificate tells crypto/tls to send no client certificate.
		return &tls.Certificate{}, nil
	}
	return p.cert, nil
}

func (p *staticProvider) RootCAs() (*x509.CertPool, error) {
	return p.roots, p.rootsErr
}

// testCA is a throwaway ECDSA certificate authority for handshake tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certs-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// leafSpec describes the throwaway leaf certificate to issue.
type leafSpec struct {
	serial      int64
	dnsNames    []string
	uris        []string
	extKeyUsage []x509.ExtKeyUsage
}

// issue signs a leaf certificate with the test CA and returns it in both
// tls.Certificate and parsed x509 form.
func (ca *testCA) issue(t *testing.T, spec leafSpec) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	var uris []*url.URL
	for _, raw := range spec.uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parsing URI SAN %q: %v", raw, err)
		}
		uris = append(uris, u)
	}
	usages := spec.extKeyUsage
	if usages == nil {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(spec.serial),
		Subject:      pkix.Name{CommonName: "certs-test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
		DNSNames:     spec.dnsNames,
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// writePEM persists a leaf certificate and its key to certPath/keyPath.
func writePEM(t *testing.T, cert tls.Certificate, certPath, keyPath string) {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing key file: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing cert file: %v", err)
	}
}

// doHandshake performs a real TLS handshake over a TCP loopback connection
// and returns the client connection state. Errors from both sides are joined
// so assertions can match whichever side failed closed.
func doHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	deadline := time.Now().Add(4 * time.Second)

	srvErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			srvErrCh <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(deadline); err != nil {
			srvErrCh <- err
			return
		}
		srvErrCh <- tls.Server(conn, serverCfg).Handshake()
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatalf("setting client deadline: %v", err)
	}
	client := tls.Client(conn, clientCfg)
	clientErr := client.Handshake()
	srvErr := <-srvErrCh
	if joined := errors.Join(clientErr, srvErr); joined != nil {
		return tls.ConnectionState{}, joined
	}
	return client.ConnectionState(), nil
}

// pinLeaf returns a peer verifier that pins the expected leaf certificate.
// ClientTLSConfig requires explicit identity verification, and this keeps
// SAN-less handshake scenarios testable.
func pinLeaf(expected *x509.Certificate) func(chains [][]*x509.Certificate) error {
	return func(chains [][]*x509.Certificate) error {
		if len(chains) == 0 || len(chains[0]) == 0 || !chains[0][0].Equal(expected) {
			return errors.New("peer leaf does not match the pinned certificate")
		}
		return nil
	}
}

func TestOptionValidation(t *testing.T) {
	provider := &staticProvider{}
	verifier := func([][]*x509.Certificate) error { return nil }
	tests := []struct {
		name        string
		build       func() (*tls.Config, error)
		expectError string
	}{
		{
			name: "client with server name and peer verifier is rejected",
			build: func() (*tls.Config, error) {
				return ClientTLSConfig(provider, WithServerName("example.com"), WithPeerVerifier(verifier))
			},
			expectError: "mutually exclusive",
		},
		{
			name: "server with server name and peer verifier is rejected",
			build: func() (*tls.Config, error) {
				return ServerTLSConfig(provider, WithServerName("example.com"), WithPeerVerifier(verifier))
			},
			expectError: "mutually exclusive",
		},
		{
			name: "client with only server name is accepted",
			build: func() (*tls.Config, error) {
				return ClientTLSConfig(provider, WithServerName("example.com"))
			},
		},
		{
			name: "client with only peer verifier is accepted",
			build: func() (*tls.Config, error) {
				return ClientTLSConfig(provider, WithPeerVerifier(verifier))
			},
		},
		{
			name: "client with zero identity options is rejected",
			build: func() (*tls.Config, error) {
				return ClientTLSConfig(provider)
			},
			expectError: "exactly one of",
		},
		{
			name: "server with peer verifier but non-verifying client auth is rejected",
			build: func() (*tls.Config, error) {
				return ServerTLSConfig(provider, WithPeerVerifier(verifier), WithClientAuth(tls.RequireAnyClientCert))
			},
			expectError: "WithPeerVerifier on a server requires WithClientAuth(tls.VerifyClientCertIfGiven) or stronger",
		},
		{
			name: "server with peer verifier and verifying client auth is accepted",
			build: func() (*tls.Config, error) {
				return ServerTLSConfig(provider, WithPeerVerifier(verifier), WithClientAuth(tls.RequireAndVerifyClientCert))
			},
		},
		{
			name: "server with zero options is accepted",
			build: func() (*tls.Config, error) {
				return ServerTLSConfig(provider)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := tt.build()
			if tt.expectError != "" {
				mustErrorContains(t, err, tt.expectError)
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg == nil {
				t.Fatal("expected a non-nil tls.Config")
			}
		})
	}
}

func TestClientConfigInternals(t *testing.T) {
	// The pipeline replaces stdlib verification with an unconditional
	// VerifyPeerCertificate; InsecureSkipVerify must be set internally and the
	// callback must always be installed.
	cfg, err := ClientTLSConfig(&staticProvider{}, WithServerName("example.com"))
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify must be set internally so the manual pipeline runs")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Errorf("VerifyPeerCertificate must be unconditionally installed")
	}
}

func TestHandshake(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) (serverCfg, clientCfg *tls.Config)
		expectError string
	}{
		{
			name: "self-signed server with client trusting provider roots succeeds",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				p, err := SelfSigned()
				if err != nil {
					t.Fatalf("SelfSigned: %v", err)
				}
				serverCfg, err := ServerTLSConfig(p)
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				cert, err := p.GetCertificate(nil)
				if err != nil {
					t.Fatalf("GetCertificate: %v", err)
				}
				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					t.Fatalf("parsing leaf certificate: %v", err)
				}
				// The self-signed leaf carries no SANs, so pin it explicitly.
				clientCfg, err := ClientTLSConfig(p, WithPeerVerifier(pinLeaf(leaf)))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
		},
		{
			name: "client rejects server presenting an unrelated certificate",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				serverCA := newTestCA(t)
				serverCert, serverLeaf := serverCA.issue(t, leafSpec{serial: 100})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCA := newTestCA(t)
				// The pinned identity never runs: chain verification against the
				// unrelated CA fails first.
				clientCfg, err := ClientTLSConfig(&staticProvider{roots: clientCA.pool}, WithPeerVerifier(pinLeaf(serverLeaf)))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "certificate",
		},
		{
			name: "client fails closed when provider trust anchors are unavailable",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := newTestCA(t)
				serverCert, serverLeaf := ca.issue(t, leafSpec{serial: 101})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				// The pinned identity never runs: trust anchor resolution fails
				// before chain verification.
				clientCfg, err := ClientTLSConfig(&staticProvider{rootsErr: errors.New("trust anchors unavailable")}, WithPeerVerifier(pinLeaf(serverLeaf)))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "trust anchors unavailable",
		},
		{
			name: "peer verifier replaces hostname verification for URI SAN identity",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := newTestCA(t)
				serverCert, _ := ca.issue(t, leafSpec{serial: 102, uris: []string{"spiffe://cluster.local/ns/default/sa/traffic"}})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCfg, err := ClientTLSConfig(&staticProvider{roots: ca.pool}, WithPeerVerifier(func(chains [][]*x509.Certificate) error {
					leaf := chains[0][0]
					if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://cluster.local/ns/default/sa/traffic" {
						return errors.New("unexpected peer identity")
					}
					return nil
				}))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
		},
		{
			name: "hostname verification fails without peer verifier when no DNS SAN matches",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := newTestCA(t)
				serverCert, _ := ca.issue(t, leafSpec{serial: 103, uris: []string{"spiffe://cluster.local/ns/default/sa/traffic"}})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCfg, err := ClientTLSConfig(&staticProvider{roots: ca.pool}, WithServerName("example.com"))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "certificate",
		},
		{
			name: "peer verifier rejection fails the handshake",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := newTestCA(t)
				serverCert, _ := ca.issue(t, leafSpec{serial: 104})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCfg, err := ClientTLSConfig(&staticProvider{roots: ca.pool}, WithPeerVerifier(func([][]*x509.Certificate) error {
					return errors.New("identity mismatch")
				}))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "identity mismatch",
		},
		{
			name: "matching DNS SAN passes hostname verification with server name",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := newTestCA(t)
				serverCert, _ := ca.issue(t, leafSpec{serial: 105, dnsNames: []string{"traffic.local"}})
				serverCfg, err := ServerTLSConfig(&staticProvider{cert: &serverCert})
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCfg, err := ClientTLSConfig(&staticProvider{roots: ca.pool}, WithServerName("traffic.local"))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
		},
		{
			name: "mutual TLS succeeds when server rebuilds client CAs per handshake",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := newTestCA(t)
				serverCert, _ := ca.issue(t, leafSpec{serial: 106, dnsNames: []string{"traffic.local"}})
				clientCert, _ := ca.issue(t, leafSpec{serial: 107, extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
				serverCfg, err := ServerTLSConfig(
					&staticProvider{cert: &serverCert, roots: ca.pool},
					WithClientAuth(tls.RequireAndVerifyClientCert),
				)
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				clientCfg, err := ClientTLSConfig(&staticProvider{cert: &clientCert, roots: ca.pool}, WithServerName("traffic.local"))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
		},
		{
			name: "mutual TLS rejects a client certificate from an unrelated CA",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := newTestCA(t)
				otherCA := newTestCA(t)
				serverCert, serverLeaf := ca.issue(t, leafSpec{serial: 108})
				clientCert, _ := otherCA.issue(t, leafSpec{serial: 109, extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
				serverCfg, err := ServerTLSConfig(
					&staticProvider{cert: &serverCert, roots: ca.pool},
					WithClientAuth(tls.RequireAndVerifyClientCert),
				)
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				// The SAN-less server leaf is pinned; the failure comes from the
				// server rejecting the unrelated client chain.
				clientCfg, err := ClientTLSConfig(&staticProvider{cert: &clientCert, roots: ca.pool}, WithPeerVerifier(pinLeaf(serverLeaf)))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "certificate",
		},
		{
			name: "mutual TLS fails closed when server provider has no trust anchors",
			setup: func(t *testing.T) (*tls.Config, *tls.Config) {
				ca := newTestCA(t)
				serverCert, serverLeaf := ca.issue(t, leafSpec{serial: 110})
				clientCert, _ := ca.issue(t, leafSpec{serial: 111, extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
				serverCfg, err := ServerTLSConfig(
					&staticProvider{cert: &serverCert},
					WithClientAuth(tls.RequireAndVerifyClientCert),
				)
				if err != nil {
					t.Fatalf("ServerTLSConfig: %v", err)
				}
				// The SAN-less server leaf is pinned; the failure comes from the
				// server side missing trust anchors.
				clientCfg, err := ClientTLSConfig(&staticProvider{cert: &clientCert, roots: ca.pool}, WithPeerVerifier(pinLeaf(serverLeaf)))
				if err != nil {
					t.Fatalf("ClientTLSConfig: %v", err)
				}
				return serverCfg, clientCfg
			},
			expectError: "trust anchors",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverCfg, clientCfg := tt.setup(t)
			_, err := doHandshake(t, serverCfg, clientCfg)
			if tt.expectError != "" {
				mustErrorContains(t, err, tt.expectError)
				return
			}
			if err != nil {
				t.Fatalf("unexpected handshake error: %v", err)
			}
		})
	}
}

func TestSelfSignedProvider(t *testing.T) {
	// The generated certificate must parse and carry the subject
	// organization.
	p, err := SelfSigned()
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}

	cert, err := p.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil certificate")
	}
	if cert.PrivateKey == nil {
		t.Fatal("certificate has no private key")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("certificate chain is empty")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	if got, want := parsed.Subject.Organization[0], "OpenKruise Agents Egress Policy Enforcer"; got != want {
		t.Errorf("subject organization = %q, want %q", got, want)
	}

	clientCert, err := p.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if !reflect.DeepEqual(cert, clientCert) {
		t.Errorf("GetClientCertificate must return the same certificate as GetCertificate")
	}

	pool, err := p.RootCAs()
	if err != nil {
		t.Fatalf("RootCAs: %v", err)
	}
	if pool == nil {
		t.Fatal("RootCAs returned nil pool")
	}
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("verifying certificate against provider roots: %v", err)
	}
}

func TestFileProviderRootCAs(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	leaf, _ := ca.issue(t, leafSpec{serial: 200})
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	writePEM(t, leaf, certPath, keyPath)

	caPath := filepath.Join(dir, "ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("writing CA bundle: %v", err)
	}
	garbagePath := filepath.Join(dir, "garbage.crt")
	if err := os.WriteFile(garbagePath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("writing garbage file: %v", err)
	}

	tests := []struct {
		name        string
		caPath      string
		expectError string
		expectNil   bool
	}{
		{
			name:      "empty CA path yields nil pool without error",
			caPath:    "",
			expectNil: true,
		},
		{
			name:   "valid CA bundle yields a pool",
			caPath: caPath,
		},
		{
			name:        "missing CA file fails closed",
			caPath:      filepath.Join(dir, "missing.crt"),
			expectError: "reading CA bundle",
		},
		{
			name:        "CA bundle without certificates fails closed",
			caPath:      garbagePath,
			expectError: "no valid certificates",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := FromFiles(certPath, keyPath, tt.caPath)
			if err != nil {
				t.Fatalf("FromFiles: %v", err)
			}
			pool, err := p.RootCAs()
			if tt.expectError != "" {
				mustErrorContains(t, err, tt.expectError)
				return
			}
			if err != nil {
				t.Fatalf("RootCAs: %v", err)
			}
			if tt.expectNil {
				if pool != nil {
					t.Errorf("expected nil pool, got %v", pool)
				}
			} else if pool == nil {
				t.Errorf("expected a non-nil pool")
			}
		})
	}
}

func TestFromFilesHotRotation(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	// Both leaves carry the same DNS SAN so hostname verification stays valid
	// across rotation; the serial numbers distinguish old from new.
	oldLeaf, _ := ca.issue(t, leafSpec{serial: 1001, dnsNames: []string{"traffic.local"}})
	writePEM(t, oldLeaf, certPath, keyPath)

	p, err := FromFiles(certPath, keyPath, "")
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	serverCfg, err := ServerTLSConfig(p)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	clientCfg, err := ClientTLSConfig(&staticProvider{roots: ca.pool}, WithServerName("traffic.local"))
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	state, err := doHandshake(t, serverCfg, clientCfg)
	if err != nil {
		t.Fatalf("initial handshake: %v", err)
	}
	if len(state.PeerCertificates) == 0 {
		t.Fatal("initial handshake returned no peer certificates")
	}
	if got := state.PeerCertificates[0].SerialNumber.Int64(); got != 1001 {
		t.Fatalf("initial certificate serial = %d, want 1001", got)
	}

	newLeaf, _ := ca.issue(t, leafSpec{serial: 1002, dnsNames: []string{"traffic.local"}})
	writePEM(t, newLeaf, certPath, keyPath)

	// The watcher reloads asynchronously; retry briefly until the new leaf is
	// served, keeping the whole test well under 5 seconds.
	deadline := time.Now().Add(4 * time.Second)
	for {
		state, err = doHandshake(t, serverCfg, clientCfg)
		if err == nil && len(state.PeerCertificates) > 0 &&
			state.PeerCertificates[0].SerialNumber.Int64() == 1002 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("rotated certificate not observed before deadline, last err=%v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
