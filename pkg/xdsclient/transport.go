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

package xdsclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Dial opens a TLS ADS connection using rotating projected roots and a
// Pod-bound bearer token. The caller owns the returned connection.
func Dial(address, rootPath, tokenPath string) (*grpc.ClientConn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" || rootPath == "" || tokenPath == "" {
		return nil, fmt.Errorf("xDS requires host:port, root and token paths")
	}
	return grpc.NewClient(address,
		grpc.WithTransportCredentials(&fileTLS{
			TransportCredentials: credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}),
			path:                 rootPath,
			serverName:           host,
		}),
		grpc.WithPerRPCCredentials(tokenFile(tokenPath)),
	)
}

type tokenFile string

func (t tokenFile) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	b, err := os.ReadFile(string(t))
	if err != nil {
		return nil, fmt.Errorf("read xDS token: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return nil, fmt.Errorf("xDS token is empty")
	}
	return map[string]string{"authorization": "Bearer " + token}, nil
}

func (tokenFile) RequireTransportSecurity() bool { return true }

// fileTLS reads the projected trust bundle for every handshake, including root
// rotation. DNS verification remains enabled; tokens are only sent over TLS.
type fileTLS struct {
	credentials.TransportCredentials
	path       string
	serverName string
}

func (f *fileTLS) ClientHandshake(
	ctx context.Context,
	authority string,
	conn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {
	b, err := os.ReadFile(f.path)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, nil, fmt.Errorf("xDS root bundle contains no certificates")
	}
	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: f.serverName}).
		ClientHandshake(ctx, authority, conn)
}

func (f *fileTLS) Clone() credentials.TransportCredentials {
	return &fileTLS{TransportCredentials: f.TransportCredentials.Clone(), path: f.path, serverName: f.serverName}
}
