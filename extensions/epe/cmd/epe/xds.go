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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"

	xdsstore "github.com/openkruise/agentio/extensions/epe/pkg/store/xds"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

var (
	enableEgressAuthz = flag.Bool(
		"enable-egressauthz",
		false,
		"Authorize and pin HTTP destinations using native Workload and TrafficPolicy xDS resources",
	)
	xdsAddress = flag.String(
		"xds-address",
		"",
		"Agentiod TLS ADS endpoint (host:port); required with --enable-egressauthz",
	)
	xdsRootPath  = flag.String("xds-root-path", "", "PEM trust bundle for Agentiod ADS")
	xdsTokenPath = flag.String(
		"xds-token-path",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"Projected Pod-bound token for ADS (requires an authorized gateway Pod)",
	)
	xdsNodeID = flag.String(
		"xds-node-id",
		"",
		"ADS node ID; defaults to waypoint~POD_IP~POD_NAME.POD_NAMESPACE~POD_NAMESPACE.svc.cluster.local",
	)
)

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

func newEgressXDS() (*xdsclient.Client, *grpc.ClientConn, error) {
	host, port, err := net.SplitHostPort(*xdsAddress)
	if err != nil || host == "" || port == "" || *xdsRootPath == "" || *xdsTokenPath == "" {
		return nil, nil, fmt.Errorf("egressauthz requires xDS host:port, root and token paths")
	}
	id := *xdsNodeID
	if id == "" {
		name, ns := os.Getenv("POD_NAME"), os.Getenv("POD_NAMESPACE")
		if name == "" || ns == "" {
			return nil, nil, fmt.Errorf("POD_NAME and POD_NAMESPACE or --xds-node-id are required")
		}
		id = "waypoint~" + os.Getenv("POD_IP") + "~" + name + "." + ns + "~" + ns + ".svc.cluster.local"
	}
	metadata, err := structpb.NewStruct(
		map[string]any{
			"POD_NAME":      os.Getenv("POD_NAME"),
			"POD_NAMESPACE": os.Getenv("POD_NAMESPACE"),
			"POD_UID":       os.Getenv("POD_UID"),
		},
	)
	if err != nil {
		return nil, nil, err
	}
	conn, err := grpc.NewClient(
		*xdsAddress,
		grpc.WithTransportCredentials(
			&fileTLS{
				TransportCredentials: credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}),
				path:                 *xdsRootPath,
				serverName:           host,
			},
		),
		grpc.WithPerRPCCredentials(tokenFile(*xdsTokenPath)),
	)
	if err != nil {
		return nil, nil, err
	}
	c, err := xdsclient.New(
		conn,
		xdsclient.Config{Node: &core.Node{Id: id, Metadata: metadata}, Watches: xdsstore.Watches()},
	)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			return nil, nil, fmt.Errorf("%w (close connection: %w)", err, closeErr)
		}
		return nil, nil, err
	}
	return c, conn, nil
}
