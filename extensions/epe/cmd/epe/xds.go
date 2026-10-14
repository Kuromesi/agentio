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
	"flag"
	"fmt"
	"os"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc"
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

func newEgressXDS() (*xdsclient.Client, *grpc.ClientConn, error) {
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
	conn, err := xdsclient.Dial(*xdsAddress, *xdsRootPath, *xdsTokenPath)
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
