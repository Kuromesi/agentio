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

// Package workloadv1 exposes the istio.workload protobuf types used by the
// control plane. Type aliases keep a single protobuf namespace registration
// while preserving message full names and anypb type URLs
// (type.googleapis.com/istio.workload.*).
package workloadv1

import "istio.io/istio/pkg/workloadapi"

type (
	Address                    = workloadapi.Address
	Address_Service            = workloadapi.Address_Service
	Address_Workload           = workloadapi.Address_Workload
	AppProtocol                = workloadapi.AppProtocol
	ApplicationTunnel          = workloadapi.ApplicationTunnel
	ApplicationTunnel_Protocol = workloadapi.ApplicationTunnel_Protocol
	Extension                  = workloadapi.Extension
	GatewayAddress             = workloadapi.GatewayAddress
	GatewayAddress_Address     = workloadapi.GatewayAddress_Address
	GatewayAddress_Hostname    = workloadapi.GatewayAddress_Hostname
	IPFamilies                 = workloadapi.IPFamilies
	LoadBalancing              = workloadapi.LoadBalancing
	LoadBalancing_HealthPolicy = workloadapi.LoadBalancing_HealthPolicy
	LoadBalancing_Mode         = workloadapi.LoadBalancing_Mode
	LoadBalancing_Scope        = workloadapi.LoadBalancing_Scope
	Locality                   = workloadapi.Locality
	NamespacedHostname         = workloadapi.NamespacedHostname
	NetworkAddress             = workloadapi.NetworkAddress
	NetworkMode                = workloadapi.NetworkMode
	Port                       = workloadapi.Port
	PortList                   = workloadapi.PortList
	Service                    = workloadapi.Service
	TunnelProtocol             = workloadapi.TunnelProtocol
	Workload                   = workloadapi.Workload
	WorkloadStatus             = workloadapi.WorkloadStatus
	WorkloadType               = workloadapi.WorkloadType
)

const (
	TunnelProtocol_NONE              = workloadapi.TunnelProtocol_NONE
	TunnelProtocol_HBONE             = workloadapi.TunnelProtocol_HBONE
	TunnelProtocol_LEGACY_ISTIO_MTLS = workloadapi.TunnelProtocol_LEGACY_ISTIO_MTLS

	NetworkMode_STANDARD     = workloadapi.NetworkMode_STANDARD
	NetworkMode_HOST_NETWORK = workloadapi.NetworkMode_HOST_NETWORK

	WorkloadType_DEPLOYMENT = workloadapi.WorkloadType_DEPLOYMENT
	WorkloadType_CRONJOB    = workloadapi.WorkloadType_CRONJOB
	WorkloadType_POD        = workloadapi.WorkloadType_POD
	WorkloadType_JOB        = workloadapi.WorkloadType_JOB

	WorkloadStatus_HEALTHY   = workloadapi.WorkloadStatus_HEALTHY
	WorkloadStatus_UNHEALTHY = workloadapi.WorkloadStatus_UNHEALTHY

	AppProtocol_UNKNOWN = workloadapi.AppProtocol_UNKNOWN
	AppProtocol_HTTP11  = workloadapi.AppProtocol_HTTP11
	AppProtocol_HTTP2   = workloadapi.AppProtocol_HTTP2
	AppProtocol_GRPC    = workloadapi.AppProtocol_GRPC

	IPFamilies_AUTOMATIC = workloadapi.IPFamilies_AUTOMATIC
	IPFamilies_IPV4_ONLY = workloadapi.IPFamilies_IPV4_ONLY
	IPFamilies_IPV6_ONLY = workloadapi.IPFamilies_IPV6_ONLY
	IPFamilies_DUAL      = workloadapi.IPFamilies_DUAL

	LoadBalancing_UNSPECIFIED_SCOPE = workloadapi.LoadBalancing_UNSPECIFIED_SCOPE
	LoadBalancing_REGION            = workloadapi.LoadBalancing_REGION
	LoadBalancing_ZONE              = workloadapi.LoadBalancing_ZONE
	LoadBalancing_SUBZONE           = workloadapi.LoadBalancing_SUBZONE
	LoadBalancing_NODE              = workloadapi.LoadBalancing_NODE
	LoadBalancing_CLUSTER           = workloadapi.LoadBalancing_CLUSTER
	LoadBalancing_NETWORK           = workloadapi.LoadBalancing_NETWORK

	LoadBalancing_UNSPECIFIED_MODE = workloadapi.LoadBalancing_UNSPECIFIED_MODE
	LoadBalancing_STRICT           = workloadapi.LoadBalancing_STRICT
	LoadBalancing_FAILOVER         = workloadapi.LoadBalancing_FAILOVER
	LoadBalancing_PASSTHROUGH      = workloadapi.LoadBalancing_PASSTHROUGH

	LoadBalancing_ONLY_HEALTHY = workloadapi.LoadBalancing_ONLY_HEALTHY
	LoadBalancing_ALLOW_ALL    = workloadapi.LoadBalancing_ALLOW_ALL

	ApplicationTunnel_NONE  = workloadapi.ApplicationTunnel_NONE
	ApplicationTunnel_PROXY = workloadapi.ApplicationTunnel_PROXY
)
