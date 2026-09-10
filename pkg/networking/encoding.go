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

package networking

import (
	"fmt"

	"github.com/openkruise/agentio/pkg/util/protoutil"

	xdscorev3 "github.com/cncf/xds/go/xds/core/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

// resourceBuilder belongs to one build. Nested helpers record the first encoding
// failure; the entry points discard the entire result if any extension failed.
type resourceBuilder struct {
	err error
}

func (b *resourceBuilder) pack(message proto.Message) *anypb.Any {
	if b.err != nil {
		return nil
	}
	value, err := protoutil.MarshalAny(message)
	if err != nil {
		b.err = fmt.Errorf("marshal gateway extension %T: %w", message, err)
	}
	return value
}

func buildClusters(config effectiveConfig) ([]*clusterv3.Cluster, error) {
	b := &resourceBuilder{}
	result, err := b.buildClusters(config)
	if b.err != nil {
		return nil, b.err
	}
	return result, err
}

func buildListeners(config effectiveConfig, trustDomain string) ([]*listenerv3.Listener, error) {
	b := &resourceBuilder{}
	result, err := b.buildListeners(config, trustDomain)
	if b.err != nil {
		return nil, b.err
	}
	return result, err
}

// staticTypedExtension is only for the fixed, empty matcher inputs below.
// User configuration must use a per-build resourceBuilder so errors propagate.
func staticTypedExtension(name string, message proto.Message) *xdscorev3.TypedExtensionConfig {
	b := &resourceBuilder{}
	result := b.typedExtension(name, message)
	if b.err != nil {
		panic(b.err)
	}
	return result
}

func buildRoutes(config *configv1.EgressGateway) ([]*routev3.RouteConfiguration, error) {
	b := &resourceBuilder{}
	result, err := b.buildRoutes(config)
	if b.err != nil {
		return nil, b.err
	}
	return result, err
}

func (b *resourceBuilder) structure(fields map[string]any) *structpb.Struct {
	if b.err != nil {
		return nil
	}
	value, err := structpb.NewStruct(fields)
	if err != nil {
		b.err = fmt.Errorf("marshal gateway extension fields: %w", err)
	}
	return value
}
