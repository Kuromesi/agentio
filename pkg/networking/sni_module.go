// Copyright 2026 The Kruise Authors
// SPDX-License-Identifier: Apache-2.0
package networking

import (
	udpatypev1 "github.com/cncf/xds/go/udpa/type/v1"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/types/known/structpb"
)

func sniPolicyListenerFilter() *listenerv3.ListenerFilter {
	fields, err := structpb.NewStruct(map[string]any{
		"dynamic_module_config": map[string]any{
			"name": "envoy_agentio_sni_policy",
			"module": map[string]any{
				"local": map[string]any{"filename": "/usr/local/lib/libenvoy_agentio_sni_policy.so"},
			},
		},
		"filter_name": "envoy_agentio_sni_policy",
	})
	if err != nil {
		panic(err)
	}
	return &listenerv3.ListenerFilter{
		Name: "envoy.filters.listener.dynamic_modules",
		ConfigType: &listenerv3.ListenerFilter_TypedConfig{TypedConfig: mustPack(&udpatypev1.TypedStruct{
			TypeUrl: "type.googleapis.com/envoy.extensions.filters.listener.dynamic_modules.v3.DynamicModuleListenerFilter",
			Value:   fields,
		})},
	}
}
