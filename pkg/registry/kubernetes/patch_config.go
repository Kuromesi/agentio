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

package kubernetes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"go.yaml.in/yaml/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	strictjson "sigs.k8s.io/json"

	"github.com/openkruise/agentio/pkg/model"
)

// patchConfig is a plain configuration payload, not a Kubernetes resource.
// The containing ConfigMap supplies its identity and source revision.
type patchConfig struct {
	TargetGateways []string     `json:"targetGateways"`
	Priority       int32        `json:"priority,omitempty"`
	Patches        []patchEntry `json:"patches"`
}

type patchEntry struct {
	Target    string          `json:"target"`
	Operation string          `json:"operation"`
	Match     json.RawMessage `json:"match,omitempty"`
	Value     json.RawMessage `json:"value,omitempty"`
}

var patchOperations = map[string]model.PatchOperation{
	"ADD":           model.PatchAdd,
	"MERGE":         model.PatchMerge,
	"REMOVE":        model.PatchRemove,
	"REPLACE":       model.PatchReplace,
	"INSERT_BEFORE": model.PatchInsertBefore,
	"INSERT_AFTER":  model.PatchInsertAfter,
	"INSERT_FIRST":  model.PatchInsertFirst,
}

func decodePatchConfig(configMap *corev1.ConfigMap) (*model.GatewayPatch, error) {
	content := configMap.Data[KubePatchDataKey]
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}
	raw, err := patchConfigJSON(content)
	if err != nil {
		return nil, err
	}
	var config patchConfig
	if err := decodePatchObject(raw, &config); err != nil {
		return nil, err
	}
	for index, target := range config.TargetGateways {
		namespace, name, found := strings.Cut(target, "/")
		if !found || len(validation.IsDNS1123Label(namespace)) > 0 || len(validation.IsDNS1123Subdomain(name)) > 0 {
			return nil, fmt.Errorf("targetGateways[%d]: expected namespace/name", index)
		}
	}
	patches := make([]model.EnvoyPatch, 0, len(config.Patches))
	for index, rawPatch := range config.Patches {
		patch, err := decodePatch(rawPatch)
		if err != nil {
			return nil, fmt.Errorf("patches[%d]: %w", index, err)
		}
		patches = append(patches, patch)
	}
	result, err := model.NewGatewayPatch(model.GatewayPatchMetadata{
		Namespace:       configMap.Namespace,
		Name:            configMap.Name,
		Source:          configMap.Namespace + "/" + configMap.Name,
		ResourceVersion: configMap.ResourceVersion,
		// A fixed timestamp makes equal-priority ConfigMap sources sort by name.
	}, config.Priority, config.TargetGateways, patches)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// Decode the complete YAML stream before JSON conversion. yaml.v3 rejects
// duplicate mapping keys, including nested value keys; JSON preserves uint64s.
func patchConfigJSON(content string) ([]byte, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode YAML: %w", err)
	}
	if _, ok := document.(map[string]any); !ok {
		return nil, fmt.Errorf("expected one YAML object")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("decode trailing YAML: %w", err)
		}
		return nil, fmt.Errorf("expected one YAML document")
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("convert YAML object to JSON: %w", err)
	}
	return raw, nil
}

func decodePatchObject(raw json.RawMessage, target any) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return fmt.Errorf("expected an object")
	}
	strictErrors, err := strictjson.UnmarshalStrict(raw, target)
	if err != nil {
		return err
	}
	return errors.Join(strictErrors...)
}

func decodePatch(input patchEntry) (model.EnvoyPatch, error) {
	operation, found := patchOperations[input.Operation]
	if !found {
		return model.EnvoyPatch{}, fmt.Errorf("operation: unknown operation %q", input.Operation)
	}
	if operation == model.PatchRemove {
		if len(input.Value) != 0 {
			return model.EnvoyPatch{}, fmt.Errorf("value: REMOVE must omit value")
		}
	} else if raw := bytes.TrimSpace(input.Value); len(raw) == 0 || raw[0] != '{' {
		return model.EnvoyPatch{}, fmt.Errorf("value: %s requires an object", input.Operation)
	}
	match, err := decodePatchMatch(input.Target, operation, input.Match)
	if err != nil {
		return model.EnvoyPatch{}, fmt.Errorf("match: %w", err)
	}
	target, err := decodePatchTarget(input.Target, match, input.Value)
	if err != nil {
		return model.EnvoyPatch{}, fmt.Errorf("value: %w", err)
	}
	return model.EnvoyPatch{Operation: operation, Target: target}, nil
}

func decodePatchTarget(kind string, match patchMatch, raw json.RawMessage) (model.PatchTarget, error) {
	switch kind {
	case "cluster":
		value, err := decodePatchValue(raw, &clusterv3.Cluster{})
		return model.ClusterPatch{Match: match.cluster, Value: value}, err
	case "listener":
		value, err := decodePatchValue(raw, &listenerv3.Listener{})
		return model.ListenerPatch{Match: match.listener, Value: value}, err
	case "listenerFilter":
		value, err := decodePatchValue(raw, &listenerv3.ListenerFilter{})
		return model.ListenerFilterPatch{Match: match.listener, Value: value}, err
	case "filterChain":
		value, err := decodePatchValue(raw, &listenerv3.FilterChain{})
		return model.FilterChainPatch{Match: match.listener, Value: value}, err
	case "networkFilter":
		value, err := decodePatchValue(raw, &listenerv3.Filter{})
		return model.NetworkFilterPatch{Match: match.listener, Value: value}, err
	case "httpFilter":
		value, err := decodePatchValue(raw, &hcmv3.HttpFilter{})
		return model.HTTPFilterPatch{Match: match.listener, Value: value}, err
	case "routeConfiguration":
		value, err := decodePatchValue(raw, &routev3.RouteConfiguration{})
		return model.RouteConfigurationPatch{Match: match.route, Value: value}, err
	case "virtualHost":
		value, err := decodePatchValue(raw, &routev3.VirtualHost{})
		return model.VirtualHostPatch{Match: match.route, Value: value}, err
	case "httpRoute":
		value, err := decodePatchValue(raw, &routev3.Route{})
		return model.HTTPRoutePatch{Match: match.route, Value: value}, err
	case "extensionConfiguration":
		value, err := decodePatchValue(raw, &corev3.TypedExtensionConfig{})
		return model.ExtensionConfigurationPatch{Value: value}, err
	default:
		return nil, fmt.Errorf("unknown target %q", kind)
	}
}

func decodePatchValue[T proto.Message](raw json.RawMessage, value T) (T, error) {
	if len(raw) == 0 {
		var empty T
		return empty, nil
	}
	err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, value)
	return value, err
}
