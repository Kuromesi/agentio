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

package model

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/util/sets"
)

type PatchOperation uint8

const (
	PatchAdd PatchOperation = iota + 1
	PatchMerge
	PatchRemove
	PatchReplace
	PatchInsertBefore
	PatchInsertAfter
	PatchInsertFirst
)

func (o PatchOperation) valid() bool { return o >= PatchAdd && o <= PatchInsertFirst }

type RouteAction uint8

const (
	RouteActionAny RouteAction = iota
	RouteActionRoute
	RouteActionRedirect
	RouteActionDirectResponse
)

type GatewayPatchMetadata struct {
	Namespace       string
	Name            string
	Source          string
	ResourceVersion string
	CreationTime    time.Time
}

// GatewayPatch is a source-qualified, validated patch plan for exact
// egress Gateways. It intentionally contains no Istio API types.
type GatewayPatch struct {
	Namespace       string
	Name            string
	Source          string
	ResourceVersion string
	CreationTime    time.Time
	Priority        int32
	TargetGateways  []string
	Patches         []EnvoyPatch
}

type EnvoyPatch struct {
	Operation PatchOperation
	Target    PatchTarget
}

// PatchTarget is sealed so every accepted target binds one match family to one
// concrete Envoy protobuf value.
type PatchTarget interface{ isPatchTarget() }

type ClusterMatch struct {
	Name       string
	Service    string
	Subset     string
	PortNumber uint32
}

type ListenerMatch struct {
	Name           string
	PortNumber     uint32
	ListenerFilter string
	FilterChain    *FilterChainMatch
}

type FilterChainMatch struct {
	Name                 string
	SNI                  string
	TransportProtocol    string
	ApplicationProtocols string
	DestinationPort      uint32
	Filter               *FilterMatch
}

type FilterMatch struct {
	Name      string
	SubFilter *SubFilterMatch
}

type SubFilterMatch struct{ Name string }

type RouteConfigurationMatch struct {
	Name        string
	PortName    string
	Gateway     string
	PortNumber  uint32
	VirtualHost *VirtualHostMatch
}

type VirtualHostMatch struct {
	Name       string
	DomainName string
	Route      *RouteMatch
}

type RouteMatch struct {
	Name   string
	Action RouteAction
}

type ClusterPatch struct {
	Match *ClusterMatch
	Value *clusterv3.Cluster
}

type ListenerPatch struct {
	Match *ListenerMatch
	Value *listenerv3.Listener
}

type ListenerFilterPatch struct {
	Match *ListenerMatch
	Value *listenerv3.ListenerFilter
}

type FilterChainPatch struct {
	Match *ListenerMatch
	Value *listenerv3.FilterChain
}

type NetworkFilterPatch struct {
	Match *ListenerMatch
	Value *listenerv3.Filter
}

type HTTPFilterPatch struct {
	Match *ListenerMatch
	Value *hcmv3.HttpFilter
}

type RouteConfigurationPatch struct {
	Match *RouteConfigurationMatch
	Value *routev3.RouteConfiguration
}

type VirtualHostPatch struct {
	Match *RouteConfigurationMatch
	Value *routev3.VirtualHost
}

type HTTPRoutePatch struct {
	Match *RouteConfigurationMatch
	Value *routev3.Route
}

type ExtensionConfigurationPatch struct{ Value *corev3.TypedExtensionConfig }

func (ClusterPatch) isPatchTarget()                {}
func (ListenerPatch) isPatchTarget()               {}
func (ListenerFilterPatch) isPatchTarget()         {}
func (FilterChainPatch) isPatchTarget()            {}
func (NetworkFilterPatch) isPatchTarget()          {}
func (HTTPFilterPatch) isPatchTarget()             {}
func (RouteConfigurationPatch) isPatchTarget()     {}
func (VirtualHostPatch) isPatchTarget()            {}
func (HTTPRoutePatch) isPatchTarget()              {}
func (ExtensionConfigurationPatch) isPatchTarget() {}

func NewGatewayPatch(
	metadata GatewayPatchMetadata,
	priority int32,
	targets []string,
	patches []EnvoyPatch,
) (GatewayPatch, error) {
	if metadata.Namespace == "" || metadata.Name == "" || metadata.Source == "" {
		return GatewayPatch{}, fmt.Errorf("GatewayPatch namespace, name, and source are required")
	}
	targetSet := sets.NewWithLength[string](len(targets))
	for _, target := range targets {
		if target == "" {
			return GatewayPatch{}, fmt.Errorf("GatewayPatch target is empty")
		}
		targetSet.Insert(target)
	}
	normalizedTargets := make([]string, 0, len(targetSet))
	for target := range targetSet {
		normalizedTargets = append(normalizedTargets, target)
	}
	if len(normalizedTargets) == 0 {
		return GatewayPatch{}, fmt.Errorf("GatewayPatch requires at least one target")
	}
	if len(patches) == 0 {
		return GatewayPatch{}, fmt.Errorf("GatewayPatch requires at least one patch")
	}
	sort.Strings(normalizedTargets)
	for index, patch := range patches {
		if !patch.Operation.valid() {
			return GatewayPatch{}, fmt.Errorf("gateway patch %d has invalid operation %d", index, patch.Operation)
		}
		if patch.Target == nil {
			return GatewayPatch{}, fmt.Errorf("gateway patch %d has no target", index)
		}
		present, supported := patchTargetHasValue(patch.Target)
		if !supported {
			return GatewayPatch{}, fmt.Errorf("gateway patch %d has unsupported target %T", index, patch.Target)
		}
		if !patchTargetSupportsOperation(patch.Target, patch.Operation) {
			return GatewayPatch{}, fmt.Errorf("gateway patch %d target %T does not support operation %d",
				index, patch.Target, patch.Operation)
		}
		if patch.Operation != PatchRemove && !present {
			return GatewayPatch{}, fmt.Errorf("gateway patch %d operation %d requires a value", index, patch.Operation)
		}
	}
	result := GatewayPatch{
		Namespace:       metadata.Namespace,
		Name:            metadata.Name,
		Source:          metadata.Source,
		ResourceVersion: metadata.ResourceVersion,
		CreationTime:    metadata.CreationTime,
		Priority:        priority,
		TargetGateways:  normalizedTargets,
		Patches:         append([]EnvoyPatch(nil), patches...),
	}
	return result.Clone(), nil
}

func patchTargetSupportsOperation(target PatchTarget, operation PatchOperation) bool {
	switch target.(type) {
	case ClusterPatch, ListenerPatch, FilterChainPatch:
		return operation == PatchAdd || operation == PatchMerge || operation == PatchRemove
	case ListenerFilterPatch, NetworkFilterPatch, HTTPFilterPatch:
		return operation >= PatchAdd && operation <= PatchInsertFirst
	case RouteConfigurationPatch:
		return operation == PatchMerge
	case VirtualHostPatch:
		return operation == PatchAdd || operation == PatchMerge || operation == PatchRemove || operation == PatchReplace
	case HTTPRoutePatch:
		return operation == PatchAdd || operation == PatchMerge || operation == PatchRemove ||
			operation == PatchInsertBefore || operation == PatchInsertAfter || operation == PatchInsertFirst
	case ExtensionConfigurationPatch:
		return operation == PatchAdd
	default:
		return false
	}
}

func (p GatewayPatch) LogicalName() string { return p.Namespace + "/" + p.Name }

func (p GatewayPatch) ResourceName() string { return p.Source + "|" + p.LogicalName() }

func (p GatewayPatch) Equals(other GatewayPatch) bool {
	if p.Namespace != other.Namespace || p.Name != other.Name || p.Source != other.Source ||
		p.ResourceVersion != other.ResourceVersion || !p.CreationTime.Equal(other.CreationTime) ||
		p.Priority != other.Priority || !slices.Equal(p.TargetGateways, other.TargetGateways) ||
		len(p.Patches) != len(other.Patches) {
		return false
	}
	for index := range p.Patches {
		if p.Patches[index].Operation != other.Patches[index].Operation ||
			!patchTargetsEqual(p.Patches[index].Target, other.Patches[index].Target) {
			return false
		}
	}
	return true
}

func (p GatewayPatch) Clone() GatewayPatch {
	result := p
	result.TargetGateways = append([]string(nil), p.TargetGateways...)
	result.Patches = make([]EnvoyPatch, len(p.Patches))
	for index, patch := range p.Patches {
		result.Patches[index] = EnvoyPatch{Operation: patch.Operation, Target: clonePatchTarget(patch.Target)}
	}
	return result
}

func patchTargetHasValue(target PatchTarget) (bool, bool) {
	switch typed := target.(type) {
	case ClusterPatch:
		return typed.Value != nil, true
	case ListenerPatch:
		return typed.Value != nil, true
	case ListenerFilterPatch:
		return typed.Value != nil, true
	case FilterChainPatch:
		return typed.Value != nil, true
	case NetworkFilterPatch:
		return typed.Value != nil, true
	case HTTPFilterPatch:
		return typed.Value != nil, true
	case RouteConfigurationPatch:
		return typed.Value != nil, true
	case VirtualHostPatch:
		return typed.Value != nil, true
	case HTTPRoutePatch:
		return typed.Value != nil, true
	case ExtensionConfigurationPatch:
		return typed.Value != nil, true
	default:
		return false, false
	}
}

func patchTargetsEqual(left, right PatchTarget) bool {
	if reflect.TypeOf(left) != reflect.TypeOf(right) {
		return false
	}
	switch leftTyped := left.(type) {
	case ClusterPatch:
		rightTyped := right.(ClusterPatch)
		return reflect.DeepEqual(leftTyped.Match, rightTyped.Match) && proto.Equal(leftTyped.Value, rightTyped.Value)
	case ListenerPatch:
		rightTyped := right.(ListenerPatch)
		return reflect.DeepEqual(leftTyped.Match, rightTyped.Match) && proto.Equal(leftTyped.Value, rightTyped.Value)
	case ListenerFilterPatch:
		rightTyped := right.(ListenerFilterPatch)
		return reflect.DeepEqual(leftTyped.Match, rightTyped.Match) && proto.Equal(leftTyped.Value, rightTyped.Value)
	case FilterChainPatch:
		rightTyped := right.(FilterChainPatch)
		return reflect.DeepEqual(leftTyped.Match, rightTyped.Match) && proto.Equal(leftTyped.Value, rightTyped.Value)
	case NetworkFilterPatch:
		rightTyped := right.(NetworkFilterPatch)
		return reflect.DeepEqual(leftTyped.Match, rightTyped.Match) && proto.Equal(leftTyped.Value, rightTyped.Value)
	case HTTPFilterPatch:
		rightTyped := right.(HTTPFilterPatch)
		return reflect.DeepEqual(leftTyped.Match, rightTyped.Match) && proto.Equal(leftTyped.Value, rightTyped.Value)
	case RouteConfigurationPatch:
		rightTyped := right.(RouteConfigurationPatch)
		return reflect.DeepEqual(leftTyped.Match, rightTyped.Match) && proto.Equal(leftTyped.Value, rightTyped.Value)
	case VirtualHostPatch:
		rightTyped := right.(VirtualHostPatch)
		return reflect.DeepEqual(leftTyped.Match, rightTyped.Match) && proto.Equal(leftTyped.Value, rightTyped.Value)
	case HTTPRoutePatch:
		rightTyped := right.(HTTPRoutePatch)
		return reflect.DeepEqual(leftTyped.Match, rightTyped.Match) && proto.Equal(leftTyped.Value, rightTyped.Value)
	case ExtensionConfigurationPatch:
		return proto.Equal(leftTyped.Value, right.(ExtensionConfigurationPatch).Value)
	default:
		return false
	}
}

func clonePatchTarget(target PatchTarget) PatchTarget {
	switch typed := target.(type) {
	case ClusterPatch:
		return ClusterPatch{Match: cloneValue(typed.Match), Value: cloneProto(typed.Value)}
	case ListenerPatch:
		return ListenerPatch{Match: cloneListenerMatch(typed.Match), Value: cloneProto(typed.Value)}
	case ListenerFilterPatch:
		return ListenerFilterPatch{Match: cloneListenerMatch(typed.Match), Value: cloneProto(typed.Value)}
	case FilterChainPatch:
		return FilterChainPatch{Match: cloneListenerMatch(typed.Match), Value: cloneProto(typed.Value)}
	case NetworkFilterPatch:
		return NetworkFilterPatch{Match: cloneListenerMatch(typed.Match), Value: cloneProto(typed.Value)}
	case HTTPFilterPatch:
		return HTTPFilterPatch{Match: cloneListenerMatch(typed.Match), Value: cloneProto(typed.Value)}
	case RouteConfigurationPatch:
		return RouteConfigurationPatch{Match: cloneRouteMatch(typed.Match), Value: cloneProto(typed.Value)}
	case VirtualHostPatch:
		return VirtualHostPatch{Match: cloneRouteMatch(typed.Match), Value: cloneProto(typed.Value)}
	case HTTPRoutePatch:
		return HTTPRoutePatch{Match: cloneRouteMatch(typed.Match), Value: cloneProto(typed.Value)}
	case ExtensionConfigurationPatch:
		return ExtensionConfigurationPatch{Value: cloneProto(typed.Value)}
	default:
		return nil
	}
}

func cloneValue[T any](value *T) *T {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneListenerMatch(value *ListenerMatch) *ListenerMatch {
	result := cloneValue(value)
	if result == nil {
		return nil
	}
	result.FilterChain = cloneValue(value.FilterChain)
	if result.FilterChain != nil {
		result.FilterChain.Filter = cloneValue(value.FilterChain.Filter)
		if result.FilterChain.Filter != nil {
			result.FilterChain.Filter.SubFilter = cloneValue(value.FilterChain.Filter.SubFilter)
		}
	}
	return result
}

func cloneRouteMatch(value *RouteConfigurationMatch) *RouteConfigurationMatch {
	result := cloneValue(value)
	if result == nil {
		return nil
	}
	result.VirtualHost = cloneValue(value.VirtualHost)
	if result.VirtualHost != nil {
		result.VirtualHost.Route = cloneValue(value.VirtualHost.Route)
	}
	return result
}

func cloneProto[T proto.Message](value T) T {
	if reflect.ValueOf(value).IsNil() {
		return value
	}
	return proto.Clone(value).(T)
}
