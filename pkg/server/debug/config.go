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

package debug

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/model"
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

type configDebugFilter struct {
	Kind      string
	Namespace string
	Name      string
	Pretty    bool
}

type configDebugResponse struct {
	GeneratedAt  time.Time            `json:"generatedAt"`
	Synced       bool                 `json:"synced"`
	CountsByKind map[string]int       `json:"countsByKind"`
	Items        []configDebugItem    `json:"items"`
	Failures     []configDebugFailure `json:"failures"`
}

type configDebugItem struct {
	Kind     string              `json:"kind"`
	Metadata configDebugMetadata `json:"metadata"`
	Spec     json.RawMessage     `json:"spec"`
}

type configDebugMetadata struct {
	Namespace         string     `json:"namespace,omitempty"`
	Name              string     `json:"name"`
	Source            string     `json:"source,omitempty"`
	ResourceVersion   string     `json:"resourceVersion,omitempty"`
	CreationTimestamp *time.Time `json:"creationTimestamp,omitempty"`
}

type configDebugFailure struct {
	Key     string `json:"key"`
	Message string `json:"message"`
}

func configDebugSnapshotAt(
	now time.Time,
	sources Sources,
	resourceCompiler *compiler.Compiler,
	filter configDebugFilter,
) (configDebugResponse, error) {
	result := configDebugResponse{
		GeneratedAt:  now.UTC().Truncate(time.Second),
		Synced:       configDebugInputsSynced(sources) && resourceCompiler.HasSynced(),
		CountsByKind: make(map[string]int),
		Items:        make([]configDebugItem, 0),
		Failures:     configDebugFailures(resourceCompiler.Failures()),
	}
	appendItem := func(item configDebugItem) {
		if !configDebugItemMatches(item, filter) {
			return
		}
		result.Items = append(result.Items, item)
		result.CountsByKind[item.Kind]++
	}

	for _, configuration := range sources.AgentioConfig.List() {
		item, err := configDebugAgentioConfig(configuration)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt AgentioConfig %q: %w", configuration.ResourceName(), err)
		}
		appendItem(item)
	}
	for _, policy := range sources.TrafficPolicies.List() {
		item, err := configDebugTrafficPolicy(policy)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt TrafficPolicy %q: %w", policy.ResourceName(), err)
		}
		appendItem(item)
	}
	for _, profile := range sources.SecurityProfiles.List() {
		item, err := configDebugSecurityProfile(profile)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt SecurityProfile %q: %w", profile.ResourceName(), err)
		}
		appendItem(item)
	}
	for _, gateway := range sources.Gateways.List() {
		item, err := configDebugGateway(gateway)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt Gateway %q: %w", gateway.ResourceName(), err)
		}
		appendItem(item)
	}
	for _, patch := range sources.GatewayPatches.List() {
		item, err := configDebugGatewayPatch(patch)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt EnvoyFilter %q: %w", patch.ResourceName(), err)
		}
		appendItem(item)
	}
	for _, telemetry := range sources.Telemetry.List() {
		item, err := configDebugTelemetry(telemetry)
		if err != nil {
			return configDebugResponse{}, fmt.Errorf("adapt Telemetry %q: %w", telemetry.ResourceName(), err)
		}
		appendItem(item)
	}

	sort.Slice(result.Items, func(left, right int) bool {
		a, b := result.Items[left], result.Items[right]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Metadata.Namespace != b.Metadata.Namespace {
			return a.Metadata.Namespace < b.Metadata.Namespace
		}
		if a.Metadata.Name != b.Metadata.Name {
			return a.Metadata.Name < b.Metadata.Name
		}
		return a.Metadata.Source < b.Metadata.Source
	})
	return result, nil
}

func configDebugInputsSynced(sources Sources) bool {
	return sources.AgentioConfig.HasSynced() &&
		sources.TrafficPolicies.HasSynced() &&
		sources.SecurityProfiles.HasSynced() &&
		sources.Gateways.HasSynced() &&
		sources.GatewayPatches.HasSynced() &&
		sources.Telemetry.HasSynced()
}

func configDebugFailures(failures map[string]string) []configDebugFailure {
	keys := make([]string, 0, len(failures))
	for key := range failures {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]configDebugFailure, 0, len(keys))
	for _, key := range keys {
		result = append(result, configDebugFailure{Key: key, Message: failures[key]})
	}
	return result
}

func configDebugItemMatches(item configDebugItem, filter configDebugFilter) bool {
	return (filter.Kind == "" || item.Kind == filter.Kind) &&
		(filter.Namespace == "" || item.Metadata.Namespace == filter.Namespace) &&
		(filter.Name == "" || item.Metadata.Name == filter.Name)
}

func configDebugAgentioConfig(configuration model.AgentioConfiguration) (configDebugItem, error) {
	spec, err := marshalConfigDebugProto(configuration.Value)
	return configDebugItem{
		Kind: "AgentioConfig",
		Metadata: configDebugMetadata{
			Name:            configuration.ResourceName(),
			ResourceVersion: configuration.ResourceVersion,
		},
		Spec: spec,
	}, err
}

func configDebugTrafficPolicy(policy model.TrafficPolicy) (configDebugItem, error) {
	kind, namespace := "TrafficPolicy", policy.Namespace
	if policy.Global {
		kind, namespace = "GlobalTrafficPolicy", ""
	}
	spec, err := marshalConfigDebugJSON(policy.Spec)
	return configDebugItem{
		Kind: kind,
		Metadata: configDebugMetadata{
			Namespace:         namespace,
			Name:              policy.Name,
			CreationTimestamp: configDebugTime(policy.CreationTime),
		},
		Spec: spec,
	}, err
}

func configDebugSecurityProfile(profile model.SecurityProfile) (configDebugItem, error) {
	kind, namespace := "SecurityProfile", profile.Namespace
	if profile.Global {
		kind, namespace = "GlobalSecurityProfile", ""
	}
	safeSpec := profile.Spec.DeepCopy()
	redactConfigDebugSecurityProfile(safeSpec)
	spec, err := marshalConfigDebugJSON(safeSpec)
	return configDebugItem{
		Kind: kind,
		Metadata: configDebugMetadata{
			Namespace:         namespace,
			Name:              profile.Name,
			CreationTimestamp: configDebugTime(profile.CreationTime),
		},
		Spec: spec,
	}, err
}

func redactConfigDebugSecurityProfile(spec *agentsv1alpha1.SecurityProfileSpec) {
	for inputIndex := range spec.Inputs {
		for key := range spec.Inputs[inputIndex].Inline {
			spec.Inputs[inputIndex].Inline[key] = "[REDACTED]"
		}
	}
	redactConfigDebugAuditHeaders(spec.Audit)
	for ruleIndex := range spec.Rules {
		headers := spec.Rules[ruleIndex].Actions.HeaderManipulation
		if headers != nil {
			for headerIndex := range headers.Set {
				headers.Set[headerIndex].Value = "[REDACTED]"
			}
		}
		redactConfigDebugAuditHeaders(spec.Rules[ruleIndex].Actions.Audit)
	}
}

func redactConfigDebugAuditHeaders(actions []agentsv1alpha1.AuditAction) {
	for actionIndex := range actions {
		webhook := actions[actionIndex].Webhook
		if webhook == nil || webhook.Request == nil {
			continue
		}
		for headerIndex := range webhook.Request.Headers {
			webhook.Request.Headers[headerIndex].Value = "[REDACTED]"
		}
	}
}

func configDebugGateway(gateway model.Gateway) (configDebugItem, error) {
	spec, err := marshalConfigDebugProto(gateway.Config)
	return configDebugItem{
		Kind: "Gateway",
		Metadata: configDebugMetadata{
			Namespace: gateway.Namespace,
			Name:      gateway.Name,
			Source:    string(gateway.Source),
		},
		Spec: spec,
	}, err
}

func configDebugGatewayPatch(patch model.GatewayPatch) (configDebugItem, error) {
	patches := make([]configDebugEnvoyPatch, 0, len(patch.Patches))
	for index, envoyPatch := range patch.Patches {
		adapted, err := configDebugPatch(envoyPatch)
		if err != nil {
			return configDebugItem{}, fmt.Errorf("patch %d: %w", index, err)
		}
		patches = append(patches, adapted)
	}
	spec, err := marshalConfigDebugJSON(configDebugGatewayPatchSpec{
		Priority:       patch.Priority,
		TargetGateways: append([]string(nil), patch.TargetGateways...),
		Patches:        patches,
	})
	return configDebugItem{
		Kind: "EnvoyFilter",
		Metadata: configDebugMetadata{
			Namespace:         patch.Namespace,
			Name:              patch.Name,
			Source:            patch.Source,
			ResourceVersion:   patch.ResourceVersion,
			CreationTimestamp: configDebugTime(patch.CreationTime),
		},
		Spec: spec,
	}, err
}

func configDebugTelemetry(telemetry model.Telemetry) (configDebugItem, error) {
	metrics := make([]configDebugTelemetryMetrics, 0, len(telemetry.Metrics))
	for _, entry := range telemetry.Metrics {
		metrics = append(metrics, configDebugMetrics(entry))
	}
	tracing := make([]configDebugTelemetryTracing, 0, len(telemetry.Tracing))
	for _, entry := range telemetry.Tracing {
		tracing = append(tracing, configDebugTracing(entry))
	}
	logging := make([]configDebugTelemetryLogging, 0, len(telemetry.AccessLogging))
	for _, entry := range telemetry.AccessLogging {
		logging = append(logging, configDebugLogging(entry))
	}
	spec, err := marshalConfigDebugJSON(configDebugTelemetrySpec{
		TargetGateways: append([]string(nil), telemetry.TargetGateways...),
		Metrics:        metrics,
		Tracing:        tracing,
		AccessLogging:  logging,
	})
	return configDebugItem{
		Kind: "Telemetry",
		Metadata: configDebugMetadata{
			Namespace:         telemetry.Namespace,
			Name:              telemetry.Name,
			Source:            telemetry.Source,
			ResourceVersion:   telemetry.ResourceVersion,
			CreationTimestamp: configDebugTime(telemetry.CreationTime),
		},
		Spec: spec,
	}, err
}

func configDebugTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	result := value.UTC()
	return &result
}

func marshalConfigDebugProto(message proto.Message) (json.RawMessage, error) {
	if message == nil {
		return json.RawMessage(`{}`), nil
	}
	safeMessage := proto.Clone(message)
	if err := redactConfigDebugProto(safeMessage.ProtoReflect()); err != nil {
		return nil, err
	}
	encoded, err := protojson.MarshalOptions{}.Marshal(safeMessage)
	if err != nil {
		return nil, err
	}
	return redactConfigDebugJSON(encoded)
}

const (
	configDebugAnyMessage         protoreflect.FullName = "google.protobuf.Any"
	configDebugDataSourceMessage  protoreflect.FullName = "envoy.config.core.v3.DataSource"
	configDebugHeaderValueMessage protoreflect.FullName = "envoy.config.core.v3.HeaderValue"
)

func redactConfigDebugProto(message protoreflect.Message) error {
	if message.Descriptor().FullName() == configDebugAnyMessage {
		wrapped, ok := message.Interface().(*anypb.Any)
		if !ok {
			return fmt.Errorf("redact protobuf Any concrete type %T", message.Interface())
		}
		embedded, err := anypb.UnmarshalNew(wrapped, proto.UnmarshalOptions{})
		if err != nil {
			return fmt.Errorf("unmarshal protobuf Any %q: %w", wrapped.TypeUrl, err)
		}
		if err := redactConfigDebugProto(embedded.ProtoReflect()); err != nil {
			return err
		}
		if err := wrapped.MarshalFrom(embedded); err != nil {
			return fmt.Errorf("marshal redacted protobuf Any %q: %w", wrapped.TypeUrl, err)
		}
		return nil
	}

	switch message.Descriptor().FullName() {
	case configDebugDataSourceMessage:
		redactConfigDebugProtoField(message, "inline_string")
		redactConfigDebugProtoField(message, "inline_bytes")
	case configDebugHeaderValueMessage:
		redactConfigDebugProtoField(message, "value")
		redactConfigDebugProtoField(message, "raw_value")
	}

	var nestedErr error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if nestedErr != nil {
			return false
		}
		switch {
		case field.IsMap() && field.MapValue().Kind() == protoreflect.MessageKind:
			value.Map().Range(func(_ protoreflect.MapKey, nested protoreflect.Value) bool {
				nestedErr = redactConfigDebugProto(nested.Message())
				return nestedErr == nil
			})
		case field.IsList() && field.Kind() == protoreflect.MessageKind:
			list := value.List()
			for index := 0; index < list.Len() && nestedErr == nil; index++ {
				nestedErr = redactConfigDebugProto(list.Get(index).Message())
			}
		case field.Kind() == protoreflect.MessageKind:
			nestedErr = redactConfigDebugProto(value.Message())
		}
		return nestedErr == nil
	})
	return nestedErr
}

func redactConfigDebugProtoField(message protoreflect.Message, name protoreflect.Name) {
	field := message.Descriptor().Fields().ByName(name)
	if field == nil || !message.Has(field) {
		return
	}
	switch field.Kind() {
	case protoreflect.StringKind:
		message.Set(field, protoreflect.ValueOfString("[REDACTED]"))
	case protoreflect.BytesKind:
		message.Set(field, protoreflect.ValueOfBytes([]byte("[REDACTED]")))
	}
}

func marshalConfigDebugJSON(value any) (json.RawMessage, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return redactConfigDebugJSON(encoded)
}

func redactConfigDebugJSON(encoded []byte) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	redactConfigDebugValue(value)
	return json.Marshal(value)
}

func redactConfigDebugValue(value any) {
	switch current := value.(type) {
	case map[string]any:
		for key, nested := range current {
			normalized := configDebugNormalizedName(key)
			if configDebugSensitiveScalarField(normalized, nested) {
				current[key] = "[REDACTED]"
				continue
			}
			redactConfigDebugValue(nested)
		}
	case []any:
		for _, nested := range current {
			redactConfigDebugValue(nested)
		}
	}
}

func configDebugSensitiveScalarField(normalized string, value any) bool {
	if _, scalar := value.(string); !scalar {
		return false
	}
	return strings.Contains(normalized, "authorization") || strings.Contains(normalized, "password") ||
		strings.Contains(normalized, "token") || strings.Contains(normalized, "secret") ||
		strings.Contains(normalized, "credential") || strings.Contains(normalized, "apikey") ||
		strings.Contains(normalized, "privatekey")
}

func configDebugNormalizedName(value string) string {
	return strings.Map(func(character rune) rune {
		switch character {
		case '-', '_', ' ', '.':
			return -1
		default:
			return character
		}
	}, strings.ToLower(value))
}

type configDebugGatewayPatchSpec struct {
	Priority       int32                   `json:"priority,omitempty"`
	TargetGateways []string                `json:"targetGateways,omitempty"`
	Patches        []configDebugEnvoyPatch `json:"patches"`
}

type configDebugEnvoyPatch struct {
	Operation string          `json:"operation"`
	Target    string          `json:"target"`
	Match     any             `json:"match,omitempty"`
	Value     json.RawMessage `json:"value,omitempty"`
}

func configDebugPatch(patch model.EnvoyPatch) (configDebugEnvoyPatch, error) {
	result := configDebugEnvoyPatch{Operation: configDebugPatchOperation(patch.Operation)}
	var value proto.Message
	switch target := patch.Target.(type) {
	case model.ClusterPatch:
		result.Target, result.Match, value = "cluster", configDebugClusterMatchValue(target.Match), target.Value
	case model.ListenerPatch:
		result.Target, result.Match, value = "listener", configDebugListenerMatchValue(target.Match), target.Value
	case model.ListenerFilterPatch:
		result.Target, result.Match, value = "listenerFilter", configDebugListenerMatchValue(target.Match), target.Value
	case model.FilterChainPatch:
		result.Target, result.Match, value = "filterChain", configDebugListenerMatchValue(target.Match), target.Value
	case model.NetworkFilterPatch:
		result.Target, result.Match, value = "networkFilter", configDebugListenerMatchValue(target.Match), target.Value
	case model.HTTPFilterPatch:
		result.Target, result.Match, value = "httpFilter", configDebugListenerMatchValue(target.Match), target.Value
	case model.RouteConfigurationPatch:
		result.Target, result.Match, value = "routeConfiguration", configDebugRouteConfigurationMatchValue(target.Match), target.Value
	case model.VirtualHostPatch:
		result.Target, result.Match, value = "virtualHost", configDebugRouteConfigurationMatchValue(target.Match), target.Value
	case model.HTTPRoutePatch:
		result.Target, result.Match, value = "httpRoute", configDebugRouteConfigurationMatchValue(target.Match), target.Value
	case model.ExtensionConfigurationPatch:
		result.Target, value = "extensionConfiguration", target.Value
	default:
		return configDebugEnvoyPatch{}, fmt.Errorf("unsupported patch target %T", patch.Target)
	}
	if value != nil {
		encoded, err := marshalConfigDebugProto(value)
		if err != nil {
			return configDebugEnvoyPatch{}, err
		}
		result.Value = encoded
	}
	return result, nil
}

type configDebugClusterMatch struct {
	Name       string `json:"name,omitempty"`
	Service    string `json:"service,omitempty"`
	Subset     string `json:"subset,omitempty"`
	PortNumber uint32 `json:"portNumber,omitempty"`
}

type configDebugListenerMatch struct {
	Name           string                  `json:"name,omitempty"`
	PortNumber     uint32                  `json:"portNumber,omitempty"`
	ListenerFilter string                  `json:"listenerFilter,omitempty"`
	FilterChain    *configDebugFilterChain `json:"filterChain,omitempty"`
}

type configDebugFilterChain struct {
	Name                 string                    `json:"name,omitempty"`
	SNI                  string                    `json:"sni,omitempty"`
	TransportProtocol    string                    `json:"transportProtocol,omitempty"`
	ApplicationProtocols string                    `json:"applicationProtocols,omitempty"`
	DestinationPort      uint32                    `json:"destinationPort,omitempty"`
	Filter               *configDebugNetworkFilter `json:"filter,omitempty"`
}

type configDebugNetworkFilter struct {
	Name      string                `json:"name,omitempty"`
	SubFilter *configDebugSubFilter `json:"subFilter,omitempty"`
}

type configDebugSubFilter struct {
	Name string `json:"name,omitempty"`
}

type configDebugRouteConfigurationMatch struct {
	Name        string                  `json:"name,omitempty"`
	PortName    string                  `json:"portName,omitempty"`
	Gateway     string                  `json:"gateway,omitempty"`
	PortNumber  uint32                  `json:"portNumber,omitempty"`
	VirtualHost *configDebugVirtualHost `json:"virtualHost,omitempty"`
}

type configDebugVirtualHost struct {
	Name       string            `json:"name,omitempty"`
	DomainName string            `json:"domainName,omitempty"`
	Route      *configDebugRoute `json:"route,omitempty"`
}

type configDebugRoute struct {
	Name   string `json:"name,omitempty"`
	Action string `json:"action,omitempty"`
}

func configDebugClusterMatchValue(match *model.ClusterMatch) any {
	if match == nil {
		return nil
	}
	return configDebugClusterMatch{
		Name: match.Name, Service: match.Service, Subset: match.Subset, PortNumber: match.PortNumber,
	}
}

func configDebugListenerMatchValue(match *model.ListenerMatch) any {
	if match == nil {
		return nil
	}
	return configDebugListenerMatch{
		Name:           match.Name,
		PortNumber:     match.PortNumber,
		ListenerFilter: match.ListenerFilter,
		FilterChain:    configDebugFilterChainValue(match.FilterChain),
	}
}

func configDebugFilterChainValue(match *model.FilterChainMatch) *configDebugFilterChain {
	if match == nil {
		return nil
	}
	return &configDebugFilterChain{
		Name:                 match.Name,
		SNI:                  match.SNI,
		TransportProtocol:    match.TransportProtocol,
		ApplicationProtocols: match.ApplicationProtocols,
		DestinationPort:      match.DestinationPort,
		Filter:               configDebugFilterValue(match.Filter),
	}
}

func configDebugFilterValue(match *model.FilterMatch) *configDebugNetworkFilter {
	if match == nil {
		return nil
	}
	result := &configDebugNetworkFilter{Name: match.Name}
	if match.SubFilter != nil {
		result.SubFilter = &configDebugSubFilter{Name: match.SubFilter.Name}
	}
	return result
}

func configDebugRouteConfigurationMatchValue(match *model.RouteConfigurationMatch) any {
	if match == nil {
		return nil
	}
	return configDebugRouteConfigurationMatch{
		Name:        match.Name,
		PortName:    match.PortName,
		Gateway:     match.Gateway,
		PortNumber:  match.PortNumber,
		VirtualHost: configDebugVirtualHostValue(match.VirtualHost),
	}
}

func configDebugVirtualHostValue(match *model.VirtualHostMatch) *configDebugVirtualHost {
	if match == nil {
		return nil
	}
	result := &configDebugVirtualHost{Name: match.Name, DomainName: match.DomainName}
	if match.Route != nil {
		result.Route = &configDebugRoute{Name: match.Route.Name, Action: configDebugRouteAction(match.Route.Action)}
	}
	return result
}

func configDebugPatchOperation(operation model.PatchOperation) string {
	switch operation {
	case model.PatchAdd:
		return "ADD"
	case model.PatchMerge:
		return "MERGE"
	case model.PatchRemove:
		return "REMOVE"
	case model.PatchReplace:
		return "REPLACE"
	case model.PatchInsertBefore:
		return "INSERT_BEFORE"
	case model.PatchInsertAfter:
		return "INSERT_AFTER"
	case model.PatchInsertFirst:
		return "INSERT_FIRST"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", operation)
	}
}

func configDebugRouteAction(action model.RouteAction) string {
	switch action {
	case model.RouteActionAny:
		return "ANY"
	case model.RouteActionRoute:
		return "ROUTE"
	case model.RouteActionRedirect:
		return "REDIRECT"
	case model.RouteActionDirectResponse:
		return "DIRECT_RESPONSE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", action)
	}
}

type configDebugTelemetrySpec struct {
	TargetGateways []string                      `json:"targetGateways,omitempty"`
	Metrics        []configDebugTelemetryMetrics `json:"metrics,omitempty"`
	Tracing        []configDebugTelemetryTracing `json:"tracing,omitempty"`
	AccessLogging  []configDebugTelemetryLogging `json:"accessLogging,omitempty"`
}

type configDebugTelemetryMetrics struct {
	Providers         []string                       `json:"providers,omitempty"`
	Overrides         []configDebugTelemetryOverride `json:"overrides,omitempty"`
	ReportingInterval string                         `json:"reportingInterval,omitempty"`
}

type configDebugTelemetryOverride struct {
	Match        configDebugTelemetrySelector               `json:"match"`
	Disabled     *bool                                      `json:"disabled,omitempty"`
	TagOverrides map[string]configDebugTelemetryTagOverride `json:"tagOverrides,omitempty"`
}

type configDebugTelemetrySelector struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	Mode string `json:"mode"`
}

type configDebugTelemetryTagOverride struct {
	Operation string `json:"operation"`
	Value     string `json:"value,omitempty"`
}

type configDebugTelemetryTracing struct {
	Mode                         string                           `json:"mode"`
	Providers                    []string                         `json:"providers,omitempty"`
	RandomSamplingPercentage     *float64                         `json:"randomSamplingPercentage,omitempty"`
	DisableSpanReporting         *bool                            `json:"disableSpanReporting,omitempty"`
	CustomTags                   map[string]configDebugTracingTag `json:"customTags,omitempty"`
	UseRequestIDForTraceSampling *bool                            `json:"useRequestIDForTraceSampling,omitempty"`
	EnableIstioTags              *bool                            `json:"enableIstioTags,omitempty"`
}

type configDebugTracingTag struct {
	Kind         string `json:"kind"`
	Name         string `json:"name,omitempty"`
	Value        string `json:"value,omitempty"`
	DefaultValue string `json:"defaultValue,omitempty"`
}

type configDebugTelemetryLogging struct {
	Mode      string   `json:"mode"`
	Providers []string `json:"providers,omitempty"`
	Disabled  *bool    `json:"disabled,omitempty"`
	Filter    *string  `json:"filter,omitempty"`
}

func configDebugMetrics(metrics model.TelemetryMetrics) configDebugTelemetryMetrics {
	result := configDebugTelemetryMetrics{
		Providers: append([]string(nil), metrics.Providers...),
		Overrides: make([]configDebugTelemetryOverride, 0, len(metrics.Overrides)),
	}
	if metrics.ReportingInterval != nil {
		result.ReportingInterval = metrics.ReportingInterval.String()
	}
	for _, override := range metrics.Overrides {
		tags := make(map[string]configDebugTelemetryTagOverride, len(override.TagOverrides))
		for name, tag := range override.TagOverrides {
			tags[name] = configDebugTelemetryTagOverride{
				Operation: configDebugTelemetryTagOperation(tag.Operation),
				Value:     tag.Value,
			}
		}
		result.Overrides = append(result.Overrides, configDebugTelemetryOverride{
			Match: configDebugTelemetrySelector{
				Kind: configDebugTelemetryMetricKind(override.Match.Kind),
				Name: override.Match.Name,
				Mode: configDebugTelemetryMode(override.Match.Mode),
			},
			Disabled:     override.Disabled,
			TagOverrides: tags,
		})
	}
	return result
}

func configDebugTracing(tracing model.TelemetryTracing) configDebugTelemetryTracing {
	tags := make(map[string]configDebugTracingTag, len(tracing.CustomTags))
	for name, tag := range tracing.CustomTags {
		tags[name] = configDebugTracingTag{
			Kind:         configDebugTelemetryTracingTagKind(tag.Kind),
			Name:         tag.Name,
			Value:        tag.Value,
			DefaultValue: tag.DefaultValue,
		}
	}
	return configDebugTelemetryTracing{
		Mode:                         configDebugTelemetryMode(tracing.Mode),
		Providers:                    append([]string(nil), tracing.Providers...),
		RandomSamplingPercentage:     tracing.RandomSamplingPercentage,
		DisableSpanReporting:         tracing.DisableSpanReporting,
		CustomTags:                   tags,
		UseRequestIDForTraceSampling: tracing.UseRequestIDForTraceSampling,
		EnableIstioTags:              tracing.EnableIstioTags,
	}
}

func configDebugLogging(logging model.TelemetryAccessLogging) configDebugTelemetryLogging {
	return configDebugTelemetryLogging{
		Mode:      configDebugTelemetryMode(logging.Mode),
		Providers: append([]string(nil), logging.Providers...),
		Disabled:  logging.Disabled,
		Filter:    logging.Filter,
	}
}

func configDebugTelemetryMode(mode model.TelemetryMode) string {
	switch mode {
	case model.TelemetryModeClient:
		return "CLIENT"
	case model.TelemetryModeServer:
		return "SERVER"
	case model.TelemetryModeClientAndServer:
		return "CLIENT_AND_SERVER"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", mode)
	}
}

func configDebugTelemetryMetricKind(kind model.TelemetryMetricKind) string {
	switch kind {
	case model.TelemetryMetricAll:
		return "ALL"
	case model.TelemetryMetricStandard:
		return "STANDARD"
	case model.TelemetryMetricCustom:
		return "CUSTOM"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", kind)
	}
}

func configDebugTelemetryTagOperation(operation model.TelemetryTagOperation) string {
	switch operation {
	case model.TelemetryTagRemove:
		return "REMOVE"
	case model.TelemetryTagUpsert:
		return "UPSERT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", operation)
	}
}

func configDebugTelemetryTracingTagKind(kind model.TelemetryTracingTagKind) string {
	switch kind {
	case model.TelemetryTracingTagLiteral:
		return "LITERAL"
	case model.TelemetryTracingTagEnvironment:
		return "ENVIRONMENT"
	case model.TelemetryTracingTagHeader:
		return "HEADER"
	case model.TelemetryTracingTagFormatter:
		return "FORMATTER"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", kind)
	}
}
