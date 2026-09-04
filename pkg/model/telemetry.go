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
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"istio.io/istio/pkg/util/sets"
)

// TelemetryMode is the traffic role selected by one Telemetry entry.
type TelemetryMode uint8

const (
	TelemetryModeClient TelemetryMode = iota + 1
	TelemetryModeServer
	TelemetryModeClientAndServer
)

func (m TelemetryMode) valid() bool {
	return m >= TelemetryModeClient && m <= TelemetryModeClientAndServer
}

// TelemetryMetricKind distinguishes the metric selector oneof without
// retaining the Istio API value in the internal collection.
type TelemetryMetricKind uint8

const (
	TelemetryMetricAll TelemetryMetricKind = iota + 1
	TelemetryMetricStandard
	TelemetryMetricCustom
)

// TelemetryTagOperation is the normalized metric dimension operation.
type TelemetryTagOperation uint8

const (
	TelemetryTagRemove TelemetryTagOperation = iota + 1
	TelemetryTagUpsert
)

// TelemetryTracingTagKind is the normalized tracing custom-tag oneof.
type TelemetryTracingTagKind uint8

const (
	TelemetryTracingTagLiteral TelemetryTracingTagKind = iota + 1
	TelemetryTracingTagEnvironment
	TelemetryTracingTagHeader
	TelemetryTracingTagFormatter
)

type TelemetryMetricSelector struct {
	Kind TelemetryMetricKind
	Name string
	Mode TelemetryMode
}

func (s TelemetryMetricSelector) validate() error {
	if !s.Mode.valid() {
		return fmt.Errorf("invalid workload mode %d", s.Mode)
	}
	switch s.Kind {
	case TelemetryMetricAll:
		if s.Name != "" {
			return fmt.Errorf("all-metrics selector must not have a name")
		}
	case TelemetryMetricStandard, TelemetryMetricCustom:
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("metric selector name is required")
		}
	default:
		return fmt.Errorf("invalid metric selector kind %d", s.Kind)
	}
	return nil
}

type TelemetryMetricTagOverride struct {
	Operation TelemetryTagOperation
	Value     string
}

func (o TelemetryMetricTagOverride) validate() error {
	switch o.Operation {
	case TelemetryTagRemove:
		if o.Value != "" {
			return fmt.Errorf("REMOVE must not have a value")
		}
	case TelemetryTagUpsert:
		if o.Value == "" {
			return fmt.Errorf("UPSERT requires a value")
		}
	default:
		return fmt.Errorf("invalid tag operation %d", o.Operation)
	}
	return nil
}

type TelemetryMetricOverride struct {
	Match        TelemetryMetricSelector
	Disabled     *bool
	TagOverrides map[string]TelemetryMetricTagOverride
}

func (o TelemetryMetricOverride) validate() error {
	if err := o.Match.validate(); err != nil {
		return err
	}
	for name, override := range o.TagOverrides {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("metric tag name is required")
		}
		if err := override.validate(); err != nil {
			return fmt.Errorf("tag %q: %w", name, err)
		}
	}
	return nil
}

type TelemetryMetrics struct {
	Providers         []string
	Overrides         []TelemetryMetricOverride
	ReportingInterval *time.Duration
}

func (m TelemetryMetrics) validate() error {
	if err := validateTelemetryProviderNames(m.Providers); err != nil {
		return err
	}
	if m.ReportingInterval != nil && *m.ReportingInterval <= 0 {
		return fmt.Errorf("reporting interval must be positive")
	}
	for index, override := range m.Overrides {
		if err := override.validate(); err != nil {
			return fmt.Errorf("override %d: %w", index, err)
		}
	}
	return nil
}

type TelemetryTracingTag struct {
	Kind         TelemetryTracingTagKind
	Name         string
	Value        string
	DefaultValue string
}

func (t TelemetryTracingTag) validate() error {
	switch t.Kind {
	case TelemetryTracingTagLiteral:
		if t.Name != "" || t.DefaultValue != "" {
			return fmt.Errorf("literal tag contains non-literal fields")
		}
	case TelemetryTracingTagEnvironment, TelemetryTracingTagHeader:
		if strings.TrimSpace(t.Name) == "" {
			return fmt.Errorf("tag source name is required")
		}
		if t.Value != "" {
			return fmt.Errorf("tag source contains a formatter value")
		}
	case TelemetryTracingTagFormatter:
		if t.Value == "" {
			return fmt.Errorf("formatter value is required")
		}
		if t.Name != "" || t.DefaultValue != "" {
			return fmt.Errorf("formatter tag contains non-formatter fields")
		}
	default:
		return fmt.Errorf("invalid tracing tag kind %d", t.Kind)
	}
	return nil
}

type TelemetryTracing struct {
	Mode                         TelemetryMode
	Providers                    []string
	RandomSamplingPercentage     *float64
	DisableSpanReporting         *bool
	CustomTags                   map[string]TelemetryTracingTag
	UseRequestIDForTraceSampling *bool
	EnableIstioTags              *bool
}

func (t TelemetryTracing) validate() error {
	if !t.Mode.valid() {
		return fmt.Errorf("invalid workload mode %d", t.Mode)
	}
	if err := validateTelemetryProviderNames(t.Providers); err != nil {
		return err
	}
	if t.RandomSamplingPercentage != nil && (*t.RandomSamplingPercentage < 0 || *t.RandomSamplingPercentage > 100) {
		return fmt.Errorf("random sampling percentage %g is outside [0,100]", *t.RandomSamplingPercentage)
	}
	for name, tag := range t.CustomTags {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("tracing tag name is required")
		}
		if err := tag.validate(); err != nil {
			return fmt.Errorf("tracing tag %q: %w", name, err)
		}
	}
	return nil
}

type TelemetryAccessLogging struct {
	Mode      TelemetryMode
	Providers []string
	Disabled  *bool
	Filter    *string
}

func (a TelemetryAccessLogging) validate() error {
	if !a.Mode.valid() {
		return fmt.Errorf("invalid workload mode %d", a.Mode)
	}
	if err := validateTelemetryProviderNames(a.Providers); err != nil {
		return err
	}
	if a.Filter != nil && strings.TrimSpace(*a.Filter) == "" {
		return fmt.Errorf("access-log filter expression is required")
	}
	return nil
}

func validateTelemetryProviderNames(names []string) error {
	seen := sets.NewWithLength[string](len(names))
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			return fmt.Errorf("provider name is required")
		}
		key := strings.ToLower(trimmed)
		if seen.Contains(key) {
			return fmt.Errorf("provider %q is duplicated", name)
		}
		seen.Insert(key)
	}
	return nil
}

type TelemetryMetadata struct {
	Namespace       string
	Name            string
	Source          string
	ResourceVersion string
	CreationTime    time.Time
}

// Telemetry is a source-qualified, normalized Telemetry declaration for
// egress Gateways. It intentionally contains no Istio Telemetry API values.
type Telemetry struct {
	Namespace       string
	Name            string
	Source          string
	ResourceVersion string
	CreationTime    time.Time
	TargetGateways  []string
	Metrics         []TelemetryMetrics
	Tracing         []TelemetryTracing
	AccessLogging   []TelemetryAccessLogging
}

func NewTelemetry(
	metadata TelemetryMetadata,
	targetGateways []string,
	metrics []TelemetryMetrics,
	tracing []TelemetryTracing,
	accessLogging []TelemetryAccessLogging,
) (Telemetry, error) {
	policy := Telemetry{
		Namespace:       metadata.Namespace,
		Name:            metadata.Name,
		Source:          metadata.Source,
		ResourceVersion: metadata.ResourceVersion,
		CreationTime:    metadata.CreationTime,
		TargetGateways:  slices.Clone(targetGateways),
		Metrics:         cloneTelemetryMetrics(metrics),
		Tracing:         cloneTelemetryTracing(tracing),
		AccessLogging:   cloneTelemetryAccessLogging(accessLogging),
	}
	if err := policy.validateAndNormalize(); err != nil {
		return Telemetry{}, err
	}
	return policy, nil
}

func (p *Telemetry) validateAndNormalize() error {
	if strings.TrimSpace(p.Namespace) == "" || strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("Telemetry namespace and name are required")
	}
	if strings.TrimSpace(p.Source) == "" {
		return fmt.Errorf("Telemetry source is required")
	}
	seenTargets := sets.NewWithLength[string](len(p.TargetGateways))
	for _, target := range p.TargetGateways {
		namespace, name, found := strings.Cut(target, "/")
		if !found || namespace == "" || name == "" || strings.Contains(name, "/") {
			return fmt.Errorf("invalid Gateway target %q", target)
		}
		if namespace != p.Namespace {
			return fmt.Errorf("Gateway target %q crosses Telemetry namespace %q", target, p.Namespace)
		}
		if seenTargets.Contains(target) {
			return fmt.Errorf("Gateway target %q is duplicated", target)
		}
		seenTargets.Insert(target)
	}
	sort.Strings(p.TargetGateways)
	for index, metrics := range p.Metrics {
		if err := metrics.validate(); err != nil {
			return fmt.Errorf("metrics %d: %w", index, err)
		}
	}
	for index, tracing := range p.Tracing {
		if err := tracing.validate(); err != nil {
			return fmt.Errorf("tracing %d: %w", index, err)
		}
	}
	for index, logging := range p.AccessLogging {
		if err := logging.validate(); err != nil {
			return fmt.Errorf("access logging %d: %w", index, err)
		}
	}
	return nil
}

func (p Telemetry) ValidateForUse() error {
	clone := p.Clone()
	return clone.validateAndNormalize()
}

func (p Telemetry) ResourceName() string { return p.Source + "|" + p.LogicalName() }

func (p Telemetry) LogicalName() string { return p.Namespace + "/" + p.Name }

func (p Telemetry) Clone() Telemetry {
	return Telemetry{
		Namespace:       p.Namespace,
		Name:            p.Name,
		Source:          p.Source,
		ResourceVersion: p.ResourceVersion,
		CreationTime:    p.CreationTime,
		TargetGateways:  slices.Clone(p.TargetGateways),
		Metrics:         cloneTelemetryMetrics(p.Metrics),
		Tracing:         cloneTelemetryTracing(p.Tracing),
		AccessLogging:   cloneTelemetryAccessLogging(p.AccessLogging),
	}
}

func (p Telemetry) Equals(other Telemetry) bool {
	return reflect.DeepEqual(p, other)
}

func cloneTelemetryMetrics(input []TelemetryMetrics) []TelemetryMetrics {
	result := make([]TelemetryMetrics, len(input))
	for index, item := range input {
		result[index] = TelemetryMetrics{
			Providers: slices.Clone(item.Providers),
			Overrides: make([]TelemetryMetricOverride, len(item.Overrides)),
		}
		if item.ReportingInterval != nil {
			value := *item.ReportingInterval
			result[index].ReportingInterval = &value
		}
		for overrideIndex, override := range item.Overrides {
			result[index].Overrides[overrideIndex] = TelemetryMetricOverride{
				Match:        override.Match,
				Disabled:     cloneValue(override.Disabled),
				TagOverrides: maps.Clone(override.TagOverrides),
			}
		}
	}
	return result
}

func cloneTelemetryTracing(input []TelemetryTracing) []TelemetryTracing {
	result := make([]TelemetryTracing, len(input))
	for index, item := range input {
		result[index] = TelemetryTracing{
			Mode:                         item.Mode,
			Providers:                    slices.Clone(item.Providers),
			RandomSamplingPercentage:     cloneValue(item.RandomSamplingPercentage),
			DisableSpanReporting:         cloneValue(item.DisableSpanReporting),
			CustomTags:                   maps.Clone(item.CustomTags),
			UseRequestIDForTraceSampling: cloneValue(item.UseRequestIDForTraceSampling),
			EnableIstioTags:              cloneValue(item.EnableIstioTags),
		}
	}
	return result
}

func cloneTelemetryAccessLogging(input []TelemetryAccessLogging) []TelemetryAccessLogging {
	result := make([]TelemetryAccessLogging, len(input))
	for index, item := range input {
		result[index] = TelemetryAccessLogging{
			Mode:      item.Mode,
			Providers: slices.Clone(item.Providers),
			Disabled:  cloneValue(item.Disabled),
			Filter:    cloneValue(item.Filter),
		}
	}
	return result
}
