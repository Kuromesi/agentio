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

// Package config provides typed, dynamically updated configuration collections.
package config

import (
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/krt"
	agentlog "github.com/openkruise/agentio/pkg/log"
)

var log = agentlog.New("config")

// Config is one effective configuration. Value is immutable after publication.
type Config[T proto.Message] struct {
	Value           T
	ResourceVersion string // Source revisions for diagnostics; excluded from equality.
}

// ResourceName identifies the effective configuration singleton.
func (Config[T]) ResourceName() string { return "effective" }

// Equals compares configuration content, excluding diagnostic source revisions.
func (c Config[T]) Equals(other Config[T]) bool { return proto.Equal(c.Value, other.Value) }

// Options selects ordered ConfigMap sources and the configuration type.
type Options[T proto.Message] struct {
	Namespace string
	Names     []string // Applied in order; an empty name disables that source.
	Key       string   // Defaults to "config".
	Defaults  T        // Must be a non-nil message containing valid defaults.
	// Apply overlays one source onto the lower layer without mutating it.
	// Defaults to config.Apply, which replaces supplied lists and submessages.
	Apply func(string, T) (T, error)
	// Validate may normalize the candidate before validating it. It runs after
	// each non-empty source is applied, before the configuration is published.
	Validate func(T) error
}

// NewCollection derives a singleton from defaults and ordered YAML/JSON sources.
// Missing or blank sources leave the lower layer unchanged. Invalid updates
// retain the last good configuration; an invalid first update uses Defaults.
func NewCollection[T proto.Message](
	configMaps krt.Collection[*corev1.ConfigMap],
	options Options[T],
	opts ...krt.CollectionOption,
) krt.Singleton[Config[T]] {
	if any(options.Defaults) == nil || !options.Defaults.ProtoReflect().IsValid() {
		panic("config: Defaults must be a non-nil protobuf message")
	}
	defaults := proto.Clone(options.Defaults).(T)
	names := slices.Clone(options.Names)
	if options.Key == "" {
		options.Key = "config"
	}
	if options.Apply == nil {
		options.Apply = Apply[T]
	}
	return krt.NewSingleton(func(ctx krt.HandlerContext) *Config[T] {
		value := proto.Clone(defaults).(T)
		versions := make([]string, 0, len(names))
		for _, name := range names {
			if name == "" {
				continue
			}
			cm := krt.FetchOne(ctx, configMaps, krt.FilterKey(options.Namespace+"/"+name))
			if cm == nil {
				continue
			}
			versions = append(versions, name+"="+(*cm).ResourceVersion)
			content := (*cm).Data[options.Key]
			if strings.TrimSpace(content) == "" {
				continue
			}
			next, err := options.Apply(content, value)
			if err == nil && options.Validate != nil {
				err = options.Validate(next)
			}
			if err != nil {
				log.Warn("retain last-known-good configuration", "namespace", options.Namespace,
					"configmap", name, "key", options.Key, "error", err)
				ctx.DiscardResult()
				// KRT publishes this fallback only when there is no previous result.
				return &Config[T]{Value: proto.Clone(defaults).(T)}
			}
			value = next
		}
		return &Config[T]{Value: value, ResourceVersion: strings.Join(versions, ",")}
	}, opts...)
}
