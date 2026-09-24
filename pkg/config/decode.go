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

package config

import (
	"fmt"

	"github.com/golang/protobuf/jsonpb"            //nolint:staticcheck // Preserve AgentioConfig field replacement semantics.
	legacyproto "github.com/golang/protobuf/proto" //nolint:staticcheck // jsonpb accepts the legacy message adapter.
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"sigs.k8s.io/yaml"
)

// Apply decodes YAML/JSON onto a copy of base, which must be non-nil. Omitted
// and null fields preserve base; supplied fields replace lists and submessages.
// Unknown fields, duplicate YAML keys, and conflicting oneof members are errors.
func Apply[T proto.Message](content string, base T) (T, error) {
	var zero T
	data, err := yaml.YAMLToJSONStrict([]byte(content))
	if err != nil {
		return zero, fmt.Errorf("parse YAML: %w", err)
	}
	value := proto.Clone(base).(T)
	if string(data) == "null" {
		return value, nil
	}
	// jsonpb supplies presence-aware replacement, but accepts conflicting oneofs.
	// Check the input with protojson before applying it to the cloned base.
	if err := protojson.Unmarshal(data, base.ProtoReflect().New().Interface()); err != nil {
		return zero, fmt.Errorf("decode configuration: %w", err)
	}
	if err := jsonpb.UnmarshalString(string(data), legacyproto.MessageV1(value)); err != nil {
		return zero, fmt.Errorf("apply configuration: %w", err)
	}
	return value, nil
}
