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
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
)

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
