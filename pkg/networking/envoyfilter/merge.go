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

package envoyfilter

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Merge applies EnvoyFilter MERGE semantics; Duration fields replace rather than merge.
func Merge(destination, patch proto.Message) {
	if destination == nil || patch == nil {
		return
	}
	destinationMessage, patchMessage := destination.ProtoReflect(), patch.ProtoReflect()
	if destinationMessage.Descriptor() != patchMessage.Descriptor() {
		if got, want := destinationMessage.Descriptor().FullName(), patchMessage.Descriptor().FullName(); got != want {
			panic(fmt.Sprintf("descriptor mismatch: %v != %v", got, want))
		}
		panic("descriptor mismatch")
	}
	mergeMessage(destinationMessage, patchMessage)
}

func mergeMessage(destination, patch protoreflect.Message) {
	if !destination.IsValid() {
		panic(fmt.Sprintf("cannot merge into invalid %v message", destination.Descriptor().FullName()))
	}
	patch.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsList():
			mergeList(destination.Mutable(field).List(), value.List(), field)
		case field.IsMap():
			mergeMap(destination.Mutable(field).Map(), value.Map(), field.MapValue())
		case field.Message() != nil && field.Message().FullName() == (&durationpb.Duration{}).ProtoReflect().Descriptor().FullName():
			destination.Set(field, protoreflect.ValueOfMessage(proto.Clone(value.Message().Interface()).ProtoReflect()))
		case field.Message() != nil:
			mergeMessage(destination.Mutable(field).Message(), value.Message())
		case field.Kind() == protoreflect.BytesKind:
			destination.Set(field, cloneBytes(value))
		default:
			destination.Set(field, value)
		}
		return true
	})
	if len(patch.GetUnknown()) > 0 {
		destination.SetUnknown(append(destination.GetUnknown(), patch.GetUnknown()...))
	}
}

func mergeList(destination, patch protoreflect.List, field protoreflect.FieldDescriptor) {
	for index := 0; index < patch.Len(); index++ {
		value := patch.Get(index)
		switch {
		case field.Message() != nil:
			cloned := destination.NewElement()
			mergeMessage(cloned.Message(), value.Message())
			destination.Append(cloned)
		case field.Kind() == protoreflect.BytesKind:
			destination.Append(cloneBytes(value))
		default:
			destination.Append(value)
		}
	}
}

func mergeMap(destination, patch protoreflect.Map, valueField protoreflect.FieldDescriptor) {
	patch.Range(func(key protoreflect.MapKey, value protoreflect.Value) bool {
		switch {
		case valueField.Message() != nil:
			cloned := destination.NewValue()
			mergeMessage(cloned.Message(), value.Message())
			destination.Set(key, cloned)
		case valueField.Kind() == protoreflect.BytesKind:
			destination.Set(key, cloneBytes(value))
		default:
			destination.Set(key, value)
		}
		return true
	})
}

func cloneBytes(value protoreflect.Value) protoreflect.Value {
	return protoreflect.ValueOfBytes(append([]byte(nil), value.Bytes()...))
}
