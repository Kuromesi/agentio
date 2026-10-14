// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package eval

import (
	"encoding/json"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// JSONDecode exposes json.decode(string) -> dyn to request and token-header
// expressions. Objects have string keys, numbers are doubles, and invalid JSON
// is an evaluation error rather than an implicit fallback to the input.
func JSONDecode() cel.EnvOption {
	return cel.Function("json.decode",
		cel.Overload("json_decode_string", []*cel.Type{cel.StringType}, cel.DynType,
			cel.UnaryBinding(func(value ref.Val) ref.Val {
				var decoded any
				if err := json.Unmarshal([]byte(value.(types.String)), &decoded); err != nil {
					return types.NewErr("json.decode: %v", err)
				}
				return types.DefaultTypeAdapter.NativeToValue(decoded)
			}),
		),
	)
}
