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
	"fmt"
	"reflect"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
)

var (
	whenEnvOnce sync.Once
	whenEnv     *cel.Env
	whenEnvErr  error
)

// WhenEnv returns the shared CEL environment for security `when` expressions.
// Variables: result (string), request/pod/inputs/response (map), profile/rule (string map).
func WhenEnv() (*cel.Env, error) {
	whenEnvOnce.Do(func() {
		whenEnv, whenEnvErr = cel.NewEnv(
			cel.Variable("result", cel.StringType),
			cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("pod", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("profile", cel.MapType(cel.StringType, cel.StringType)),
			cel.Variable("rule", cel.MapType(cel.StringType, cel.StringType)),
			cel.Variable("inputs", cel.MapType(cel.StringType, cel.DynType)),
			cel.Variable("response", cel.MapType(cel.StringType, cel.DynType)),
			ext.Bindings(),
			ext.Strings(),
			ext.Sets(),
			ext.Lists(),
		)
	})
	return whenEnv, whenEnvErr
}

// CompileValue parses and type-checks a CEL expression without constraining
// its result type. CredentialProvider extraMetadata values may be strings,
// lists, or any other JSON-compatible value.
func CompileValue(expr string) (cel.Program, error) {
	env, err := WhenEnv()
	if err != nil {
		return nil, fmt.Errorf("init CEL env: %w", err)
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile value: %w", issues.Err())
	}
	prog, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("program value: %w", err)
	}
	return prog, nil
}

// CompileBool parses and type-checks a CEL expression that must return bool.
// An empty expression compiles to a nil program (the "always fire" path).
func CompileBool(expr string) (cel.Program, error) {
	if expr == "" {
		return nil, nil
	}
	env, err := WhenEnv()
	if err != nil {
		return nil, fmt.Errorf("init CEL env: %w", err)
	}
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile when: %w", issues.Err())
	}
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("compile when: expression must return bool, got %s", ast.OutputType().String())
	}
	prog, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("program when: %w", err)
	}
	return prog, nil
}

// EvalBool evaluates a compiled program against activation. A nil program
// returns true (the empty-expression "always fire" path).
func EvalBool(prog cel.Program, activation map[string]any) (bool, error) {
	if prog == nil {
		return true, nil
	}
	val, _, err := prog.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("eval when: %w", err)
	}
	b, ok := val.(types.Bool)
	if !ok {
		return false, fmt.Errorf("eval when: result is %T not bool", val)
	}
	return bool(b), nil
}

// EvalValue evaluates a CEL program and converts the result to its native Go
// representation for JSON normalization.
func EvalValue(prog cel.Program, activation map[string]any) (any, error) {
	val, _, err := prog.Eval(activation)
	if err != nil {
		return nil, fmt.Errorf("eval value: %w", err)
	}
	if val.Type() == types.NullType {
		return nil, nil
	}
	native, err := val.ConvertToNative(reflect.TypeOf((*any)(nil)).Elem())
	if err != nil {
		return nil, fmt.Errorf("convert value: %w", err)
	}
	return native, nil
}
