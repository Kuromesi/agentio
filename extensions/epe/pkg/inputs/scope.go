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
// Package inputs provides the evaluation-scope views and activations that
// feed CEL and template expressions. It contains only expression-visible
// data; extraction and identity types live in extproc/attributes.
package inputs

import "sync"

// Scope is the unified, read-only evaluation scope shared by the CEL and
// template engines. It deliberately carries only non-sensitive request
// context: identity payloads such as SandboxToken must never be added here.
type Scope struct {
	Request Request
	Pod     Pod
	Profile Profile
	Rule    Rule
	Inputs  map[string]any
}

// Activation projects the Scope into the CEL variable bag (variables
// `request`, `pod`, `profile`, `rule`, `inputs`). The returned map is pooled; the
// caller must invoke the returned release function when done. The audit-only
// `result` variable is intentionally absent; audit flows use NewActivation.
func (s *Scope) Activation() (map[string]any, func()) {
	act := activationPool.Get().(map[string]any)
	project(act, s.Request, s.Pod, s.Profile, s.Rule)
	act["inputs"] = s.Inputs
	// A plain Scope activation must not expose the audit-only "result"
	// variable. Deleting it here is safe: the slot does not persist in the
	// pooled map, NewActivation re-adds it on every audit-path use.
	delete(act, "result")
	return act, func() { ReleaseActivation(act) }
}

// NewActivation projects the shared views into the CEL variable bag,
// including the audit-only `result` variable. The returned map is pooled;
// the caller must return it via ReleaseActivation.
func NewActivation(req Request, pod Pod, profile Profile, rule Rule, result string) map[string]any {
	return NewActivationWithInputs(req, pod, profile, rule, nil, result)
}

// NewActivationWithInputs projects the shared views and profile-scoped inputs
// into the CEL variable bag.
func NewActivationWithInputs(req Request, pod Pod, profile Profile, rule Rule, inputs map[string]any, result string) map[string]any {
	act := activationPool.Get().(map[string]any)
	project(act, req, pod, profile, rule)
	act["result"] = result
	act["inputs"] = inputs
	return act
}

// ReleaseActivation returns a pooled activation map for reuse.
func ReleaseActivation(act map[string]any) {
	delete(act, "inputs")
	delete(act, "response")
	activationPool.Put(act)
}

// activationPool reuses the activation map structure across evaluations.
var activationPool = sync.Pool{
	New: func() any {
		return map[string]any{
			"result":      "",
			"request":     make(map[string]any, 8),
			"pod":         make(map[string]any, 4),
			"profile":     make(map[string]string, 2),
			"rule":        make(map[string]string, 1),
			"headers":     make(map[string]string, 8),
			"queryParams": make(map[string]string, 4),
			"labels":      make(map[string]string, 4),
		}
	},
}

// project fills the pooled activation map with the request/pod/profile/rule
// variables. It never touches the `result` slot; callers decide whether that
// audit-only variable is exposed.
func project(act map[string]any, req Request, pod Pod, profile Profile, rule Rule) {
	headers := act["headers"].(map[string]string)
	queryParams := act["queryParams"].(map[string]string)
	labels := act["labels"].(map[string]string)
	reqMap := act["request"].(map[string]any)
	podMap := act["pod"].(map[string]any)
	profileMap := act["profile"].(map[string]string)
	ruleMap := act["rule"].(map[string]string)

	clear(headers)
	clear(queryParams)
	clear(labels)
	clear(reqMap)
	clear(podMap)
	clear(profileMap)
	clear(ruleMap)

	for k, v := range req.headers {
		headers[k] = v
	}
	for k, vals := range req.Query {
		if len(vals) > 0 {
			queryParams[k] = vals[0]
		}
	}
	for k, v := range pod.Labels {
		labels[k] = v
	}

	reqMap["host"] = req.Host
	reqMap["port"] = int64(req.Port)
	reqMap["path"] = req.Path
	reqMap["method"] = req.Method
	reqMap["scheme"] = req.Scheme
	reqMap["headers"] = headers
	reqMap["queryParams"] = queryParams

	podMap["name"] = pod.Name
	podMap["namespace"] = pod.Namespace
	podMap["ip"] = pod.IP
	podMap["labels"] = labels

	profileMap["name"] = profile.Name
	profileMap["namespace"] = profile.Namespace

	ruleMap["name"] = rule.Name
}
