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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"text/template"
	"time"

	"github.com/openkruise/agentio/test/e2e/kube"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const operationTimeout = 2 * time.Minute

type input struct {
	namespace string
	manifest  string
}

// Plan collects manifest inputs and applies them in declaration order.
// ResourceScope remains the lifecycle authority for everything the plan applies.
type Plan struct {
	scope   *kube.ResourceScope
	inputs  []input
	err     error
	records []kube.ResourceRecord
}

func New(scope *kube.ResourceScope) *Plan {
	return &Plan{scope: scope}
}

// Copy returns an independent copy of the unapplied manifest inputs.
func (p *Plan) Copy() *Plan {
	if p == nil {
		return &Plan{err: errors.New("config plan is required")}
	}
	return &Plan{
		scope:  p.scope,
		inputs: append([]input(nil), p.inputs...),
		err:    p.err,
	}
}

func (p *Plan) YAML(namespace string, manifests ...string) *Plan {
	if p == nil {
		return p
	}
	for _, manifest := range manifests {
		p.inputs = append(p.inputs, input{namespace: namespace, manifest: manifest})
	}
	return p
}

func (p *Plan) Eval(namespace string, values any, manifests ...string) *Plan {
	if p == nil || p.err != nil {
		return p
	}
	for index, manifest := range manifests {
		parsed, err := template.New(fmt.Sprintf("manifest-%d", index+1)).Option("missingkey=error").Parse(manifest)
		if err != nil {
			p.err = fmt.Errorf("parse manifest template %d: %w", index+1, err)
			return p
		}
		var rendered bytes.Buffer
		if err := parsed.Execute(&rendered, values); err != nil {
			p.err = fmt.Errorf("render manifest template %d: %w", index+1, err)
			return p
		}
		p.inputs = append(p.inputs, input{namespace: namespace, manifest: rendered.String()})
	}
	return p
}

func (p *Plan) File(namespace string, paths ...string) *Plan {
	if p == nil || p.err != nil {
		return p
	}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			p.err = fmt.Errorf("read manifest file %q: %w", path, err)
			return p
		}
		p.YAML(namespace, string(content))
	}
	return p
}

func (p *Plan) EvalFile(namespace string, values any, paths ...string) *Plan {
	if p == nil || p.err != nil {
		return p
	}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			p.err = fmt.Errorf("read manifest template file %q: %w", path, err)
			return p
		}
		p.Eval(namespace, values, string(content))
		if p.err != nil {
			p.err = fmt.Errorf("evaluate manifest template file %q: %w", path, p.err)
			return p
		}
	}
	return p
}

func (p *Plan) Apply(ctx context.Context, mode kube.Mode) ([]kube.ResourceRecord, error) {
	if p == nil {
		return nil, errors.New("config plan is required")
	}
	if p.err != nil {
		return nil, p.err
	}
	if p.scope == nil {
		return nil, errors.New("config plan requires a resource scope")
	}
	type plannedObject struct {
		namespace string
		object    *unstructured.Unstructured
	}
	objects := make([]plannedObject, 0, len(p.inputs))
	for index, planned := range p.inputs {
		decoded, err := kube.DecodeYAML(bytes.NewBufferString(planned.manifest))
		if err != nil {
			return nil, fmt.Errorf("decode manifest input %d: %w", index+1, err)
		}
		for _, object := range decoded {
			objects = append(objects, plannedObject{namespace: planned.namespace, object: object})
		}
	}

	applied := make([]kube.ResourceRecord, 0, len(objects))
	for _, planned := range objects {
		record, err := p.scope.ApplyInNamespace(ctx, planned.namespace, planned.object, mode)
		if err != nil {
			return applied, fmt.Errorf("apply %s %s/%s: %w", planned.object.GetKind(), planned.object.GetNamespace(), planned.object.GetName(), err)
		}
		applied = append(applied, record)
		p.records = append(p.records, record)
	}
	return applied, nil
}

func (p *Plan) ApplyOrFail(t testing.TB, mode kube.Mode) []kube.ResourceRecord {
	t.Helper()
	ctx, cancel := operationContext(t)
	defer cancel()
	records, err := p.Apply(ctx, mode)
	if err != nil {
		t.Fatalf("apply manifest plan: %v", err)
	}
	return records
}

func (p *Plan) Delete(ctx context.Context) error {
	if p == nil {
		return errors.New("config plan is required")
	}
	if p.scope == nil {
		return errors.New("config plan requires a resource scope")
	}
	var errs []error
	for index := len(p.records) - 1; index >= 0; index-- {
		if err := p.scope.Delete(ctx, p.records[index]); err != nil {
			errs = append(errs, fmt.Errorf("delete %s %s/%s: %w", p.records[index].GVR.Resource, p.records[index].Namespace, p.records[index].Name, err))
		}
	}
	return errors.Join(errs...)
}

func (p *Plan) DeleteOrFail(t testing.TB) {
	t.Helper()
	ctx, cancel := operationContext(t)
	defer cancel()
	if err := p.Delete(ctx); err != nil {
		t.Fatalf("delete manifest plan: %v", err)
	}
}

func operationContext(t testing.TB) (context.Context, context.CancelFunc) {
	t.Helper()
	deadline := time.Now().Add(operationTimeout)
	if provider, ok := t.(interface {
		Deadline() (time.Time, bool)
	}); ok {
		if testDeadline, hasDeadline := provider.Deadline(); hasDeadline && testDeadline.Before(deadline) {
			deadline = testDeadline
		}
	}
	return context.WithDeadline(context.Background(), deadline)
}
