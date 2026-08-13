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

package securityprofiletest

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	structurallisttype "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/listtype"
	structuralpruning "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/pruning"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"
	celconfig "k8s.io/apiserver/pkg/apis/cel"

	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test/env"
)

// crdSchemas holds the structural schemas, OpenAPI validators, and compiled
// CEL validators for the agentio profile CRDs, loaded once per process from
// the chart's checked-in CRD manifests — the same manifests installed into
// clusters, so offline defaulting and validation track apiserver behavior.
type crdSchemas struct {
	structural map[schema.GroupVersionKind]*structuralschema.Structural
	openapi    map[schema.GroupVersionKind]validation.SchemaCreateValidator
	cel        map[schema.GroupVersionKind]*cel.Validator
}

var loadSchemas = sync.OnceValues(func() (*crdSchemas, error) {
	return loadCRDSchemas(
		filepath.Join(env.IstioSrc, "manifests/charts/agentio/files/securityprofile-crd.yaml"),
		filepath.Join(env.IstioSrc, "manifests/charts/agentio/files/globalsecurityprofile-crd.yaml"),
	)
})

func loadCRDSchemas(files ...string) (*crdSchemas, error) {
	out := &crdSchemas{
		structural: map[schema.GroupVersionKind]*structuralschema.Structural{},
		openapi:    map[schema.GroupVersionKind]validation.SchemaCreateValidator{},
		cel:        map[schema.GroupVersionKind]*cel.Validator{},
	}
	for _, file := range files {
		data, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("open CRD manifest: %w", err)
		}
		decoder := kubeyaml.NewYAMLOrJSONDecoder(data, 512*1024)
		for {
			crdv1 := &apiextensionsv1.CustomResourceDefinition{}
			err := decoder.Decode(crdv1)
			if err == io.EOF {
				break
			}
			if err != nil {
				data.Close()
				return nil, fmt.Errorf("decode CRD manifest %s: %w", file, err)
			}
			if crdv1.Kind != "CustomResourceDefinition" {
				continue
			}
			crd := apiextensions.CustomResourceDefinition{}
			if err := apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(crdv1, &crd, nil); err != nil {
				data.Close()
				return nil, fmt.Errorf("convert CRD %s: %w", crdv1.Name, err)
			}
			for _, ver := range crd.Spec.Versions {
				gvk := schema.GroupVersionKind{
					Group:   crd.Spec.Group,
					Version: ver.Name,
					Kind:    crd.Spec.Names.Kind,
				}
				crdSchema := ver.Schema
				if crdSchema == nil {
					crdSchema = crd.Spec.Validation
				}
				if crdSchema == nil {
					data.Close()
					return nil, fmt.Errorf("CRD %s version %s has no schema", crd.Name, ver.Name)
				}
				openapiValidator, _, err := validation.NewSchemaValidator(crdSchema.OpenAPIV3Schema)
				if err != nil {
					data.Close()
					return nil, fmt.Errorf("build OpenAPI validator for %v: %w", gvk, err)
				}
				structural, err := structuralschema.NewStructural(crdSchema.OpenAPIV3Schema)
				if err != nil {
					data.Close()
					return nil, fmt.Errorf("build structural schema for %v: %w", gvk, err)
				}
				out.structural[gvk] = structural
				out.openapi[gvk] = openapiValidator
				if celValidator := cel.NewValidator(structural, true, celconfig.PerCallLimit); celValidator != nil {
					out.cel[gvk] = celValidator
				}
			}
		}
		data.Close()
	}
	return out, nil
}

// applyDefaults fills in CRD defaults in place, mirroring what the
// apiserver does on admission.
func (s *crdSchemas) applyDefaults(un *unstructured.Unstructured) error {
	structural, ok := s.structural[un.GroupVersionKind()]
	if !ok {
		return fmt.Errorf("no CRD schema registered for %v", un.GroupVersionKind())
	}
	structuraldefaulting.Default(un.Object, structural)
	return nil
}

// validate runs the offline equivalent of apiserver admission validation:
// OpenAPI schema, list-type invariants, unknown-field pruning, and CEL
// x-kubernetes-validations rules.
func (s *crdSchemas) validate(un *unstructured.Unstructured) error {
	gvk := un.GroupVersionKind()
	structural, ok := s.structural[gvk]
	if !ok {
		return fmt.Errorf("no CRD schema registered for %v", gvk)
	}
	if err := validation.ValidateCustomResource(nil, un.Object, s.openapi[gvk]).ToAggregate(); err != nil {
		return fmt.Errorf("%v %v/%v: %w", gvk.Kind, un.GetNamespace(), un.GetName(), err)
	}
	if err := structurallisttype.ValidateListSetsAndMaps(nil, structural, un.Object).ToAggregate(); err != nil {
		return fmt.Errorf("%v %v/%v: %w", gvk.Kind, un.GetNamespace(), un.GetName(), err)
	}
	pruneOpts := structuralschema.UnknownFieldPathOptions{TrackUnknownFieldPaths: true}
	unknownFieldPaths := structuralpruning.PruneWithOptions(un.DeepCopy().Object, structural, false, pruneOpts)
	unknownFieldPaths = slices.FilterInPlace(unknownFieldPaths, func(path string) bool {
		// Some CRDs don't spell out all metadata fields; the apiserver
		// does not prune metadata either.
		return !strings.HasPrefix(path, "metadata.")
	})
	if len(unknownFieldPaths) > 0 {
		return fmt.Errorf("%v %v/%v: unknown fields %v", gvk.Kind, un.GetNamespace(), un.GetName(), unknownFieldPaths)
	}
	if celValidator, ok := s.cel[gvk]; ok {
		errs, _ := celValidator.Validate(context.Background(), nil, structural, un.Object, nil, celconfig.RuntimeCELCostBudget)
		if err := errs.ToAggregate(); err != nil {
			return fmt.Errorf("%v %v/%v: %w", gvk.Kind, un.GetNamespace(), un.GetName(), err)
		}
	}
	return nil
}
