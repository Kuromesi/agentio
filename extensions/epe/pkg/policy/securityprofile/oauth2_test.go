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

package securityprofile

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	v1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/openkruise/agentio/extensions/epe/pkg/credential"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/oauth2"
)

func TestOAuth2PayloadProjection(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation v1alpha1.OAuth2Operation
		want      string
	}{
		{"device", v1alpha1.OAuth2Operation{DeviceAuthorization: &v1alpha1.OAuth2DeviceAuthorizationConfig{}},
			credential.OAuth2OperationDeviceAuthorization},
		{"token", v1alpha1.OAuth2Operation{Token: &v1alpha1.OAuth2TokenConfig{AllowedGrantTypes: []string{"refresh_token"}}},
			credential.OAuth2OperationToken},
		{"resource", v1alpha1.OAuth2Operation{Resource: &v1alpha1.OAuth2ResourceConfig{}}, credential.OAuth2OperationResource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &v1alpha1.TokenTransformationAction{
				Type: v1alpha1.TokenTransformationTypeOAuth2,
				CredentialRef: v1alpha1.CredentialRef{
					CredentialProvider: &v1alpha1.CredentialProviderRef{Name: "remote-provider"},
				},
				OAuth2: &v1alpha1.OAuth2Config{
					Operation: tc.operation,
					CustomResponse: &v1alpha1.OAuth2CustomResponse{
						Error: &runtime.RawExtension{Raw: []byte(`{"code":20050,"nested":{"public":true}}`)},
						AuthorizationRequired: &runtime.RawExtension{Object: &unstructured.Unstructured{
							Object: map[string]any{"code": int64(99991663)},
						}},
					},
				},
			}
			original := a.DeepCopy()
			payloads := payloadsOrFail(t, &Rule{Actions: v1alpha1.SecurityRuleActions{TokenTransformation: a}})
			if len(payloads) != 1 || payloads[oauth2.FilterName] == nil {
				t.Fatalf("OAuth action must mount only its protocol filter: %v", payloads)
			}
			regs, err := filter.Build(oauth2.Definition(nil))
			if err != nil {
				t.Fatal(err)
			}
			configs, errs := filter.Project(regs, payloads)
			if errs[0] != nil {
				t.Fatal(errs[0])
			}
			got := configs[0].(oauth2.Config)
			if got.CredentialProviderName != "remote-provider" || got.Operation != tc.want {
				t.Fatalf("unexpected neutral configuration: %+v", got)
			}
			if tc.operation.Token != nil &&
				!reflect.DeepEqual(got.AllowedGrantTypes, tc.operation.Token.AllowedGrantTypes) {
				t.Fatalf("grant restriction lost: %+v", got)
			}
			var response map[string]any
			if err := json.Unmarshal(got.CustomResponse.AuthorizationRequired, &response); err != nil {
				t.Fatal(err)
			}
			if response["code"] != float64(99991663) ||
				!strings.Contains(string(got.CustomResponse.Error), `"nested"`) {
				t.Fatalf("response fields lost: %+v", got.CustomResponse)
			}
			if !reflect.DeepEqual(a, original) {
				t.Fatal("projection mutated the source action")
			}
		})
	}
}

func TestOAuth2ProjectionRejectsInvalidPolicy(t *testing.T) {
	regs, err := filter.Build(oauth2.Definition(nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		modify func(*v1alpha1.TokenTransformationAction)
		want   string
	}{
		{"missing config", func(a *v1alpha1.TokenTransformationAction) { a.OAuth2 = nil }, "configuration is required"},
		{"wrong type", func(a *v1alpha1.TokenTransformationAction) { a.Type = v1alpha1.TokenTransformationTypeApiKey }, "requires the OAuth2"},
		{"no operation", func(a *v1alpha1.TokenTransformationAction) { a.OAuth2.Operation = v1alpha1.OAuth2Operation{} }, "exactly one"},
		{"multiple operations", func(a *v1alpha1.TokenTransformationAction) {
			a.OAuth2.Operation.Resource = &v1alpha1.OAuth2ResourceConfig{}
		}, "exactly one"},
		{"secret source", func(a *v1alpha1.TokenTransformationAction) {
			a.CredentialRef = v1alpha1.CredentialRef{Secret: &v1alpha1.SecretCredentialRef{Name: "secret"}}
		}, "CredentialProvider"},
		{"provider parameters", func(a *v1alpha1.TokenTransformationAction) {
			a.CredentialRef.CredentialProvider.Parameters = map[string]v1alpha1.ValueSource{"scope": {}}
		}, "parameter-free"},
		{"API key options", func(a *v1alpha1.TokenTransformationAction) { a.ApiKey = &v1alpha1.ApiKeyConfig{} }, "apiKey"},
		{"allow failure", func(a *v1alpha1.TokenTransformationAction) { a.FailStrategy = v1alpha1.FailStrategyAllow }, "Block"},
		{"ignore failure", func(a *v1alpha1.TokenTransformationAction) { a.FailStrategy = v1alpha1.FailStrategyIgnore }, "Block"},
		{"resource success", func(a *v1alpha1.TokenTransformationAction) {
			a.OAuth2.Operation = v1alpha1.OAuth2Operation{Resource: &v1alpha1.OAuth2ResourceConfig{}}
			a.OAuth2.CustomResponse = &v1alpha1.OAuth2CustomResponse{Success: &runtime.RawExtension{Raw: []byte(`{}`)}}
		}, "Token operation"},
		{"reserved response field", func(a *v1alpha1.TokenTransformationAction) {
			a.OAuth2.CustomResponse = &v1alpha1.OAuth2CustomResponse{Success: &runtime.RawExtension{Raw: []byte(`{"access_token":"private"}`)}}
		}, "standard field"},
		{"password grant", func(a *v1alpha1.TokenTransformationAction) {
			a.OAuth2.Operation.Token.AllowedGrantTypes = []string{credential.OAuth2GrantPassword}
		}, "password grant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &v1alpha1.TokenTransformationAction{
				Type: v1alpha1.TokenTransformationTypeOAuth2,
				CredentialRef: v1alpha1.CredentialRef{
					CredentialProvider: &v1alpha1.CredentialProviderRef{Name: "provider"},
				},
				OAuth2: &v1alpha1.OAuth2Config{
					Operation: v1alpha1.OAuth2Operation{Token: &v1alpha1.OAuth2TokenConfig{}},
				},
			}
			tc.modify(a)
			sp := &Profile{
				Rules: []Rule{{Name: "oauth", Actions: v1alpha1.SecurityRuleActions{TokenTransformation: a}}},
			}
			if err := sp.Project(regs); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}
