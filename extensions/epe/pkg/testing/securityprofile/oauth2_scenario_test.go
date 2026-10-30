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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
)

// These scenarios use published CRD shapes and the production filter/provider
// wiring over ext_proc gRPC, rather than directly constructing an OAuth filter.
func TestScenario_OAuth2PublishedAPI(t *testing.T) {
	for _, kind := range []string{kindSecurityProfile, kindGlobalSecurityProfile} {
		t.Run(kind, func(t *testing.T) {
			for _, tc := range []struct {
				name        string
				config      string
				body        string
				contentType string
				action      string
				response    string
				status      int
				fields      map[string]string
			}{
				{"device", "operation: {deviceAuthorization: {}}", "scope=docs.read&client_secret=private", "application/x-www-form-urlencoded",
					"CreateOAuth2DeviceSession", `{"status":"InProgress","authorizationRequired":true,"deviceSessionId":"session","userCode":"USER","verificationUri":"https://issuer.example.test/approve","authorizationExpiresInSeconds":300}`, 200,
					map[string]string{"scopes": "docs.read"}},
				{"authorized device", "operation: {deviceAuthorization: {}}", "", "application/x-www-form-urlencoded",
					"CreateOAuth2DeviceSession", `{"status":"Authorized","authorizationRequired":false,"deviceSessionId":"session","userCode":"USER","authorizationExpiresInSeconds":300}`, 200, map[string]string{"scopes": ""}},
				{"poll", "operation: {token: {}}", "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=session", "application/x-www-form-urlencoded",
					"PollOAuth2DeviceSession", `{"status":"Authorized","accessToken":"private-access","tokenType":"Bearer","accessTokenExpiresInSeconds":3600}`, 200,
					map[string]string{"deviceSessionId": "session"}},
				{"authorization_pending", "operation: {token: {}}", "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=session", "application/x-www-form-urlencoded",
					"PollOAuth2DeviceSession", `{"status":"InProgress","outcome":{"retryable":true,"requiresNewAuthorization":false,"oauth2Error":{"errorCode":"authorization_pending","errorDescription":"Awaiting user authorization.","httpStatus":200}}}`, 200,
					map[string]string{"deviceSessionId": "session"}},
				{"slow_down", "operation: {token: {}}", "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=session", "application/x-www-form-urlencoded",
					"PollOAuth2DeviceSession", `{"status":"InProgress","outcome":{"retryable":true,"requiresNewAuthorization":false,"oauth2Error":{"errorCode":"slow_down","errorDescription":"Poll less frequently.","httpStatus":200}}}`, 200,
					map[string]string{"deviceSessionId": "session"}},
				{"JSON refresh", "operation: {token: {allowedGrantTypes: [refresh_token]}}\ncustomResponse:\n  success: {code: 0}",
					`{"grant_type":"refresh_token","refresh_token":"unused","client_id":"untrusted","client_secret":"private"}`, "application/json; charset=utf-8",
					"GetOAuth2DeviceAccessToken", `{"status":"Ready","accessToken":"private-access","tokenType":"Bearer","refreshToken":"private-refresh","appSecret":"private-secret"}`, 200, map[string]string{}},
				{"resource", "operation: {resource: {}}", "", "application/octet-stream",
					"GetOAuth2DeviceAccessToken", `{"status":"Ready","accessToken":"private-access","tokenType":"Bearer"}`, 0, map[string]string{}},
				{"unsupported grant", "operation: {token: {}}", "grant_type=client_credentials", "application/x-www-form-urlencoded", "", "", 400, nil},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var calls atomic.Int32
					identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						var fields map[string]string
						if err := json.NewDecoder(r.Body).Decode(&fields); err != nil {
							t.Error(err)
						}
						if r.Header.Get("Authorization") != "Bearer platform-token" ||
							r.Header.Get("X-Api-Action-Name") != tc.action ||
							fields["resourceId"] != "sandbox-client" || fields["credentialProviderName"] != "business-provider" {
							t.Errorf("incorrect trusted selection: headers=%v fields=%v", r.Header, fields)
						}
						delete(fields, "resourceId")
						delete(fields, "credentialProviderName")
						if tc.action == "CreateOAuth2DeviceSession" {
							if fields["idempotencyKey"] == "" {
								t.Error("missing create idempotency key")
							}
							delete(fields, "idempotencyKey")
						}
						if !reflect.DeepEqual(fields, tc.fields) {
							t.Errorf("parameters: got %v, want %v", fields, tc.fields)
						}
						if _, err := io.WriteString(w, tc.response); err != nil {
							t.Error(err)
						}
					}))
					defer identity.Close()
					h := New(t, Options{Providers: providerRegistry(t, identity.URL)})
					h.Fixture.ApplyYAML(oauth2ProfileYAML(kind, tc.config))
					request := enginetest.NewRequest(http.MethodPost, "api.example.test", "/oauth").Scheme("https").
						Workload("test-ns", "sandbox", map[string]string{"app": "sandbox"}).
						SandboxToken("request", "platform-token", "sandbox-client").
						Header("authorization", "Bearer unused").Header("content-type", tc.contentType)
					if tc.status != 0 {
						request.Body([]byte(tc.body))
					}
					verdict := h.Run(t, request)
					if verdict.Err != nil {
						t.Fatal(verdict.Err)
					}
					if tc.status == 0 {
						verdict.RequireHeader(t, "Authorization", "Bearer private-access")
						if verdict.Kind != enginetest.VerdictMutated || verdict.RequestBodyChanged ||
							verdict.ModeOverride != nil {
							t.Fatalf("resource must forward without changing its body: %+v", verdict)
						}
					} else {
						verdict.RequireBlockedBody(t, tc.status, "")
						if strings.Contains(verdict.ImmediateBody, "private-") {
							t.Fatalf("private credential entered a local reply: %s", verdict.ImmediateBody)
						}
						var body map[string]any
						if err := json.Unmarshal([]byte(verdict.ImmediateBody), &body); err != nil {
							t.Fatal(err)
						}
						switch tc.name {
						case "device", "authorized device":
							if body["device_code"] != "session" {
								t.Fatalf("device session: %v", body)
							}
						case "poll", "JSON refresh":
							if body["access_token"] != "unused" || body["refresh_token"] != "unused" {
								t.Fatalf("workload token reply: %v", body)
							}
							if tc.name == "JSON refresh" && body["code"] != float64(0) {
								t.Fatalf("custom response was not projected: %v", body)
							}
						case "unsupported grant":
							if body["error"] != "unsupported_grant_type" {
								t.Fatalf("unsupported grant reply: %v", body)
							}
						case "authorization_pending", "slow_down":
							if body["error"] != tc.name || body["access_token"] != nil || body["refresh_token"] != nil {
								t.Fatalf("device polling error reply: %v", body)
							}
						}
					}
					wantCalls := int32(1)
					if tc.action == "" {
						wantCalls = 0
					}
					if calls.Load() != wantCalls {
						t.Fatalf("Identity calls = %d, want %d", calls.Load(), wantCalls)
					}
				})
			}
		})
	}
}

func oauth2ProfileYAML(kind, config string) string {
	namespace := ""
	if kind == kindSecurityProfile {
		namespace = "  namespace: test-ns\n"
	}
	return fmt.Sprintf(`apiVersion: agents.kruise.io/v1alpha1
kind: %s
metadata:
  name: oauth2
%sspec:
  selector:
    matchLabels: {app: sandbox}
  rules:
    - name: oauth2
      match:
        - domains: [api.example.test]
          paths: [{type: Exact, value: /oauth}]
      actions:
        tokenTransformation:
          type: OAuth2
          credentialRef: {credentialProvider: {name: business-provider}}
          oauth2:
            %s
`, kind, namespace, strings.ReplaceAll(config, "\n", "\n            "))
}

func TestOAuth2DocumentedLarkPolicy(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "docs/tasks/broker-oauth-credentials.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(data), "```yaml\n")
	if !found {
		t.Fatal("OAuth task guide has no YAML policy example")
	}
	policy, _, found := strings.Cut(rest, "```")
	if !found {
		t.Fatal("OAuth task guide has an incomplete YAML policy example")
	}
	NewFixture(t).ApplyYAML(policy)
}
