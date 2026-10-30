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

// Full-chain AliyunSTS re-signing scenarios driven through the enginetest
// harness; see extensions/epe/pkg/testing/enginetest/doc.go for the test
// layering convention. They live in this directory, not next to the filter,
// so the signer's wire-level tests stay with the signer. Signature
// algorithms and detection branches stay in sign/; signer-level behaviour
// in aliyun_test.go.
package securityprofile

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	"github.com/openkruise/agentio/pkg/kube"
)

const stsProfileYAML = `
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: sts-resign
  namespace: test-ns
spec:
  selector:
    matchLabels:
      app: sandbox
  rules:
  - name: resign
    match:
    - domains:
      - "*"
    actions:
      tokenTransformation:
        type: AliyunSTS
        credentialRef:
          kind: Secret
          name: sts-creds
`

func stsSecret() *corev1.Secret {
	return newSTSSecret("test-ns", "sts-creds", "STS.NEWAK", "NEWSECRET", "NEWTOKEN")
}

func v3Request() *enginetest.RequestBuilder {
	return enginetest.NewRequest("POST", "ecs.cn-hangzhou.aliyuncs.com", "/").
		Workload("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
		Header("host", "ecs.cn-hangzhou.aliyuncs.com").
		Header("x-acs-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").
		Header("authorization", "ACS3-HMAC-SHA256 Credential=OLDAK,SignedHeaders=host,Signature=stale").
		Header("x-acs-accesskey-id", "OLDAK").
		Header("x-acs-security-token", "OLDSTS")
}

// TestScenario_V3ResignFromSecret proves the ACS3 header re-signing path
// end to end: the AliyunSTS signer is reachable through the registry, the
// STS triplet is read from the pod-namespace Secret, and the signature
// headers are rewritten in the response mutation.
func TestScenario_V3ResignFromSecret(t *testing.T) {
	h := New(t, Options{Kube: kube.NewFakeClient(stsSecret())})
	h.Fixture.ApplyYAML(stsProfileYAML)

	verdict := h.Run(t, v3Request())
	verdict.RequireOutcome(t, "mutated")
	verdict.RequireHeader(t, "x-acs-security-token", "NEWTOKEN")
	authorization := verdict.RequestHeaderValues("authorization")
	if len(authorization) != 1 {
		t.Fatalf("authorization values = %v, want exactly one (ops=%+v)", authorization, verdict.RequestHeaderOps)
	}
	if !strings.Contains(authorization[0], "STS.NEWAK") || strings.Contains(authorization[0], "OLDAK") {
		t.Errorf("authorization = %q, want new access key and no old one", authorization[0])
	}
}

// TestScenario_V1RPCQueryOnlyPOSTResignsWithoutBody proves at wire level
// that a V1-RPC POST with all parameters in the query string is re-signed
// in the headers phase without requesting body delivery from Envoy.
func TestScenario_V1RPCQueryOnlyPOSTResignsWithoutBody(t *testing.T) {
	h := New(t, Options{Kube: kube.NewFakeClient(stsSecret())})
	h.Fixture.ApplyYAML(stsProfileYAML)

	verdict := h.Run(t, enginetest.NewRequest("POST", "ecs.cn-hangzhou.aliyuncs.com",
		"/?Action=DescribeInstances&AccessKeyId=OLDAK&SecurityToken=OLDSTS"+
			"&Signature=oldSignature&SignatureMethod=HMAC-SHA1&SignatureVersion=1.0").
		Workload("test-ns", "sandbox-pod", map[string]string{"app": "sandbox"}).
		Header("host", "ecs.cn-hangzhou.aliyuncs.com"))

	verdict.RequireOutcome(t, "mutated")
	if verdict.ModeOverride != nil {
		t.Fatalf("query-only V1-RPC POST requested body delivery: %v", verdict.ModeOverride)
	}
	newPath := verdict.RequestHeaderValues(":path")
	if len(newPath) != 1 {
		t.Fatalf(":path values = %v, want exactly one rewrite (ops=%+v)", newPath, verdict.RequestHeaderOps)
	}
	if !strings.Contains(newPath[0], "AccessKeyId=STS.NEWAK") || strings.Contains(newPath[0], "oldSignature") {
		t.Errorf(":path = %q, want re-signed query with new access key", newPath[0])
	}
}

// An out-of-scope Secret follows the default Block strategy.
func TestScenario_OutsideSecretNamespaceHonoursBlockStrategy(t *testing.T) {
	h := New(t, Options{Kube: kube.NewFakeClient(stsSecret()), SecretNamespace: "agentio-system"})
	h.Fixture.ApplyYAML(stsProfileYAML)

	h.Run(t, v3Request()).RequireBlocked(t, 403)
}
