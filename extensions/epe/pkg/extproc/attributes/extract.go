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
// Package attributes resolves Envoy attributes — the request pseudo-headers,
// source identity and filter state — into the per-request context the engine
// consumes. Nothing here is expression-visible; the expression vocabulary
// lives in the inputs package.
package attributes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"

	extProcPb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	structpb "google.golang.org/protobuf/types/known/structpb"
	"k8s.io/apimachinery/pkg/types"
	log "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/extensions/epe/pkg/engine/filter"
	"istio.io/istio/extensions/epe/pkg/httpreq"
	"istio.io/istio/extensions/epe/pkg/labels"
	"istio.io/istio/extensions/epe/pkg/logging"
)

const (
	// ExtProcAttrsKey is the top-level key under which Envoy delivers the
	// ext_proc filter attributes.
	ExtProcAttrsKey = "envoy.filters.http.ext_proc"

	FilterStateDownstreamPeerName      = "filter_state['downstream_peer'].name"
	FilterStateDownstreamPeerNamespace = "filter_state['downstream_peer'].namespace"
	// AttrSourceAddress is Envoy's standard CEL attribute for the
	// connection peer (the calling Sandbox pod, from the egress gateway's
	// perspective). It is delivered as "<ip>:<port>"; only the IP half is
	// what we want, so callers strip the trailing port. The egress
	// gateway must list "source.address" in its ext_proc
	// request_attributes for this to be populated.
	AttrSourceAddress        = "source.address"
	FilterStateSandboxLabels = "filter_state['sandbox.labels']"
	FilterStateSandboxToken  = "filter_state['sandbox.token']"

	AttrDestinationPort = "destination.port"
)

// Extract resolves the Envoy ext-proc headers message and its attributes
// into the per-request Peer (caller identity and credential) and
// httpreq.HTTPRequest (with the destination.port override applied). When pod
// identity is missing from filter_state it returns a partial Peer and a zero
// HTTPRequest and logs the condition; callers should check Peer.Valid and
// fail open. A malformed sandbox token leaves Peer.Token nil. Log lines use
// the logger from ctx, so request-scoped key/values are carried on them.
func Extract(ctx context.Context, headers *extProcPb.HttpHeaders, attrs map[string]*structpb.Struct) (filter.Peer, httpreq.HTTPRequest) {
	logger := log.FromContext(ctx)
	loggerD := logger.V(logging.DEBUG)

	podNamespace := extractFilterStateString(attrs, FilterStateDownstreamPeerNamespace)
	podName := extractFilterStateString(attrs, FilterStateDownstreamPeerName)
	peer := filter.Peer{
		Pod: types.NamespacedName{Namespace: podNamespace, Name: podName},
		IP:  extractPodIP(attrs),
	}
	sandboxLabelsEncoded := extractFilterStateString(attrs, FilterStateSandboxLabels)

	if podNamespace == "" || podName == "" {
		// Operator-visible: the ext-proc filter relies on Envoy populating
		// filter_state['downstream_peer'] (e.g. via the Istio metadata
		// exchange filter or an equivalent). Without it we cannot resolve
		// the source pod, so no SecurityProfile can be applied. Pass the
		// request through and let the operator find the misconfiguration.
		logger.Info("Pod identity missing from filter_state; passing request through unmodified",
			"podNamespace", podNamespace, "podName", podName)
		return peer, httpreq.HTTPRequest{}
	}

	// Pod labels come from filter_state['sandbox.labels'], a base64-encoded
	// "k1=v1,k2=v2" string.
	podLabels := labels.ParseSandboxLabels(sandboxLabelsEncoded)
	if sandboxLabelsEncoded != "" && len(podLabels) == 0 {
		loggerD.Info("sandbox.labels was present but failed to decode", "encoded", sandboxLabelsEncoded)
	}
	// Guarded: Go builds the key-value slice at the call site, before Info can
	// check the level and drop it, so an unguarded line costs an allocation on
	// every request even with DEBUG off.
	if loggerD.Enabled() {
		loggerD.Info("Extracted pod info from attributes",
			"pod", podName, "namespace", podNamespace, "labels", podLabels)
	}
	peer.Labels = podLabels

	peer.Token = parseSandboxToken(ctx, extractFilterStateString(attrs, FilterStateSandboxToken))

	req := parseHTTPRequest(ctx, extractHeaderMap(headers))

	// Override port with the real TCP destination port from envoy if available.
	if dstPort := extractAttributeInt(attrs, AttrDestinationPort); dstPort > 0 && dstPort <= 65535 {
		req.Port = int32(dstPort)
	}

	return peer, req
}

// parseSandboxToken parses the raw filter_state['sandbox.token'] string:
// base64-decoded JSON, falling back to raw JSON when the value is not valid
// base64. On success the parsed token is returned; on failure a DEBUG line
// is logged and nil is returned. Returns nil when the raw value is empty.
func parseSandboxToken(ctx context.Context, raw string) *filter.SandboxToken {
	if raw == "" {
		return nil
	}
	tokenJSON, decErr := base64.StdEncoding.DecodeString(raw)
	if decErr != nil {
		tokenJSON = []byte(raw)
	}
	var st filter.SandboxToken
	if err := json.Unmarshal(tokenJSON, &st); err != nil {
		log.FromContext(ctx).V(logging.DEBUG).Info("Failed to parse sandbox.token", "error", err.Error())
		return nil
	}
	return &st
}

// extractPodIP returns the caller pod IP from Envoy's source.address
// attribute, delivered as "<ip>:<port>"; only the IP half is returned.
// Returns an empty string when the attribute is absent or unparseable.
func extractPodIP(attrs map[string]*structpb.Struct) string {
	raw := extractFilterStateString(attrs, AttrSourceAddress)
	if raw == "" {
		return ""
	}
	if raw[0] == '[' {
		if end := strings.IndexByte(raw, ']'); end > 0 {
			return raw[1:end]
		}
		return raw
	}
	if idx := strings.LastIndexByte(raw, ':'); idx >= 0 {
		return raw[:idx]
	}
	return raw
}

// getExtProcStruct returns the top-level structpb.Struct for the ext_proc
// filter attributes without any copying or allocation.
func getExtProcStruct(attrs map[string]*structpb.Struct) *structpb.Struct {
	if attrs == nil {
		return nil
	}
	if s, ok := attrs[ExtProcAttrsKey]; ok {
		return s
	}
	for key, s := range attrs {
		if strings.Contains(key, "ext_proc") {
			return s
		}
	}
	return nil
}

// extractAttributeInt extracts a numeric attribute from the ext_proc
// attributes struct. Returns 0 when the key is absent or not numeric.
func extractAttributeInt(attrs map[string]*structpb.Struct, key string) int64 {
	s := getExtProcStruct(attrs)
	if s == nil {
		return 0
	}
	fields := s.GetFields()
	if fields == nil {
		return 0
	}
	v, ok := fields[key]
	if !ok {
		return 0
	}
	if n := v.GetNumberValue(); n != 0 {
		return int64(n)
	}
	return 0
}

// extractFilterStateString extracts a string value from the Envoy ext_proc
// filter_state attributes using zero-copy protobuf field access. It looks up
// the key directly, then tries the filter_state['key'] format, and finally
// falls back to a suffix match.
func extractFilterStateString(attrs map[string]*structpb.Struct, key string) string {
	s := getExtProcStruct(attrs)
	if s == nil {
		return ""
	}
	fields := s.GetFields()
	if fields == nil {
		return ""
	}
	if v, ok := fields[key]; ok {
		return valueToString(v)
	}
	fsKey := "filter_state['" + key + "']"
	if v, ok := fields[fsKey]; ok {
		return valueToString(v)
	}
	for k, v := range fields {
		if strings.HasSuffix(k, key) {
			return valueToString(v)
		}
	}
	return ""
}

// valueToString extracts a string from a structpb.Value. For simple string
// values it returns directly; for struct values it looks for a "value" field.
func valueToString(v *structpb.Value) string {
	if v == nil {
		return ""
	}
	if s := v.GetStringValue(); s != "" {
		return s
	}
	if sv := v.GetStructValue(); sv != nil {
		if inner, ok := sv.GetFields()["value"]; ok {
			return inner.GetStringValue()
		}
	}
	return ""
}

// extractHeaderMap converts Envoy's HeaderMap to a plain string map for easier processing.
// Envoy normalizes header names to lowercase per HTTP/2 spec, so keys are stored in lowercase.
func extractHeaderMap(headers *extProcPb.HttpHeaders) map[string]string {
	if headers == nil || headers.GetHeaders() == nil {
		return map[string]string{}
	}
	hs := headers.GetHeaders().GetHeaders()
	// Sized up front: without the hint the map rehashes several times on a
	// realistic header count, and the header count is known here.
	result := make(map[string]string, len(hs))
	for _, h := range hs {
		if h.Key != "" {
			result[strings.ToLower(h.Key)] = string(h.RawValue)
		}
	}
	return result
}
