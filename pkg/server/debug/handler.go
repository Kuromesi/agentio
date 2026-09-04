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

package debug

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/openkruise/agentio/pkg/compiler"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
)

const Path = "/debug/configz"

type Sources struct {
	AgentioConfig    krt.Collection[model.AgentioConfiguration]
	TrafficPolicies  krt.Collection[model.TrafficPolicy]
	SecurityProfiles krt.Collection[model.SecurityProfile]
	Gateways         krt.Collection[model.Gateway]
	GatewayPatches   krt.Collection[model.GatewayPatch]
	Telemetry        krt.Collection[model.Telemetry]
}

var supportedConfigDebugKinds = map[string]struct{}{
	"AgentioConfig":         {},
	"TrafficPolicy":         {},
	"GlobalTrafficPolicy":   {},
	"SecurityProfile":       {},
	"GlobalSecurityProfile": {},
	"Gateway":               {},
	"EnvoyFilter":           {},
	"Telemetry":             {},
}

// Real loopback peers bypass authentication; every other peer reuses the
// control plane authenticator and namespace authorization.
func NewHandler(
	sources Sources,
	resourceCompiler *compiler.Compiler,
	authenticator attestation.Authenticator,
	rootNamespace string,
) http.Handler {
	serveDump := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "malformed query", http.StatusBadRequest)
			return
		}
		filter, err := parseConfigDebugFilter(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		response, err := configDebugSnapshotAt(time.Now(), sources, resourceCompiler, filter)
		if err != nil {
			log.Error("config debug request failed", "path", r.URL.Path, "remote", r.RemoteAddr, "class", "snapshot_failed", "error", err)
			http.Error(w, "failed to build configuration snapshot", http.StatusInternalServerError)
			return
		}
		var encoded []byte
		if filter.Pretty {
			encoded, err = json.MarshalIndent(response, "", "  ")
		} else {
			encoded, err = json.Marshal(response)
		}
		if err != nil {
			log.Error("config debug request failed", "path", r.URL.Path, "remote", r.RemoteAddr, "class", "encoding_failed", "error", err)
			http.Error(w, "failed to encode configuration snapshot", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(encoded)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			w = configDebugHeadResponseWriter{ResponseWriter: w}
		}
		if !isLoopbackRemoteAddr(r.RemoteAddr) {
			identity, err := authenticateConfigDebugRequest(r, authenticator)
			if err != nil {
				log.Warn("config debug access denied", "path", r.URL.Path, "remote", r.RemoteAddr, "class", "authentication_failed")
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			if !authorizeConfigDebugIdentity(identity, rootNamespace) {
				log.Warn("config debug access denied", "path", r.URL.Path, "remote", r.RemoteAddr, "class", "authorization_failed")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		switch {
		case r.URL.Path == Path:
			serveDump(w, r)
		case r.URL.Path == LoggingPath || strings.HasPrefix(r.URL.Path, LoggingPath+"/"):
			serveLogging(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func parseConfigDebugFilter(values url.Values) (configDebugFilter, error) {
	for key, entries := range values {
		switch key {
		case "pretty", "kind", "namespace", "name":
		default:
			return configDebugFilter{}, fmt.Errorf("unsupported query parameter %q", key)
		}
		if len(entries) != 1 {
			return configDebugFilter{}, fmt.Errorf("query parameter %q must be specified once", key)
		}
	}
	filter := configDebugFilter{
		Pretty:    values.Has("pretty"),
		Kind:      values.Get("kind"),
		Namespace: values.Get("namespace"),
		Name:      values.Get("name"),
	}
	if values.Has("kind") {
		if _, supported := supportedConfigDebugKinds[filter.Kind]; !supported {
			return configDebugFilter{}, fmt.Errorf("unsupported configuration kind %q", filter.Kind)
		}
	}
	if values.Has("namespace") && filter.Namespace == "" {
		return configDebugFilter{}, fmt.Errorf("namespace filter must not be empty")
	}
	if values.Has("name") && filter.Name == "" {
		return configDebugFilter{}, fmt.Errorf("name filter must not be empty")
	}
	return filter, nil
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	address, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return false
	}
	return address.Addr().Unmap().IsLoopback()
}

func authenticateConfigDebugRequest(
	r *http.Request,
	authenticator attestation.Authenticator,
) (model.PeerIdentity, error) {
	incoming := metadata.MD{}
	for _, value := range r.Header.Values("Authorization") {
		incoming.Append("authorization", value)
	}
	return authenticator.Authenticate(metadata.NewIncomingContext(r.Context(), incoming))
}

func authorizeConfigDebugIdentity(identity model.PeerIdentity, rootNamespace string) bool {
	return identity.AttestedBy == model.AttestationKubernetes &&
		identity.Principal.Kind == model.PrincipalServiceAccount &&
		identity.Principal.Validate() == nil &&
		identity.Principal.ServiceAccount.Namespace == rootNamespace
}

type configDebugHeadResponseWriter struct {
	http.ResponseWriter
}

func (w configDebugHeadResponseWriter) Write(body []byte) (int, error) {
	return len(body), nil
}
