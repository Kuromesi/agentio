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

// Package enginetest is an in-process test harness for the traffic
// extension request-handling engine. It drives the real ext_proc
// extproc.Server.Process loop through a fake Envoy stream, compiles
// SecurityProfile fixtures through the production pipeline (including CRD
// structural defaulting and offline CEL validation against the chart's CRD
// manifests), and reduces the response sequence to a Verdict.
//
// # Where tests live
//
// enginetest is a toolbox, not a home for feature tests:
//
//   - Single-package semantics (matchers, policy evaluation, sorting) stay
//     in the owning package's ordinary _test.go files and do not need this
//     harness.
//   - Full-chain scenarios (CRD YAML -> plugin chain -> verdict) live next
//     to the behavior they exercise, in an external test package that
//     imports enginetest: package mcpacl_test for MCP policy wiring,
//     package extproc_test for orchestration behavior, and so on. The
//     external package form avoids an import cycle, since enginetest
//     imports the engine packages.
//   - The _test.go files inside this package only prove the harness itself
//     works.
//
// Only integration boundaries that cannot exist in-process stay in
// tests/integration/agentio: Envoy-authenticated
// attributes, egress TLS termination, apiserver/CRD deployment
// consistency, krt watch propagation, and cross-pod webhook delivery.
package enginetest
