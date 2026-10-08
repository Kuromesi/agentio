# Maintained pilot-agent extraction

Source baseline: `openkruise/agentio`, `release-0.1`, commit
`169bad3c36783711989757cd907465b8fe9cfc3a`. Original code is Apache-2.0;
copyright notices are retained. These are local sources, not an Istio Go library
dependency. The gateway binary must have no `istio.io/*` package in its dependency
tree, including indirect imports.

| Local code | Source and changes |
| --- | --- |
| `envoy/agent.go`, `envoy/proxy.go`, `envoy/admin.go` | Copied from `pkg/envoy`. Replace Istio logging, collections, HTTP and environment helpers with standard-library implementations. Remove FIPS, bootstrap overrides and permissive unknown-static-field handling. Bound Admin requests, reap the child on kill/skip-drain, and bound the optional active-connection drain loop. |
| `envoy/ready.go`, `envoy/stats.go` | Copied from `pilot/cmd/pilot-agent/status/ready/probe.go` and `status/util/stats.go`. Preserve initial CDS/LDS and LIVE/workers checks. Remove Istio startup metric and helper dependencies. |
| `../identity.go` | Adapt the `security/pkg/nodeagent/cache/secretcache.go` CSR/cache/rotation responsibilities and `caclient/providers/citadel/client.go` signing protocol. This is a reduced implementation, not a verbatim copy of the complete secret cache. Retain locally generated RSA keys, SPIFFE CSR, actual certificate expiry, 50% rotation grace and 1% jitter. Use Go `crypto/x509`; reload token and roots per signing attempt, bound retries, validate returned identity/key/chain, and retain a valid cached certificate during CA failure. |
| `../sds.go` | Adapt `security/pkg/nodeagent/sds/sdsservice.go` resource generation and watch/push behavior. Replace the generic Istio xDS framework with a bounded SotW stream loop for `default` and `ROOTCA`; reject arbitrary file and domain secret requests. Local SDS remains SotW, as in pilot-agent. |
| `caproto/ca.proto`, generated Go | Vendor the CA wire schema from `istio/api` commit `f9b16f1f49ce`, the API dependency of the release baseline. Preserve protobuf service/message names for compatibility with agentiod. The local Go package owns the implementation; no Istio API Go import is used. |

Additional intentional differences:

- Projected workload trust roots come from the mounted ConfigMap or
  ClusterTrustBundle, not `istio.mesh.v1alpha1.ProxyConfig` discovery. A one-second
  poll follows projected-volume symlink swaps. A signing attempt has a ten-second
  deadline, so a blocked CA can delay that loop. Malformed/missing replacements
  retain the last valid bundle. Root changes trigger renewal and an SDS push.
- Only Pod-token authentication and the existing CA signing protocol are retained.
  No cloud credential plugins, arbitrary file SDS, output-certificate files,
  private-key providers, CRL discovery, external SDS delegation or mesh bootstrap.
- `../xds.go` is an Agentio transparent ADS relay, not a copy of pilot-agent's
  generic proxy with DNS, Wasm download/config rewriting, health and trust-bundle
  subscription processing. Native Envoy Wasm/ECDS remains available. The relay
  retains the release baseline's gRPC keepalive defaults without importing its helpers.
- SDS and ADS stay alive until Envoy drain and process cleanup finish.

When updating from pilot-agent, review upstream fixes to these source paths and
port applicable fixes explicitly. Do not restore a whole-agent dependency.

Regenerate the local CA message code with `protoc-gen-go v1.36.11`, staging
`ca.proto` at `security/v1alpha1/ca.proto`, and passing
`--go_opt=module=github.com/openkruise/agentio`. The vendored gRPC stubs retain the
unchanged service definition. Protocol compatibility does not require importing
the original Go module.
