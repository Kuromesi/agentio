# Maintained pilot-agent extraction

Source baseline: `openkruise/agentio`, `release-0.1`, commit `169bad3c36783711989757cd907465b8fe9cfc3a`. Original code is Apache-2.0; copyright notices are retained. These are local sources, not an Istio Go library dependency. The gateway binary must have no `istio.io/*` package in its dependency tree, including indirect imports.

| Local code | Source and changes |
| --- | --- |
| `envoy/agent.go`, `envoy/proxy.go`, `envoy/admin.go` | Copied from `pkg/envoy`. Replace Istio logging, collections, HTTP and environment helpers with standard-library implementations. Remove FIPS, bootstrap overrides and permissive unknown-static-field handling. Bound Admin requests, reap the child on kill/skip-drain, and bound the optional active-connection drain loop. |
| `envoy/ready.go`, `envoy/stats.go` | Copied from `pilot/cmd/pilot-agent/status/ready/probe.go` and `status/util/stats.go`. Preserve initial CDS/LDS and LIVE/workers checks. Remove Istio startup metric and helper dependencies. |
| `../identity.go` | Adapt the `security/pkg/nodeagent/cache/secretcache.go` CSR/cache/rotation responsibilities and `caclient/providers/citadel/client.go` signing protocol. This is a reduced implementation, not a verbatim copy of the complete secret cache. Retain locally generated RSA keys, SPIFFE CSR, actual certificate expiry, 50% rotation grace and 1% jitter. Use Go `crypto/x509`; reload token and roots per signing attempt, bound retries, validate returned identity/key/chain, and retain a valid cached certificate during CA failure. |
| `../sds.go` | Adapt `security/pkg/nodeagent/sds/sdsservice.go` resource generation and watch/push behavior. Replace the generic Istio xDS framework with a bounded SotW stream loop for `default` and `ROOTCA`; reject arbitrary file and domain secret requests. Local SDS remains SotW, as in pilot-agent. |
| `caproto/ca.proto`, generated Go | Vendor the CA wire schema from `istio/api` commit `f9b16f1f49ce`, the API dependency of the release baseline. Preserve protobuf service/message names for compatibility with agentiod. The local Go package owns the implementation; no Istio API Go import is used. |

Additional intentional differences:

- Projected workload trust roots come from the mounted ConfigMap or ClusterTrustBundle, not `istio.mesh.v1alpha1.ProxyConfig` discovery. A one-second poll follows projected-volume symlink swaps independently of CA signing requests. A signing attempt has a ten-second deadline. Malformed/missing replacements retain the last valid bundle. Root changes trigger renewal and an SDS push.
- Only Pod-token authentication and the existing CA signing protocol are retained. No cloud credential plugins, arbitrary file SDS, output-certificate files, private-key providers, CRL discovery, external SDS delegation or mesh bootstrap.
- `../xds.go` is an Agentio transparent ADS relay, not a copy of pilot-agent's generic proxy with DNS, Wasm download/config rewriting, health and trust-bundle subscription processing. Native Envoy Wasm/ECDS remains available. The relay retains the release baseline's gRPC keepalive defaults without importing its helpers.
- SDS and ADS stay alive until Envoy drain and process cleanup finish.

When updating from pilot-agent, review upstream fixes to these source paths and port applicable fixes explicitly. Do not restore a whole-agent dependency.

Regenerate the local CA message code with `protoc-gen-go v1.36.11`, staging `ca.proto` at `security/v1alpha1/ca.proto`, and passing `--go_opt=module=github.com/openkruise/agentio`. The vendored gRPC stubs retain the unchanged service definition. Protocol compatibility does not require importing the original Go module.

Legacy gateway compatibility:

- `gateway-agent --legacy` uses a separate bootstrap for the pinned custom Envoy (`LEGACY_ENVOY_IMAGE` in `docker/Dockerfile.gateway`). Build with `--target legacy`; its default command enables legacy mode. The default/community target is unchanged.
- The compatibility contract retains `waypoint~IP~pod.namespace~DNS-domain`, proxy version `1.29`, metadata discovery, policy store, and the release baseline runtime and statistics settings. Active-connection statistics remain enabled for drain. Agent build metadata stays independent of the proxy compatibility version.
- Defaults use `/etc/istio/proxy`, `/var/run/secrets/istio/root-cert.pem` and `/var/run/secrets/tokens/istio-token`. Existing `AGENTIO_*` path overrides still work. `CA_ADDR` is also the discovery address when `AGENTIO_XDS_ADDRESS` is absent. `AGENTIO_DNS_DOMAIN` defaults to `<namespace>.svc.cluster.local`; `AGENTIO_SERVICE_CLUSTER` defaults to `<workload>.<namespace>`, using `ISTIO_META_WORKLOAD_NAME` when set and otherwise the Pod name.
- Mounted `/etc/istio/pod/labels` supplies policy selector metadata. Custom metadata still uses `AGENTIO_META_*` and `AGENTIO_METAJSON_*`; this does not emulate the pilot-agent CLI or its `PROXY_CONFIG` input. Deployments must change their args to `--legacy`, supply `POD_UID`, and explicitly wire worker/drain options as needed.
- Trust roots still come from projected files, not mesh ProxyConfig discovery. Switching the executable does not restore cloud credentials, DNS capture, or agent-side Wasm downloading. Existing deployment defaults are not switched.

Legacy bootstrap runtime and statistics values are adapted from `tools/packaging/common/envoy_bootstrap.json` and `pkg/bootstrap/config.go` at the source baseline above.
