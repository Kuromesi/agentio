# EPE (Egress Policy Enforcer)

EPE is Agentio's Envoy external processor for applying `SecurityProfile` and `GlobalSecurityProfile` rules to agent egress traffic. The deployed artifact is named `agentio-epe` (image, chart `epe.*` values, Kubernetes resources); the code lives under `extensions/epe/`.

The `tokenTransformation` action can fetch short-lived credentials from an external credential provider; the HTTP contract a provider must implement is documented in [docs/reference/credential-provider.md](../../docs/reference/credential-provider.md).

## Code layout

```text
extensions/epe/
├── cmd/
│   └── epe/                 # Process entrypoint, flags, Kubernetes clients,
│                            # health, admin, metrics, and TLS setup.
├── pkg/
│   ├── engine/              # Evaluates rules in policy order and actions within each
│   │   │                    # rule in registration order. Owns body-phase cursor
│   │   │                    # continuation, the per-invocation budget/metrics wrapper,
│   │   │                    # and net-effect mutation folding. Its dependency closure
│   │   │                    # is guarded free of the policy API and ext_proc protos.
│   │   └── filter/          # Filter contract: interface, actions, mutations,
│   │                        # registry, stream info, peer identity.
│   ├── extproc/             # The protocol edge: ext_proc stream handling, body
│   │   │                    # handling, and response translation.
│   │   └── attributes/      # Envoy attribute and filter-state extraction.
│   ├── filters/             # Concrete filters implementing the contract:
│   │   │                    # block, bypass, mcpacl, tokentransform.
│   │   └── tokentransform/
│   │       └── signers/     # Per-provider request re-signing; aliyun implements the
│   │                        # published ACS V3/ROA/RPC and OSS V4 signing specs.
│   ├── policy/              # The only subtree allowed to import the CRD API.
│   │   ├── securityprofile/ # Compiled profile model, rule binder, resolver,
│   │   │                    # and the policy-side audit stream logger.
│   │   └── profilestore/    # KRT-backed SecurityProfile and GlobalSecurityProfile
│   │                        # watches and lock-free snapshots.
│   ├── wiring/              # Composition root assembling the production filter
│   │                        # chain and loggers; hosts the arch guard tests.
│   ├── eval/                # CEL/template evaluation.
│   ├── inputs/              # Shared request evaluation scope.
│   ├── httpreq/             # Neutral HTTP request tuple.
│   ├── audit/               # Audit routing and CEL conditions, plus the shared
│   │   │                    # bounded async delivery primitive.
│   │   ├── accesslog/       # Per-request audit log entries.
│   │   └── sinks/webhook/   # Audit webhook rendering and delivery.
│   ├── credential/          # Credential-provider client and token caches.
│   ├── certs/               # Serving certificate providers and SPIFFE-aware TLS validation.
│   ├── admin/               # Admin and profile-debug HTTP endpoints.
│   ├── server/              # ext_proc gRPC server construction.
│   ├── metrics/             # Process-wide Prometheus registry.
│   ├── labels/              # Label key/value pair parsing.
│   ├── logging/             # Log verbosity level constants.
│   ├── runnable/            # Long-running component contract and gRPC/HTTP adapters.
│   └── testing/
│       ├── enginetest/      # Full-chain scenario-test harness (fake Envoy stream, YAML
│       │                    # fixtures, audit receiver, metric probes).
│       └── filtertest/      # Shared fakes for filter unit tests.
└── docker/                  # Runtime container image definition.
```

## Build and test

From the Agentio repository root:

```bash
go test -race -count=1 ./extensions/epe/...
go build ./extensions/epe/cmd/epe
```

The container image is `agentio-epe`, defined by `extensions/epe/docker/Dockerfile` and registered in `tools/docker.yaml`:

```bash
make docker.agentio-epe
DOCKER_ARCHITECTURES=linux/amd64,linux/arm64 make docker.agentio-epe
```

The Dockerfile expects the `epe` binary under `<TARGETARCH>/`; the docker builder supplies that layout by running `${TARGET_OUT_LINUX}/epe` once per requested architecture, so a multi-architecture build needs no arch-specific wiring beyond `EXTENSION_BINARIES` in `Makefile.core.mk`. The release pipeline builds `linux/amd64,linux/arm64` and publishes the image under the Agentio release version.

The complete Agentio KinD E2E package and scenario matrix can be run with:

```bash
make test.e2e.agentio
```

That suite validates the mesh side of the ext_proc contract — `tests/integration/agentio/extproc_test.go` deploys the stub server from `pkg/test/extproc` (`testdata/ext-proc.yaml:31`) and asserts Envoy is configured to call it. It does not run the `agentio-epe` image, and no scenario sets `epe.enabled=true`; the KinD build list includes `docker.agentio-epe` only so image build regressions surface on presubmit.

EPE's own behavior is covered in-process by the `enginetest` harness, which drives the real `extproc.Server.Process` loop and the production filter chain over a fake Envoy stream (`pkg/testing/enginetest/doc.go`). The boundaries that harness names as out-of-scope — Envoy-authenticated attributes, egress TLS termination, apiserver/CRD deployment consistency, krt watch propagation, cross-pod webhook delivery — have no KinD coverage today.

## Contributor guide

Keep the policy boundary intact: `pkg/policy/` owns the SecurityProfile CRD API. The architecture guard permits only two narrow exceptions: `pkg/admin/` renders CRD-typed debug views, and `pkg/testing/enginetest/` authors CRD objects for tests. `pkg/extproc/` translates the external-processing protocol; `pkg/engine/` and `pkg/filters/` remain policy- and ext_proc-proto-free. `pkg/wiring/` is the composition root and its architecture guards enforce these rules.

To add an action/filter, define its schema and descriptor under `pkg/filters/`, register it in `pkg/wiring/`, and map the CRD action to the filter payload in `pkg/policy/securityprofile/payloads.go`. Add the action's CRD/API schema upstream rather than hand-editing generated CRDs. Update `pkg/wiring/arch_guard_test.go` when a new filter needs a source-directory mapping, and cover parsing, action behavior, and a full-chain fixture.

Use focused checks while iterating:

```bash
go test ./extensions/epe/pkg/filters/<filter>/...
go test ./extensions/epe/pkg/policy/securityprofile/...
go test ./extensions/epe/pkg/wiring/...
go test ./extensions/epe/pkg/testing/enginetest/...
```

The `enginetest` harness is the scenario boundary for EPE behavior: write YAML profile fixtures and drive the real processing loop with its fake Envoy stream. `make test.e2e.agentio` does not deploy `agentio-epe` or set `epe.enabled=true`; it validates the mesh ext_proc plumbing against a stub and builds the EPE image on presubmit. Treat the Envoy-authenticated attributes, gateway TLS termination, Kubernetes watch/deployment propagation, and cross-Pod webhook delivery as KinD coverage gaps.
