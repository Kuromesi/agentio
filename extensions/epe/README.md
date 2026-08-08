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

The container image is defined by `extensions/epe/docker/Dockerfile`, which expects the `epe` binary under `<TARGETARCH>/`.

The complete Agentio KinD E2E package and scenario matrix can be run with:

```bash
make test.e2e.agentio
```

This product-level validation exercises EPE through the ext-proc E2E tests in `tests/integration/agentio` alongside the other Agentio E2E packages and scenarios.
