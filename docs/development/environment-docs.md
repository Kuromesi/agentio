# Generate environment variable documentation

The Agentiod and EPE reference tables are generated from `istio.io/istio/pkg/env` registrations, using the same `env.VarDescriptions()` registry as the CLI output. Add or update the name, default, and description in the owning package's `env.Register` call.

```sh
make gen.envdocs
make check.envdocs
```

`make gen` also regenerates the environment tables. Commit the generated document changes together with the registration changes. CI runs `make check.envdocs` to catch drift.

The generator builds both binaries with the repository's Go toolchain, then invokes `-print-env -print-env-format=markdown` in a clean environment. This includes registrations in each command package, such as Agentiod logging. Export exits before logging setup, Kubernetes client creation, and server startup. Only the regions between the generated environment markers are replaced; usage instructions and Helm examples remain hand-written.

Markdown output covers `AGENTIO_*` for Agentiod and `IDENTITY_PROVIDER_*`, `TOKEN_CACHE_*`, `STS_CACHE_*`, `CREDENTIAL_PROVIDER_*`, and `AUDIT_WEBHOOK_*` for EPE. Extend the command's prefix selection when introducing a new family of documented settings. Plain `-print-env` lists every visible registration, including dependencies; shared packages may register settings that a particular binary does not consume.

Types and defaults come from registration metadata, not current environment values or Helm values. Hidden variables are omitted and deprecated variables are marked. For a CPU-dependent default such as `AGENTIO_PUSH_CONCURRENCY`, the Markdown exporter replaces the machine-specific number with a reference to the registration's description. Keep that description consistent with the calculation when changing its behavior. Text output retains the binary's calculated default.

Settings read through `os.Getenv` without registration are outside this mechanism. Helm mappings, runtime resolution rules, and configuration examples belong in the surrounding reference prose.
