# Go quality checks

`make lint` runs `go vet` for the main module and the e2e module.
`make lint.golangci` runs the pinned golangci-lint version from the Makefile
against the main module, using `.golangci.yml`. It includes error checking,
exported API documentation, duplication, complexity, and import formatting.
Generated files are excluded; test functions are exempt from documentation,
duplication, and complexity checks.

The full golangci-lint audit currently contains historical findings. To check
changes relative to a known base:

```sh
make lint.golangci GOLANGCI_LINT_ARGS="--new-from-rev=<base-commit>"
```

CI uses the pull request base or the previous push commit. Thus a long-lived
feature branch can still report findings from earlier commits on that branch;
this is not a clean baseline for the entire branch. New rules do not replace
the existing full-module `go vet` gate.

An installed binary can be used with `GOLANGCI_LINT=golangci-lint`. Configuration
uses the [golangci-lint v2 schema](https://golangci-lint.run/docs/configuration/file/).

## Equality benchmarks

```sh
go test ./pkg/model -run '^$' -bench BenchmarkModelEquals -benchmem -count=3
```

The fixtures use independently allocated equal objects to model an unchanged
informer update. The Workload, Sandbox, and Service comparisons preserve field
order where applicable and distinguish nil from empty maps and slices. Their
field-coverage tests also fail when a new field is added but omitted from Equals.

These microbenchmarks measure equality costs, not end-to-end KRT throughput.
TrafficPolicy, SecurityProfile, and Telemetry retain their existing comparisons;
changing their nested specifications requires separate profiling and semantic
coverage.

Measured on Apple M4, darwin/arm64, Go 1.26.5 (median of three runs):

| Equal, independently allocated objects | Before (ns/op) | After (ns/op) | Allocations before → after |
| --- | ---: | ---: | ---: |
| Workload | 547.4 | 73.73 | 11 → 0 |
| Sandbox | 417.1 | 60.12 | 11 → 0 |
| Service | 279.6 | 18.01 | 2 → 0 |
