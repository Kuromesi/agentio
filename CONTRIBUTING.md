# Contributing to agentio

Agentio is a modified derivative of [Istio](https://istio.io/), licensed under the Apache License 2.0.

## Copyright headers

- **New files** authored for agentio: add the full Apache 2.0 header with `Copyright 2026 The Kruise Authors`.
- **Files derived from Istio that you modify**: keep the original `// Copyright Istio Authors` header and add a `// Modifications Copyright 2026 The Kruise Authors` line directly below it. Do not remove upstream copyright or license notices.
- Do not add modification notices to files you did not change.
- Run `./bin/fix_copyright_kruise.sh` to add the correct header automatically. Do **not** use `common/scripts/fix_copyright_banner.sh` for agentio files — it stamps the Istio banner.

## Contributing changes back to upstream Istio

Some changes may be contributed back to the upstream Istio project. Istio requires a signed-off Developer Certificate of Origin (DCO) on every commit: run `git commit -s`. Follow Istio's [contribution guidelines](https://github.com/istio/community/blob/master/CONTRIBUTING.md) for upstream PRs.
