# Building and updating ztunnel

Agentio builds ztunnel from the `ZTUNNEL_REPO_SHA` entry in `agentio.deps`.
The pin records the source repository and full commit SHA, using the same format
on `master` and `release-0.1`. Updating this pin does not require an image to have
been published by the ztunnel repository.

## Source updates

`Sync ztunnel dependency` runs daily at 02:23 UTC. It resolves the pinned source
repository's default branch and opens separate dependency PRs targeting Agentio
`master` and `release-0.1`. Each target has its own automation branch and
concurrency group. Other dependency entries are preserved.

To update one branch manually, run:

```bash
gh workflow run sync-ztunnel-deps.yml --repo openkruise/agentio --ref master \
  -f target_branch=master
```

Use `target_branch=release-0.1` or `target_branch=all` for the other targets.
Set `dry_run=true` to validate the source update without opening a PR.
The sync uses the Agentio repository's `AGENTIO_SYNC_APP_CLIENT_ID` and
`AGENTIO_SYNC_APP_PRIVATE_KEY` with contents and pull request write permissions.

## Master builds and releases

The reusable `agentio-ztunnel` workflow checks out the pinned source, compiles on
native amd64 and arm64 runners with the corresponding BoringSSL FIPS libraries,
and smoke-tests the binaries in Agentio's pinned runtime image. It uploads the
binaries for the calling workflow; no registry credentials are needed to compile.

Presubmit builds the amd64 ztunnel image alongside agentiod, EPE, and the test
fixture. Each E2E job publishes those local candidates into its isolated registry
and tests their immutable digests. Dependency PRs therefore exercise their new
ztunnel source before merging, including PRs from forks.

`agentio-image` packages both architectures and publishes ztunnel with the Agentio
candidate tag alongside agentiod and EPE, using Agentio's `development`
environment credentials. The source commit is recorded in the image version and
OCI revision label. The image tag identifies the Agentio build; it need not equal
the ztunnel source SHA.

`agentio-release` uses the resulting ztunnel digest for the candidate chart, E2E,
and release BOM. After E2E succeeds, it promotes that same digest to the release
version, and to `latest` for stable releases, without rebuilding it. CNI,
proxy-init, gateway, and trust-package dependencies continue to use image pins.

`release-0.1` retains its existing Agentio-owned compilation and publication
workflow. The shared sync on `master` updates its source pin directly.

The `sync-agentio-dependency-bom` workflow continues accepting published CNI,
proxy-init, and gateway images. Legacy ztunnel image notifications are ignored;
Agentio no longer needs ztunnel's independent image publisher or its credentials.
