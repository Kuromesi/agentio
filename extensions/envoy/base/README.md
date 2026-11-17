# Agentio Envoy base image

This directory maintains a small Envoy patch for legacy external processors that read `filter_state['downstream_peer'].name` and `filter_state['downstream_peer'].namespace`.

`versions.env` pins the Envoy source, build image, and runtime image. The final base image replaces only `/usr/local/bin/envoy` in the pinned runtime image. It does not contain gateway-agent or Rust dynamic modules.

## Compatibility interface

The patch registers the `agentio.legacy_downstream_peer` filter-state object factory in Envoy's existing set-filter-state implementation. Its input is `name` followed by one newline and `namespace`. Both fields must be nonempty; extra newlines are rejected. Kubernetes workload names and namespaces cannot contain newlines.

The object exposes only the CEL string fields `name` and `namespace`. Unknown fields are absent. The factory does not restore Istio peer discovery or read client headers.

The internal control plane must create this object from the trusted canonical workload identity before the business ext_proc filter runs. Installing the image alone does not create `downstream_peer`. `sandbox.labels` remains a separate filter-state entry with its existing encoding and label filtering.

The factory's C++ tests are included in the patch at `//test/extensions/filters/common/set_filter_state:filter_config_test`. They cover field access, unknown fields, malformed input, and the absence of upstream sharing by default.

## Build status

The build workflow and ECS provisioning are not included in this initial review. The patch has not been compiled or runtime-tested. Review this compatibility interface before starting the native amd64 and arm64 builds.
