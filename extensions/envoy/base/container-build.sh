#!/usr/bin/env bash
# Copyright 2026 The Kruise Authors
set -euo pipefail

cd /source
bazel_options=(
  -c opt --strip=always --jobs="${BUILD_JOBS:-24}"
  --repository_cache=/build/repository-cache
  --disk_cache=/build/action-cache
)
bazel --output_user_root=/build/bazel-root test "${bazel_options[@]}" \
  --test_output=errors \
  //test/extensions/filters/common/set_filter_state:filter_config_test
bazel --output_user_root=/build/bazel-root build "${bazel_options[@]}" \
  //source/exe:envoy-static
install -m 755 bazel-bin/source/exe/envoy-static /output/envoy
