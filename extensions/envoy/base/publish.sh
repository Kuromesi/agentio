#!/usr/bin/env bash
# Copyright 2026 The Kruise Authors
set -euo pipefail

base=$(cd "$(dirname "$0")" && pwd)
revision=$(git -C "$base" rev-parse HEAD)
image=${1:?usage: publish.sh IMAGE TAG AMD64_IMAGE ARM64_IMAGE}
tag=${2:?missing tag}
amd64=${3:?missing amd64 image}
arm64=${4:?missing arm64 image}
exec 9>"${DATA_DIR:-/disk1/agentio-envoy}/build.lock"
flock -n 9
for arch in amd64 arm64; do
  reference=$amd64
  [[ $arch != arm64 ]] || reference=$arm64
  docker pull --platform "linux/$arch" "$reference"
  actual_arch=$(docker image inspect --format '{{.Architecture}}' "$reference")
  actual_revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$reference")
  if [[ $actual_arch != "$arch" || $actual_revision != "$revision" ]]; then
    echo "Expected $arch image from $revision; got $actual_arch from $actual_revision" >&2
    exit 1
  fi
done
docker buildx imagetools create --tag "$image:$tag" "$amd64" "$arm64"
digest=$(docker buildx imagetools inspect "$image:$tag" --format '{{json .Manifest}}' |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])')
if [[ ! $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Registry did not return a valid manifest digest" >&2
  exit 1
fi
docker buildx imagetools inspect "$image@$digest" --raw |
  python3 -c '
import json, sys
platforms = sorted((m["platform"]["os"], m["platform"]["architecture"])
                   for m in json.load(sys.stdin)["manifests"])
assert platforms == [("linux", "amd64"), ("linux", "arm64")], platforms
'
echo "AGENTIO_IMAGE=$image@$digest"
