#!/usr/bin/env bash
# Copyright 2026 The Kruise Authors
set -euo pipefail

base=$(cd "$(dirname "$0")" && pwd)
source "$base/versions.env"
image=${1:?usage: build.sh IMAGE TAG ARCH}
tag=${2:?missing tag}
arch=${3:?missing architecture}
case "$(uname -m)/$arch" in
  x86_64/amd64|aarch64/arm64) ;;
  *) echo "Build must run on a native $arch host" >&2; exit 1 ;;
esac
revision=$(git -C "$base" rev-parse HEAD)
data=${DATA_DIR:-/disk1/agentio-envoy}
mkdir -p "$data/runs/$revision" "$data/cache"
exec 9>"$data/build.lock"
flock -n 9
work="$data/runs/$revision"
envoy="$work/envoy"
output="$work/output"
mkdir -p "$output"
if [[ ! -d "$envoy/.git" ]]; then
  git init -q "$envoy"
fi
git -C "$envoy" fetch --depth=1 https://github.com/envoyproxy/envoy.git "$ENVOY_COMMIT"
# This is a generated checkout dedicated to this source revision.
git -C "$envoy" checkout --detach --force FETCH_HEAD
git -C "$envoy" apply --check "$base/patches/legacy-downstream-peer.patch"
git -C "$envoy" apply "$base/patches/legacy-downstream-peer.patch"

container="agentio-envoy-$arch-$tag"
docker create --name "$container" --init --network host \
  --mount "type=bind,src=$envoy,dst=/source" \
  --mount "type=bind,src=$data/cache,dst=/build" \
  --mount "type=bind,src=$base,dst=/agentio,readonly" \
  --mount "type=bind,src=$output,dst=/output" \
  -e BUILD_JOBS="${BUILD_JOBS:-24}" \
  --entrypoint /bin/bash "$ENVOY_BUILD_IMAGE" /agentio/container-build.sh
trap 'docker rm --force "$container" >/dev/null' EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
docker start --attach "$container"
if [[ $(docker inspect --format '{{.State.ExitCode}}' "$container") != 0 ]]; then
  echo "Envoy compilation or C++ tests failed" >&2
  exit 1
fi

native="$image:$tag-$arch"
docker buildx build --platform "linux/$arch" --provenance=false --load \
  --file "$base/Dockerfile" \
  --build-arg "ENVOY_RUNTIME_IMAGE=$ENVOY_RUNTIME_IMAGE" \
  --label "org.opencontainers.image.source=https://github.com/Kuromesi/agentio" \
  --label "org.opencontainers.image.revision=$revision" \
  --label "io.agentio.envoy.commit=$ENVOY_COMMIT" \
  --tag "$native" "$output"
if [[ $(docker image inspect --format '{{.Architecture}}' "$native") != "$arch" ]]; then
  echo "Candidate image does not have the expected $arch architecture" >&2
  exit 1
fi
docker run --rm --entrypoint /usr/local/bin/envoy "$native" --version
docker run --rm --user 1337:1337 --entrypoint /usr/local/bin/envoy \
  --mount "type=bind,src=$base/smoke.yaml,dst=/etc/agentio-smoke.yaml,readonly" \
  "$native" --mode validate -c /etc/agentio-smoke.yaml
docker push "$native"
digest=$(docker buildx imagetools inspect "$native" --format '{{json .Manifest}}' |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])')
if [[ ! $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Registry did not return a valid candidate digest" >&2
  exit 1
fi
echo "AGENTIO_IMAGE=$image@$digest"
