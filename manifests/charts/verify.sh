#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_dir"

helm lint "$repo_dir/manifests/charts/agentio"

go test ./manifests/charts
go test ./...
