#!/bin/bash

ISTIO_API=$(go env GOMODCACHE)/$(grep 'istio.io/api' go.mod | awk '{print $1 "@" $2}')
COMMON_PROTOS="${ISTIO_API}/common-protos"

protoc -I. -I"${ISTIO_API}" -I"${COMMON_PROTOS}" \
    --go_out=. --go_opt=paths=source_relative \
    pilot/pkg/serviceregistry/kube/controller/sandbox/extensions/extensions.proto

protoc -I. -I"${ISTIO_API}" -I"${COMMON_PROTOS}" \
  --go_out=. --go_opt=paths=source_relative \
  pilot/pkg/serviceregistry/kube/controller/sandbox/extensions/sandboxconfig.proto

protoc -I. -I"${ISTIO_API}" -I"${COMMON_PROTOS}" \
  --go_out=. \
  --go_opt=paths=source_relative \
  --golang-jsonshim_out=. \
  --golang-jsonshim_opt=paths=source_relative \
  pilot/pkg/serviceregistry/kube/controller/sandbox/extensions/extensions.proto

protoc -I. -I"${ISTIO_API}" -I"${COMMON_PROTOS}" \
  --go_out=. \
  --go_opt=paths=source_relative \
  --golang-jsonshim_out=. \
  --golang-jsonshim_opt=paths=source_relative \
  pilot/pkg/serviceregistry/kube/controller/sandbox/extensions/sandboxconfig.proto
