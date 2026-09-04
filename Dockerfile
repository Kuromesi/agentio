# syntax=docker/dockerfile:1

# BASE_DISTRIBUTION switches between the debug and distroless runtime images.
ARG BASE_DISTRIBUTION=debug

# Agentio does not publish paired base images under a shared version, so each
# runtime image is pinned directly to an immutable multi-platform digest.
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:debug-nonroot@sha256:d5563cc7f2f44313f332e91138cc8c6a158899afeeeab2fce3b0f9ccdb3cf9ee
ARG DISTROLESS_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

FROM golang:1.25.13 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/agentiod ./cmd/agentiod

# The following section is used when BASE_DISTRIBUTION=debug.
FROM ${BASE_IMAGE} AS debug

# The following section is used when BASE_DISTRIBUTION=distroless.
FROM ${DISTROLESS_IMAGE} AS distroless

# Build the final image from the selected runtime stage.
# hadolint ignore=DL3006
FROM ${BASE_DISTRIBUTION:-debug}

COPY --from=builder /out/agentiod /usr/local/bin/agentiod
USER 1337:1337
ENTRYPOINT ["/usr/local/bin/agentiod"]
