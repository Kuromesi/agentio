# Build from the repository root: docker build -f bench/xds/Dockerfile -t xds-load:dev .
ARG GO_VERSION=1.26.8
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY api ./api
COPY bench/xds/fakeclient ./bench/xds/fakeclient
COPY bench/xds/load ./bench/xds/load
COPY bench/xds/loadapi ./bench/xds/loadapi
COPY bench/xds/scenario ./bench/xds/scenario
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -o /xds-load ./bench/xds/load

FROM scratch
COPY --from=build /xds-load /usr/local/bin/xds-load
USER 65532:65532
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/xds-load"]
