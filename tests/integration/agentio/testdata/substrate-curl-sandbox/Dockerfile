FROM golang:1.25-alpine AS build

WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/egress main.go

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        chrony \
        curl \
        fuse3 \
        git \
        iptables \
        iputils-ping \
        jq \
        less \
        nfs-common \
        nftables \
        openssh-server \
        socat \
        sudo \
        systemd \
        systemd-sysv \
        util-linux \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/egress /usr/local/bin/egress
COPY agentio-egress-poc.service /etc/systemd/system/agentio-egress-poc.service
RUN ln -s /etc/systemd/system/agentio-egress-poc.service \
        /etc/systemd/system/multi-user.target.wants/agentio-egress-poc.service
ENTRYPOINT ["/usr/local/bin/egress"]
