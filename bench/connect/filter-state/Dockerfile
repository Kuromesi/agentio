ARG ENVOY_IMAGE
FROM ${ENVOY_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-h2 openssl \
    && rm -rf /var/lib/apt/lists/*
COPY bench/connect/filter-state/*.py /tests/
COPY pkg/networking/testdata/agentio-egress-gateway.json /tests/gateway.json
USER 1337:1337
ENTRYPOINT ["python3", "/tests/verify.py", "/usr/local/bin/envoy", "--golden", "/tests/gateway.json"]
