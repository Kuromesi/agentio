# Build bin/connect-load and bin/connect-bench in an external staging directory.
# docker build -f bench/connect/Dockerfile -t agentio-connect:bench "$CONNECT_BENCH_BUILD"
ARG BASE_IMAGE=agentio-network-limits:runtime
FROM ${BASE_IMAGE}
COPY bin/connect-load bin/connect-bench /usr/local/bin/
# The Go runner uses the host's CPU affinity and clock-tick utilities.
RUN command -v taskset && command -v getconf
ENTRYPOINT ["/usr/local/bin/connect-bench"]
CMD ["run", "-output=/results"]
