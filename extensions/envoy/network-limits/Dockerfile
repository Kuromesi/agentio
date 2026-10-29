# Build the module on Linux with build.sh first.
FROM envoyproxy/envoy:v1.39.4@sha256:74bd4eb5629708d3fadca1a5e6b85d208f338d7bb54e06b69565905c5294cc01 AS runtime
COPY target/release/libenvoy_agentio_network_limits.so /usr/local/lib/
