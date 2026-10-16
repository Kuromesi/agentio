# The module is built on Linux by build.sh before assembling this example image.
# This is an upstream Envoy integration image, not Agentio's patched gateway image.
FROM envoyproxy/envoy:v1.39.4@sha256:74bd4eb5629708d3fadca1a5e6b85d208f338d7bb54e06b69565905c5294cc01
COPY target/release/libenvoy_agentio_sni_policy.so /usr/local/lib/
ENV ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib
