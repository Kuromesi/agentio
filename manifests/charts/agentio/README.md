# Agentio

This chart installs Agentio.

```bash
helm upgrade --install agentio . \
  -n agentio-system --create-namespace --atomic --wait
```

The default `profile: ambient` installs CNI and node ztunnel. Select the injected per-Pod ztunnel profile with `--set profile=sidecar`. Optional components use `egressGateway.mode` and `epe.mode` rather than overlapping boolean switches.

Agentiod logging is configured with `agentiod.logging.level` (`debug`, `info`, `warn`, or `error`) and `agentiod.logging.format` (`text` or `json`).

Agentiod closes long-lived gRPC connections after `agentiod.keepalive.maxServerConnectionAge` (default `30m`) so clients periodically reconnect and re-authenticate. Set it to `0s` to disable periodic connection expiry.

See [the repository installation guide](../README.md) for complete mode, namespace enrollment, EPE, Gateway API, and upgrade examples.
