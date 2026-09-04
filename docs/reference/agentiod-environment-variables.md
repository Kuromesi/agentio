# Agentiod environment variables

Print the complete list, including binary defaults and descriptions, from the exact binary you plan to deploy:

```console
$ agentiod -print-env
```

From a source checkout, the equivalent command is:

```console
$ go run ./cmd/agentiod -print-env
```

The binary default applies when a variable is absent. The Helm chart sets many variables explicitly, so the effective value in a chart installation can differ from the binary default.

## Configure environment variables with Helm

Prefer a dedicated chart value when one exists. For example, `agentiod.logging.level` sets `AGENTIO_LOG_LEVEL`, and `agentiod.meshInternalTrafficPolicy` sets `AGENTIO_MESH_INTERNAL_TRAFFIC_POLICY`. Variables without a dedicated value can be passed through `agentiod.env`:

```yaml
agentiod:
  env:
    AGENTIO_PUSH_DEBOUNCE: 250ms
```

After an environment-variable change, Helm rolls the `agentiod` Deployment. These variables are read when the process starts; changing a Pod's environment does not update a running process.

## Configuration groups

The `-print-env` output is the authoritative reference. Registered settings are grouped by prefix and purpose:

- control-plane identity and config: `AGENTIO_SERVICE_NAME`, `AGENTIO_TOKEN_AUDIENCE`, `AGENTIO_TRUSTED_NODE_ACCOUNTS`, and `AGENTIO_*CONFIGMAP_NAME`;
- workload CA and trust distribution: `AGENTIO_CA_*`, `AGENTIO_TRUST_BUNDLE_*`, and `AGENTIO_WORKLOAD_CERT_*`;
- xDS and KRT flow control: `AGENTIO_KRT_*`, `AGENTIO_PUSH_*`, `AGENTIO_CLIENT_QUEUE_SIZE`, and `AGENTIO_MAX_REQUESTS_PER_SECOND`;
- injection and gateway deployment: `AGENTIO_ENABLE_SIDECAR_INJECTOR`, `AGENTIO_INJECTOR_*`, `AGENTIO_NATIVE_SIDECARS`, `AGENTIO_ENABLE_GATEWAY_DEPLOYER`, and `AGENTIO_GATEWAY_LEASE_NAME`;
- networking: `AGENTIO_GATEWAY_*`, `AGENTIO_ENABLE_SNI_TRAFFIC_POLICY`, and `AGENTIO_MESH_INTERNAL_TRAFFIC_POLICY`;
- logging and debug access: `AGENTIO_LOG_*` and `AGENTIO_ENABLE_DEBUG_ON_HTTP`.

## On-demand TLS certificates

On-demand domain certificates use the `AGENTIO_MITM_*` settings. The chart maps `agentiod.mitm.secretName`, `agentiod.mitm.secretNamespace`, and `agentiod.mitm.signMode` to the corresponding CA variables. Lifetime, renewal, cache, and concurrency settings can be supplied through `agentiod.env`.

`AGENTIO_MITM_SIGN_MODE` accepts:

- `SELF_SIGN`: Agentio owns and persists a self-signed CA in the configured Secret. This is the binary and chart default.
- `SECRET`: Agentio reads an externally managed CA Secret and does not rotate the root.

For an externally managed CA:

```yaml
agentiod:
  mitm:
    signMode: SECRET
    secretNamespace: agentio-system
    secretName: agentio-mitm-ca
```

The Secret must contain `ca.crt` and `ca.key`. Keep the Secret namespace and the configured egress-gateway identity scope consistent.

## Inspect the effective Pod environment

Inspect the rendered Deployment rather than relying only on chart defaults:

```console
$ kubectl get deployment agentiod \
    --namespace agentio-system \
    --output jsonpath='{range .spec.template.spec.containers[?(@.name=="discovery")].env[*]}{.name}{"="}{.value}{"\n"}{end}'
```

Values populated through `valueFrom`, such as `POD_NAME`, are shown without their runtime value by this command.

## Adjust the log level at runtime

When `AGENTIO_ENABLE_DEBUG_ON_HTTP` is enabled, the monitoring listener exposes an authenticated logging endpoint at `/debug/logging`. Like Istio's logging scopes, each registered Agentio component has an independent output level. List the available components and their current levels with GET:

```console
$ curl http://127.0.0.1:15014/debug/logging | jq '.[] | select(.name == "default" or .name == "krt")'
{"name":"default","output_level":"info"}
{"name":"krt","output_level":"info"}
```

The exact list depends on the components linked into and initialized by the binary. Read one component or change only that component by adding its name to the URL. Valid levels are `debug`, `info`, `warn`, `error`, and `none`:

```console
$ curl http://127.0.0.1:15014/debug/logging/krt
{"name":"krt","output_level":"info"}

$ curl --request PUT \
    --header 'Content-Type: application/json' \
    --data '{"output_level":"debug"}' \
    http://127.0.0.1:15014/debug/logging/krt
```

`PUT /debug/logging` remains available and changes the `default` scope. The default scope covers standard-library, Kubernetes dependency, and other unscoped logs; it does not overwrite levels already assigned to registered components. At startup, `AGENTIO_LOG_LEVEL` initializes the default and every registered component to the same value.

Loopback requests do not require credentials. Requests from any other address must pass the same TokenReview and root-namespace authorization as `/debug/configz`. A successful change returns HTTP 202 and affects existing loggers immediately. It is process-local and is not persisted: after an `agentiod` restart, `AGENTIO_LOG_LEVEL` supplies the level again.

## See also

- [Agentio configuration](agentio-configuration.md)
