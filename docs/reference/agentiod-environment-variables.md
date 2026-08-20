# Agentiod environment variables

`agentiod` is based on Istio's `pilot-discovery` and supports its upstream environment variables. This page documents only the environment variables added or given Agentio-specific behavior by this repository. For the inherited variables, see the [Istio `pilot-discovery` reference](https://istio.io/latest/docs/reference/commands/pilot-discovery/).

The **binary default** applies when the environment variable is absent. The Agentio Helm chart sets some variables explicitly, so the effective default of a chart installation can differ from the binary default.

## Configure environment variables with Helm

Use a dedicated chart value when one is listed in the tables below. Variables without a dedicated value can be passed through `agentiod.env`:

```yaml
agentiod:
  env:
    ON_DEMAND_SIGN_MODE: "SELF_SIGN"
```

After an environment-variable change, Helm rolls the `agentiod` Deployment. These variables are read when the process starts; changing a Pod's environment does not update a running process.

## Traffic processing

| Variable | Type | Binary default | Description |
| --- | --- | --- | --- |
| `VALIDATE_TLS_TERMINATED_SNI` | Boolean | `true` | After TLS termination, validates that the TLS SNI and HTTP Host header are consistent. |
| `EXTERNAL_NAMES_CONTROLLER_DNS_SERVER` | String | Empty | Comma-separated DNS server addresses, including ports, used to resolve `egressPolicies.matchHosts`, for example `10.96.0.10:53`. When empty, Agentio discovers nameservers from `/etc/resolv.conf` and falls back to `127.0.0.1:53`. |

## On-demand TLS certificates

| Variable | Type | Binary default | Description |
| --- | --- | --- | --- |
| `ENABLE_ON_DEMAND_CERTS` | Boolean | `false` | Enables on-demand certificate signing. Requests are authorized by verified gateway identity: only proxies matching a configured `egressGateways` entry may pull certificates. |
| `ON_DEMAND_SIGN_MODE` | String | `SECRET` | `SECRET` reads a persistent CA from a Kubernetes Secret. `SELF_SIGN` creates an ephemeral CA at startup and is intended only for testing; it is unsuitable for multiple `agentiod` replicas. |
| `ON_DEMAND_SECRET_NAMESPACE` | String | Empty | Namespace of the CA Secret used in `SECRET` mode. If `RESTRICTED_SECRETS_SCOPE` is set, the Secret must be readable within that scope. Must be set when `ON_DEMAND_SIGN_MODE` is set to `SECRET`. |
| `ON_DEMAND_SECRET_NAME` | String | Empty | Name of the CA Secret. It must contain `ca.crt` and `ca.key`. Must be set when `ON_DEMAND_SIGN_MODE` is set to `SECRET`. |
| `ON_DEMAND_CERT_VALIDITY` | Duration | `24h` | Validity of generated certificates. Expired certificates are regenerated on the next request. |

For production TLS termination, use a shared CA and keep the Secret, `RESTRICTED_SECRETS_SCOPE`, and the `EgressGateway` namespace configuration consistent:

```yaml
agentiod:
  enableTlsTermination: true
  onDemandCertSignMode: SECRET
  env:
    ON_DEMAND_SECRET_NAMESPACE: agentio-system
    ON_DEMAND_SECRET_NAME: agentio-mitm-ca
```

## Inspect the effective Pod environment

Inspect the rendered Deployment rather than relying only on chart defaults:

```console
$ kubectl get deployment agentiod \
    --namespace agentio-system \
    --output jsonpath='{range .spec.template.spec.containers[?(@.name=="discovery")].env[*]}{.name}{"="}{.value}{"\n"}{end}'
```

Values populated through `valueFrom`, such as `POD_NAME`, are shown without their runtime value by this command.

## See also

- [Agentio configuration](agentio-configuration.md)
