# Workload and gateway identities

Agentio certificates carry one effective SPIFFE identity in a URI SAN. The
control plane publishes the same identity in WDS `WorkloadIdentity.spiffe_id`.
This WDS extension is protobuf metadata, not an X.509 certificate extension.

## Certificate identity

Kubernetes workloads and egress gateways use the logical URI
`spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`. Pods sharing a
namespace and service account share this URI. A gateway's URI uses its own Pod
service account; gateway membership does not rewrite the certificate identity.

`Principal` is an opaque SPIFFE URI, not a Kubernetes identity structure. The
registry owns URI naming. ztunnel validates URI syntax and compares the complete
identity without a runtime profile whitelist. This implementation supports
Kubernetes attestation; VM and other source adapters are not implemented.

## Authentication and gateway membership

`Workload.Principal` is the effective certificate identity. `Workload.Source`
records the trusted source as `{Registry, Key}`; Kubernetes uses
`{Registry: "kubernetes/<cluster>", Key: "<pod-uid>"}`. Kubernetes namespace, SA
and Pod binding remain authentication evidence in `PeerIdentity.Kubernetes`.
WDS retains namespace and SA metadata for Kubernetes discovery and Pod matching.

Every CA target is authorized against a live registered Workload. A Pod-bound
token permits self issuance; a configured shared ztunnel can delegate eligible
workloads on its own node, but cannot delegate gateway instances.

The registry determines gateway membership from trusted Kubernetes resources:

- Static AgentioConfig gateways use the nonempty selector of the same-name
  Service in the gateway namespace.
- Gateways owned by the Agentio GatewayClass controller use the matching
  `gateway.networking.k8s.io/gateway-name` Pod label in that namespace.
- Conflicting membership prevents certificate issuance without removing the
  network discovery record. Terminating Pods retain their discovery identity
  with `Ready=false`, but cannot obtain new certificates or connection scopes.
  Terminal Pods leave discovery. Pod readiness and Gateway status addresses are
  not prerequisites for issuance.

Gateway declarations, Services, member Pods and their credentials must be managed
by trusted administrators. A label alone does not establish a trust boundary.
Gateway connections receive a scope at connection establishment. Subsequent SDS
requests use that scope and check Gateway validity without rechecking membership.

## Opt-in instance certificate issuance

The CA can sign a registered source instance alongside the existing URI SAN.
Two Pods using the same namespace and service account retain the same logical
SPIFFE URI, while their source extensions differ. For example:

```text
URI SAN: spiffe://cluster.local/ns/demo/sa/app
Workload source extension (non-critical):
  registry: kubernetes/production
  key: 5bfc62a3-7e78-4bfc-bc32-25b25b3bbdd7
```

Set `AGENTIO_WORKLOAD_SOURCE_EXTENSION_OID` to a project-owned private enterprise
OID allocated to this extension. There is no production default. The OID must
start with `1.3.6.1.4.1.` and must be configured consistently on CA replicas and
future consumers. An empty value keeps principal-only issuance available and
rejects explicit instance requests with `FailedPrecondition`.

Clients opt in through the existing Istio CA request's `metadata` field:

```json
{
  "ImpersonatedIdentity": "spiffe://cluster.local/ns/demo/sa/app",
  "WorkloadSource": {
    "registry": "kubernetes/production",
    "key": "5bfc62a3-7e78-4bfc-bc32-25b25b3bbdd7"
  }
}
```

`WorkloadSource` selects a target; it is not authentication evidence. The CA
authorizes the complete `(Principal, SourceRef)` pair against the trusted
registry before signing. Self issuance requires the caller's bound Pod; shared
ztunnel delegation retains the existing node-local workload restrictions. A
shared SA alone does not authorize requesting another Pod's source extension.
The CA never substitutes the shared proxy's own Pod UID for the target instance.

The custom X.509 extension's `extnValue` contains this ASN.1 DER payload:

```asn1
WorkloadSource ::= SEQUENCE {
  registry UTF8String,
  key      UTF8String
}
```

The extension is non-critical. Its contents are constructed from the authorized
source; extensions supplied in a CSR are not copied. No runtime, gateway role or
Sandbox policy binding is asserted by this payload. `key` retains the source
registry's native identifier and is not required to be a UUID.

When `WorkloadSource` is absent, the CA retains principal-only request behavior
and omits this extension. A present but malformed or unauthorized source fails without falling back to a
principal-only certificate. All requests must select the workload's effective
principal; the CA does not rewrite gateway identities.

This implementation adds CA issuance only. Requesters, certificate cache keys
and peer authorization do not yet use the instance extension. Enabling the OID
alone does not make existing clients request it. Before deploying instance-based
policy, requesters must select the target source, caches must distinguish
`(Principal, SourceRef)`, and consumers must validate the signed source and its
trusted policy binding. URI-only consumers still see a shared logical identity.

## Compatibility

Older CA clients may omit `ImpersonatedIdentity`; the CA derives the Kubernetes
SA URI from authenticated caller evidence and still authorizes it against the
registered Workload. Older WDS clients use namespace, service account and trust
domain fields; newer clients use the complete SPIFFE identity. Missing explicit
identity fields may use the old input encoding, but malformed identities and
certificate SAN mismatches fail without fallback.

Gateway authority comes from the trusted membership rules above. A Pod whose
service account merely matches a gateway name does not gain gateway scope.
Existing SA-only deployments must have a matching Service selector or a managed
Gateway API membership. Removing membership does not change the Pod's logical
SPIFFE URI or prohibit ordinary self issuance; it removes gateway scope for new
connections. Established connections retain their existing scope.

URI-only peers and SA-based policy rules retain their logical identity
granularity. Instance-specific authorization requires the source extension and
consumer changes described above; neither a new URI naming mode nor a global
URI migration switch is required.
