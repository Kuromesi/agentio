# SecurityProfile gateway destination rules

TrafficPolicy keeps its sandbox/ztunnel execution point. SecurityProfile owns
HTTP/TLS processing and TCP destination fallthrough at the native egress gateway.
No separate TLS rule list is introduced: existing `rules[].actions.tls` remains.

```yaml
spec:
  rules:
  - name: allow-api
    match:
    - domains: [api.example.com]
      schemes: [https]
      ports: [443]
    actions:
      bypass: true
  tcpRules:
  - name: deny-other-destinations
    match:
    - cidrs: ["0.0.0.0/0", "::/0"]
    action: deny
```

Applicable profiles keep existing priority order; Sandbox inline rules follow
shared profiles. TCP rules use first match, OR between clauses/CIDRs/ports, and
AND between CIDR and port within a clause. No match, including an empty chain,
allows. `agents.kruise.io/tcp-rules` carries the same rule array on a Sandbox as a
trusted manager annotation, alongside the existing `security-rules` annotation.

| Path | Destination authorization | Forwarding target |
| --- | --- | --- |
| HTTP block | Reject immediately | None |
| HTTP bypass | Skip SP TCP rules; retain platform checks | Authorized, pinned Host/route target |
| HTTP mutation only / no match | SP TCP rules and platform checks | Authorized, pinned Host/route target |
| Explicit TLS deny | Reject immediately | None |
| Explicit TLS passthrough | Terminal domain permission; skip SP TCP rules | SNI DNS destination, encrypted bytes unchanged |
| TLS no match (`fallthrough`) | Original-destination TCP decision | Original CONNECT IP and port |
| Terminated TLS carrying HTTP | HTTP processing above | HTTP target |
| Terminated TLS carrying another protocol | Original-destination TCP decision | Original IP, with outer SNI/SAN for TLS origination |
| Raw TCP / inspection timeout | Original-destination TCP decision | Original CONNECT IP and port |

A TCP deny is a fallthrough rule, not an unconditional IP restriction: an explicit
HTTP bypass or TLS passthrough can override it. For a universal platform deny,
keep the independent platform enforcement. For “inject credentials for a domain,
otherwise deny private addresses”, use a nonterminal mutation rule plus private
CIDR denies; do not add bypass to that rule.

The control plane publishes one compiled `agentio.security.SecurityProfile` per
shared profile, containing HTTP JSON and typed `agentio.security.SNIPolicy` and
`agentio.security.TCPPolicy` fields. Workloads carry ordered references;
Sandboxes embed their own SecurityProfile in extensions. HTTP/TCP-only profile updates
change the profile resource without republishing Workloads. During compatibility
rollout, SNI changes also update the legacy embedded Workload/Sandbox SNI projection. Porter resolves all
references under the existing CONNECT deadline and uses the same captured profiles
for TCP decisions and SNI metadata.

Adjacent SNI entries with identical action and port sets merge their domain lists.
Entries separated by a different action remain ordered, including wildcard matches.
TCP rules retain their source order; shared profiles follow the existing priority
ordering and precede the Sandbox profile.
Porter uses an authenticated identity and one captured resource snapshot to return
`agentio.tcp.original_destination_decision = allow | deny`; it does not reject
CONNECT on a TCP deny. Envoy checks the decision when selecting the TCP chain,
before connecting upstream. After the final chain is selected, a network filter
keeps the decision local with `shared_with_upstream: NONE`, so it does not
partition external upstream pools. TLS termination preserves it until MainForward
selects its final chain. Missing/invalid decisions fail closed. Empty policies
are valid and default to allow. Only successfully compiled profiles are published;
a missing referenced profile remains an unavailable dependency.
EPE binds the TCP chain to the same profile snapshot as HTTP rules, checks final
addresses, and uses the existing upstream-address pinning path.

This changes native gateway deployment contracts: install the updated SecurityProfile
and GlobalSecurityProfile CRDs, and use matching Agentiod, Porter and Envoy
SNI-module/gateway versions. The old SNI type and embedded WDS/Sandbox projection remain available to older
Porter versions. This preserves SNI delivery, but does not make the new TCP
metadata contract usable by old Porter; use matching gateway/Porter versions
when enabling the new TCP enforcement path.
Existing TrafficPolicy restrictions remain
independent; SP bypass cannot override a connection already denied by ztunnel.

## Local API dependency

API source is in the companion `agents-sp-tcp-gateway-policy` worktree. The
`agents-api-sp-tcp-gateway-policy` worktree contains its synchronized types and
CRDs. Local `go.work` uses that API module without publishing a dependency.
Before merging, synchronize/release agents-api and update agentio's go.mod to the
published version; local go.work is for this review workspace only.

## Validation notes

The source API's `make generate manifests` and API package tests pass. The local
agents-api mirror's Go types and clientset compile. Its existing
`make gen-openapi-schema` target references a missing `cmd/gen-schema/main.go`
(and legacy kruise-api generator paths); that unrelated generator was not repaired.
The synchronized SecurityProfile CRDs come from the canonical agents generator.

## Compiled profile delivery

```text
Workload → ordered PolicyReference → shared SecurityProfile
                                    ├─ SNIPolicy
                                    └─ TCPPolicy
Sandbox → inline SecurityProfile
          ├─ SNIPolicy
          └─ TCPPolicy
```

The two policy messages update together within one SecurityProfile. Multiple shared
profiles are separate xDS resources; this does not promise a transactional update
across profiles. Missing references retain the existing discovery wait/rejection
behavior. Compilation and decode errors keep the existing handling; this change
adds no status protocol or admission webhook. HTTP configuration uses the existing field 4 (`policy_json`); SNI and TCP use
fields 5 and 6. EPE retains Kubernetes and xDS profile-source modes.
