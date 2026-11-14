# Agentio connection policy module

This dynamic library provides the gateway's CONNECT policy store, SNI listener filter and TCP network filter. Its module name is `envoy_agentio_connection_policy`; the filter entry points are `envoy_agentio_connection_policy_store`, `envoy_agentio_sni_policy` and `envoy_agentio_tcp_policy`. Porter supplies an ordered, per-SecurityProfile SNI/TCP view through `agentio:connection:policy` dynamic metadata. CONNECT registers the view in a worker-local store and shares only the hash as `agentio.connection.policy_hash` filter state. TLS termination relays the complete snapshot hash to the post-termination listener. Explicit SNI passthrough publishes an exclusive profile boundary in `agentio.tcp_policy.end_before`; it is local to that forwarding stage. The CONNECT HTTP filter and TCP network filter hold references to the same immutable snapshot; the final consumer removes it from the store. Identical JSON reuses an entry after a hash and content check. Parsing and validation happen once, on the first SNI/TCP consumer, so cleartext HTTP does not parse unused connection rules. The existing CONNECT identity capture also captures the temporary JSON; it needs no separate input filter. Temporary JSON filter state and policy metadata are cleared after registration. SNI evaluation uses the validated snapshot without revalidating its rules. Missing hashes or invalid policies fail closed; the module does not fall back to raw JSON or the flat SNI projection. Porter emits only the grouped connection policy; its flat SNI and precomputed TCP decision outputs have been removed.

For TLS, the listener filter evaluates each profile's SNI rules before its TCP rules against the restored original IP and port. SNI deny and TCP deny reject; TCP allow ends evaluation and forwards to the original address. SNI passthrough skips only that profile's TCP rules, resolves the SNI, rechecks the preceding profiles against the resolved candidates, and pins an authorized numerical address before TCP proxy can connect. After TLS termination, HTTP evaluation starts from the highest-priority profile and evaluates the complete HTTP/TCP chain. EPE starts with the complete chain. The TCP network filter receives a view of the selected profiles, backed by the same snapshot, and does not infer policy scope from TLS actions or destination mode. The gateway rejects malformed non-empty SNI before TLS routing. `*` matches every TLS connection, including missing SNI; exact names and suffix wildcards require a name. With no SNI, passthrough authorizes and pins the original destination without DNS. Unmatched TLS falls through to TCP rules for the original destination.

Raw TCP is authorized on connection initialization before initializing TCP proxy. Protocol inspection timeout closes the connection. The filter blocks incoming data until authorization completes. An empty ordered profile list permits traffic; missing or malformed connection policy closes the connection. Non-HTTP traffic after TLS termination also uses the network filter. EPE evaluates HTTP and TCP rules locally in profile order, including an explicit TCP allow before a lower-priority HTTP block.

SNI DNS uses a shared-per-filter-configuration Hickory resolver with TTL caching, IPv4-only hostname lookup and a five-second query deadline, preserving the gateway's current hostname address-family behavior. Literal original destinations support both IP families. Resolved addresses pass the gateway's mandatory address exclusions. The authorized address is pinned in `envoy.network.transport_socket.original_dst_address`. SNI forwarding also writes the numeric IP to `envoy.upstream.dynamic_host` before the DFP filter primes its cache, so DFP connects to the authorized address. Connection destruction cancels pending resolution.

ServiceEntry endpoint bindings retain their configured numeric destination and port and use ORIGINAL_DST clusters without DNS or a DFP filter. Post-termination endpoint TCP adds a TLS transport socket using the outer SNI for SNI/SAN validation. Other post-termination non-HTTP forwarding resolves the outer SNI and checks the complete TCP policy chain, including the terminating profile. TLS passthrough still leaves certificate verification to the client.

Native `tlsTermination.excludeHosts` only disables termination. It cannot override a SNI/TCP denial or invalid policy. A selected termination changed to passthrough uses the complete TCP chain; an explicit policy passthrough keeps only preceding profiles. Profile order and first-match semantics remain unchanged. The SNI listener receives these exclusions as `exclude_hosts`, so routing consumes one final decision rather than overriding it later. Static TLS routing with SNI policy disabled and legacy proxyv2 keep their existing routing behavior.

TCP module `filter_config` examples (the payload inside `google.protobuf.Struct`):

```yaml
# Raw TCP and fixed ServiceEntry endpoints; no DNS resolver is created.
mode: ORIGINAL_DST
denied_cidrs:
  - 100.100.100.200/32
```

```yaml
# Domain forwarding; resolve, authorize and pin the selected numerical address.
mode: DYNAMIC_FORWARD
denied_cidrs:
  - 100.100.100.200/32
```

`mode` is required and selects destination lookup only. `DYNAMIC_FORWARD` reads `envoy.upstream.dynamic_host` (or inspected SNI if absent), uses the original port, and falls back to the original address only for an empty target name. DNS failure denies the connection. `denied_cidrs` is an optional list of IP prefixes; it applies before profile authorization in both modes, including an empty profile view. The generator supplies mandatory gateway exclusions plus user entries. The user-facing Agentio configuration remains `egressAuthorization.deniedCIDRs`. The former `resolveSni`, `skipMatchedProfile` and `deniedCidrs` module fields are no longer accepted.

Deploy the gateway image containing the policy-store entry point before publishing hash-transfer configuration. The gateway configuration and module must be upgraded together; missing policy hashes fail closed.

The production `docker/Dockerfile.gateway` includes this module with community Envoy. The control plane emits the extension only to authenticated `agentio-egress~` clients. The legacy proxyv2 image does not support the listener dynamic-module configuration and continues to receive its existing custom matcher during rolling upgrades.

Build on Linux with Rust 1.93+, clang/libclang, curl and tar:

```sh
cd extensions/envoy/connection-policy
bash build.sh
```

The build downloads the required subtree from pinned Envoy SDK tag `v1.40.2`, checks formatting, runs unit tests and builds `target/release/libenvoy_agentio_connection_policy.so`. The SDK cache is ignored; remove `.envoy-sdk` when changing the SDK pin.

The standalone smoke fixture uses test headers, static certificates and local origins to isolate module behavior. It exercises real TLS termination and relay, ordered matching, wildcard boundaries, normalization, denial, absent/invalid policies, cleartext, alternating policies and conflicting actions. Production HBONE, Porter discovery and on-demand SDS require the integrated gateway test as well.

```sh
docker build -t agentio-envoy-connection-policy:dev .
python3 tests/smoke.py
```

The TCP smoke fixture checks profile priority, scoped SNI passthrough, SNI destination changes, authorization before any origin connection, missing SNI, and server-first TCP. Its header-based policy producer is test-only.

```sh
python3 tests/tcp_smoke.py --image agentio-envoy-connection-policy:dev
```

Go and Rust TCP matchers share `pkg/policy/testdata/tcp_rules.json`; run `go test ./pkg/policy` and the module unit tests to check the same CIDR/port corpus in both implementations.
