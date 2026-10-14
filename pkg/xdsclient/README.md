# Delta ADS client

`Client` owns transport-stream ordering, ACK/NACK, subscriptions, aliases,
readiness and atomic cache publication. It does not interpret application
resources. Consumers register each wire type with `Watch`.

`New` requires a connection and a non-nil Node, but accepts an empty Node ID
and empty Watches. Agentiod identity requirements belong to its consumers:
EPE requires an explicit node ID or Pod identity to construct one; Porter
requires Pod identity and constructs its node ID from it.

## Resource transforms

`Watch.Transform` runs once per resource in a received update, after wire and
optional `Validate` checks. It returns the value to retain in the cache. Only
that result is retained: there is no second raw payload cache. With no transform,
the client retains a complete `*anypb.Any`.

A transform may decode a protobuf, extract a few fields into a consumer-owned
struct, or precompile a policy. Returning an error rejects the entire response,
sends a NACK and keeps the stream open. Previously accepted data and readiness
remain unchanged. No partial transforms or deletion decisions are published
from that rejected response. An initial rejection does not make a type ready.

`Demand` returns `*Resource`; `Resource.Value` has the type chosen by the watch.
Snapshots copy the maps but share resource values. All published values,
including nested maps, slices and protobuf messages, are **read-only**. Updates
replace resources; existing readers retain a consistent older value. Callers
that need to mutate a protobuf must clone it first.

Transforms and deletion callbacks run synchronously under the client lock.
They must not call back into the client, perform network I/O, or mutate previously
published values. Keep them limited to parsing and local decisions.

## Subscription lifetime

`Demand` adds an explicit named subscription and waits for a resource or a
not-found response. Concurrent calls for the same name share the subscription.
Cancelling one caller stops only its wait; the subscription remains active.
The client does not impose a subscription count limit.

By default, deletion clears the cached resource and reports `ErrNotFound` while
retaining subscription interest, so recreation can be delivered automatically.
A consumer can instead return `ReleaseSubscription` from `Watch.OnDelete`:

```go
OnDelete: func(name string) xdsclient.DeleteAction {
    return xdsclient.ReleaseSubscription
},
```

The callback runs for deleted explicit names and subscribed aliases that
vanish. The client ends existing waiters with `ErrNotFound`, removes their
subscription state and sends unsubscribe. A later `Demand` starts a new
subscription. If it arrives before the pending unsubscribe is sent, an explicit
resubscribe replaces that pending operation, as supported by Delta xDS. An old
waiter cannot consume a new subscription's result.

Releasing an explicit name never removes a wildcard subscription. This matters
for EPE, which still watches complete resource types: deleted explicit fetches
are released, but the wildcard continues to receive new resources. Porter uses
named watches only and demands resources again when new connections need them.

## Connection and synchronization

`Snapshot.Connected` reports whether the ADS stream is open. `Snapshot.Synced`
and `Observe` report whether each type has accepted a response on that stream.
This does not imply that every named subscription has returned a resource;
`Demand` waits for its own name independently. NACK leaves these states unchanged.

On disconnect, published values remain available through `Snapshot`, while
`Connected` and `Synced` reset. Consumers choose whether to use retained values.
`Demand` waits for fresh data; Porter and EPE require synchronized data for new
policy decisions. Cancellation of `Run` also retains the last publication.

Reconnection replays active names without `initial_resource_versions`. For each
type, the first accepted response replaces its retained resources and alias
index; subsequent responses accumulate into this fresh cache. Old resources
absent from the new stream cannot silently survive reconnection. An empty first
response also replaces the old cache. This is incremental synchronization, not
a barrier waiting for every named resource. Released names are not replayed.

The client's response receive limit is `math.MaxInt32`, matching Agentiod's
request receive limit. There is no subscription count limit or request chunking.
