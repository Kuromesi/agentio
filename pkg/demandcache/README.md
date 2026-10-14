# Demand retention cache

`Cache[V]` manages the lifetime of on-demand subscriptions. It has no xDS or protobuf dependency and stores only handles, keys and access metadata. The source owns resource values and updates; every lookup reads the source's current value.

The source supplies a `Lease[V]` with `Demand`, `Done` and `Release`. Acquisition and release must be local, nonblocking operations that do not call back into the cache. `Done` signals that the source has ended the subscription, allowing the next lookup to acquire a new generation. Waiters on the previous generation retain its result/error.

`Config.IdleTTL` and `Config.MaxEntries` apply across all types in a cache. One LRU uses `(type, name)` keys. Both settings default to zero (disabled); applications choose their own defaults. Negative settings are rejected. The entry target is not a byte or RSS limit.

A lookup pins its lease until completion. The last completed lookup moves it to the LRU front and starts its idle interval. Source updates alone do not refresh idle time. Concurrent lookups share a lease; canceling one does not release it while others are waiting. A failed last lookup releases the lease. Pending lookups may temporarily exceed the entry target; idle entries are evicted as lookups finish.

Run `Run(ctx)` once to expire entries without new traffic and release them on shutdown. Capacity eviction also runs synchronously during lookups. `Close` stops the cache and releases pending and idle leases; the source must wake pending demands when their lease is released. The cache does not close the source's connection.

For xdsclient, adapt `Client.Acquire` and pass the wrapper wherever a `Demand` source is accepted:

```go
cache, err := demandcache.New(func(typ, name string) (demandcache.Lease[*xdsclient.Resource], error) {
    return client.Acquire(typ, name)
}, demandcache.Config{IdleTTL: time.Minute, MaxEntries: 10000})
```

Run both the client and wrapper under the application's lifecycle, and handle the construction error. Eviction only relinquishes the wrapper's ownership; other explicit owners, persistent `Client.Demand` calls or wildcard watches may keep the source's values alive. Route managed accesses through the wrapper and use named watches when eviction needs to free values. Values already returned to callers are not invalidated by eviction.

This idle TTL is a consumer retention policy, separate from protocol TTL or server-side deletion. Porter uses this wrapper for named Workload/Sandbox lookups; EPE's wildcard watches do not use it.
