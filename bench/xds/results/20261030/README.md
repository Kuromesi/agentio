# Retained Linux benchmark evidence — 2026-10-30

These are the original, unmodified benchmark stdout files from the follow-up performance investigation, not a new measurement of the latest PR head.

- Base: upstream `3162d74c996845086f2421348af180a7520f5199`, with the same compatible benchmark fixtures added.
- After: that base plus the then-uncommitted optimized repair, subsequently committed in `4a7fc361279511cd7203311560e76de51110f666`. This predates the metadata integration and the unrelated-NACK recovery filter.
- Linux/amd64, Intel Xeon 6982P-C, Go 1.26.8; `GOMAXPROCS=4`, affinity CPUs 24,26,28,30. Existing kind workloads remained running.
- Six samples per revision, 500ms per sample. Three revisions (base, earlier repair, optimized repair) rotated execution order; only the base/optimized samples are copied here. Test binaries were compiled before measurement.
- Use `v2-*-xds.txt` for ordinary and delayed ACKs, `distinct-*-xds.txt` for delayed distinct-resource ACKs, `*-store.txt` for Store, and `base-xds.txt`/`after-xds.txt` for mixed-client pushes and scheduler. Earlier ACK samples in the last pair were superseded by v2.

| Scenario (median) | Base | After |
| --- | ---: | ---: |
| 64 full updates before ACK | 41.787531 ms/op | 42.673177 ms/op |
| 64 distinct-resource updates before ACK | 6.924694 ms/op | 6.966680 ms/op |
| 10,000 subscribers, publish and drain without backlog | 755.183 µs/op | 792.124 µs/op |
| 1,000 gateways / 1,000 subscribers with backlog | 43.626601 ms/op | 12.476362 ms/op |

The delayed ACK unit is an entire batch of 64 pushes and ACKs. StorePublish includes Store.Apply and draining each subscriber's channel. These are in-process costs, not gRPC/Envoy throughput or P99 latency.

Compare retained samples with benchstat, for example:

```sh
benchstat bench/xds/results/20261030/v2-base-xds.txt bench/xds/results/20261030/v2-after-xds.txt
benchstat bench/xds/results/20261030/distinct-base-xds.txt bench/xds/results/20261030/distinct-after-xds.txt
benchstat bench/xds/results/20261030/base-store.txt bench/xds/results/20261030/after-store.txt
```

Current fixtures can be exercised with:

```sh
GOMAXPROCS=4 go test ./pkg/xds -run '^$' \
  -bench '^BenchmarkGateway(DeltaACK|DelayedACK|DelayedDistinctACK)$' -benchmem -benchtime=500ms -count=6
GOMAXPROCS=4 go test ./pkg/xds/store -run '^$' \
  -bench '^BenchmarkStore(Publish|GatewayBacklog)$' -benchmem -benchtime=500ms -count=6
```

Replaying on the old base requires porting compatible benchmark fixtures; copying today's entire test suite onto it is not supported. The retained samples make the reported numbers inspectable; they do not establish identical performance on newer upstream code. Complete historical source staging and three-way execution scripts remain at `/root/agentio-xds-perf-investigation-20261030` on the original host.
