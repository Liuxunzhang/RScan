# Performance: benchmarks & profiling

This document describes how to measure and profile RScan's hot paths.

## Benchmarks

CPU-bound setup work (target/port expansion) runs on every scan before any
network I/O, so it is the most latency-sensitive pure code. Benchmarks live
under `net/benches/` and use [criterion](https://bors.rust-lang.org).

Run them with the bundled just recipe (quick mode by default):

```sh
just bench              # quick: sample-size 100, 3s measurement
just bench full=1       # full criterion run (longer, statistical)
```

or directly:

```sh
cargo bench -p rscan-net
```

### What is covered

| Benchmark | Input | What it measures |
| --- | --- | --- |
| `expand_targets/slash20` | `10.0.0.0/20` (4 096 hosts) | CIDR expansion + per-host string formatting |
| `expand_targets/slash16` | `172.16.0.0/16` (65 536 hosts) | Large single-CIDR expansion |
| `expand_targets mixed`   | alias `192` + two `/24`s + single host | Multi-spec expansion + cross-spec dedup |
| `parse_ports complex`    | `1-1000,8080,9000-9100,...` | Port-spec parsing |
| `parse_ports small`      | `80,443,22` | Minimal port-spec parsing |

criterion saves baselines under `target/criterion/`. Compare a change against
the previous baseline:

```sh
cargo bench -p rscan-net -- --save-baseline before
# ... make a change ...
cargo bench -p rscan-net -- --baseline before
```

### Finding acted on by these benchmarks

`expand_targets` previously rebuilt a `HashSet` of every accumulated target on
each append, making multi-spec expansion quadratic. The `expand_targets mixed`
benchmark surfaced a ~1.9× overhead versus a single `/16` of similar size.
Switching to a single order-preserving dedup at the end (`dedup_preserving_order`)
cut the mixed case from ~13.8 ms to ~7.2 ms and the `/16` case from ~7.5 ms to
~5.9 ms on the reference machine, with no change in output.

## Profiling

For network-bound code (the scan loops themselves), microbenchmarks are a poor
fit; profile a real run instead.

### Sample with a local target

Point the release binary at a controlled local workload and sample it:

```sh
cargo build --release --workspace

# CPU sample (macOS, Instruments/Xcode):
xcrun xctrace record --template 'Time Profiler' \
  --launch -- ./target/release/rscan -h 127.0.0.1 -p 1-1000 --no-write

# CPU sample (Linux, perf):
perf record -F 997 -g -- ./target/release/rscan -h 127.0.0.1 -p 1-1000 --no-write
perf report --no-children
```

### Flamegraph

With [`cargo-flamegraph`](https://github.com/flamegraph-rs/flamegraph):

```sh
cargo flamegraph --bin rscan -- -h 127.0.0.1 -p 1-1000 --no-write
```

> The release profile uses `panic = "abort"`. `cargo bench` overrides this via
> `[profile.bench]` so criterion's panic-catching loop works, but flamegraph /
> perf samples against the release binary directly, which is fine for
> wall-clock profiling.
