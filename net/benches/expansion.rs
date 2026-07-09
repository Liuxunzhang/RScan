//! Microbenchmarks for the CPU-bound scan-setup hot paths in `rscan-net`.
//!
//! Target/port expansion runs on every scan before any network I/O, so it is
//! the most latency-sensitive pure code in the pipeline. These benchmarks cover
//! the realistic shapes that expansion takes in practice: a single CIDR, a large
//! CIDR, an alias plus mixed specs, and port-spec parsing.
//!
//! Run with: `cargo bench -p rscan-net` (or `just bench`).

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use rscan_net::{expand_targets, parse_ports};

/// A /20 (4096 hosts) and a /16 (65536 hosts) cover medium and large scans.
const CIDR_SPECS: &[(&str, &str)] = &[("slash20", "10.0.0.0/20"), ("slash16", "172.16.0.0/16")];

fn bench_expand_targets_single(c: &mut Criterion) {
    let mut group = c.benchmark_group("expand_targets");
    for (label, spec) in CIDR_SPECS {
        let specs = vec![(*spec).to_string()];
        group.bench_with_input(BenchmarkId::from_parameter(label), &specs, |b, specs| {
            b.iter(|| expand_targets(black_box(specs)).unwrap())
        });
    }
    group.finish();
}

fn bench_expand_targets_mixed(c: &mut Criterion) {
    // Mirrors a typical CLI invocation: an alias ("192" -> 192.168.0.0/16),
    // a couple of /24s, and a single host.
    let mixed = vec![
        "192".to_string(),
        "10.0.0.0/24".to_string(),
        "172.16.5.0/24".to_string(),
        "203.0.113.42".to_string(),
    ];
    c.bench_function("expand_targets mixed", |b| {
        b.iter(|| expand_targets(black_box(&mixed)).unwrap())
    });
}

fn bench_parse_ports(c: &mut Criterion) {
    let spec = "1-1000,8080,9000-9100,22,80,443,3389,3306,6379,27017";
    c.bench_function("parse_ports complex", |b| {
        b.iter(|| parse_ports(black_box(spec)).unwrap())
    });

    let small = "80,443,22";
    c.bench_function("parse_ports small", |b| {
        b.iter(|| parse_ports(black_box(small)).unwrap())
    });
}

criterion_group!(
    benches,
    bench_expand_targets_single,
    bench_expand_targets_mixed,
    bench_parse_ports,
);
criterion_main!(benches);
