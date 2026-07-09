# Common development and release checks.
default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace --all-targets --no-fail-fast

build:
    cargo build --release --workspace

# Run criterion benchmarks (quick mode by default; pass `full=1` for the full run).
bench full='':
    cargo bench -p rscan-net {{ if full == "1" { "" } else { "-- --sample-size 100 --measurement-time 3" } }}

check-all: fmt-check clippy test build
