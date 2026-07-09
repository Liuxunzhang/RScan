# RSCAN

RSCAN is a Rust workspace intended to **standalone-reimplement the original `fscan` feature set and behavior** without depending on the original Go repository layout.

## Features

- Host liveness discovery and TCP port scanning
- Service plugins and weak-credential checks
- Web title detection, fingerprinting, and POC execution
- Local information collection and selected local modules
- Service fingerprinting with Go-compatibility regressions

## Build

```bash
cargo build --release
```

Binary output:

```bash
target/release/rscan
```

## Usage

```bash
# Host/port scanning
./target/release/rscan -h 192.168.1.10/24

# Enable service fingerprinting
./target/release/rscan -h 192.168.1.10 -p 22,80,445 -fingerprint

# Scan URL targets only
./target/release/rscan -u http://127.0.0.1:8080

# Run a named module
./target/release/rscan -h 192.168.1.10 -m ssh -user root -pwd 123456
```

Show full help:

```bash
./target/release/rscan -h
```

## Development and Quality Checks

Recommended pre-submit checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
cargo build --release --workspace
```

If `just` is installed, the same gate is available as:

```bash
just check-all
```

The repository includes a GitHub Actions CI workflow for formatting, Clippy, tests, and release builds.

## Workspace Layout

- `cli/`: CLI entrypoint
- `config/`: argument parsing and runtime config
- `core/`: orchestration layer
- `fingerprint/`: service fingerprinting
- `plugins/`: service/vulnerability modules
- `poc/`: Web POC engine
- `web/`: Web probing and fingerprinting
- `net/`: target expansion, liveness, and port scanning

## Standalone Assets

The workspace now vendors the compatibility resources it needs:

- `fingerprint/assets/nmap-service-probes.txt`
- `fingerprint/assets/Config.go`
- `web/assets/Rules.go`
- `poc/embedded-pocs/`
- `plugins/assets/MS17010-Exp.go`

That means this directory can be copied out or initialized as its own Git repository without requiring the outer `fscan/` tree.
