# RSCAN

RSCAN is a Rust workspace intended to **standalone-reimplement the original Go feature set and behavior** without depending on the original repository layout.

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
- `fingerprint/assets/port_map.rs`
- `web/assets/rules.rs`
- `poc/embedded-pocs/`

That means this directory can be copied out or initialized as its own Git repository without requiring the outer legacy repository tree.
