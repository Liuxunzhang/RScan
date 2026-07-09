# Contributing

Before opening a pull request, run the same checks used by CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
cargo build --release --workspace

If you have `just` installed, run the full gate with:

```bash
just check-all
```
```

Keep tests deterministic: prefer binding test services to `127.0.0.1:0` unless the behavior being tested explicitly depends on a protocol-specific port. Avoid developer-machine-specific paths or local network assumptions in default tests.
