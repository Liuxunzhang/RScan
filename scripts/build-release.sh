#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

remap_flags=(
  "--remap-path-prefix=${HOME}=/home/build"
  "--remap-path-prefix=${HOME}/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f=/crates"
  "--remap-path-prefix=${ROOT_DIR}=/src"
)

if [[ -n "${RUSTFLAGS:-}" ]]; then
  export RUSTFLAGS="${RUSTFLAGS} ${remap_flags[*]}"
else
  export RUSTFLAGS="${remap_flags[*]}"
fi

cd "${ROOT_DIR}"
exec cargo build --release "$@"
