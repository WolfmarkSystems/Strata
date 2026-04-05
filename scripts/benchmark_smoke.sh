#!/usr/bin/env bash
set -euo pipefail

if cargo bench --workspace --no-run; then
  echo "Benchmark smoke compile succeeded."
  exit 0
fi

echo "cargo bench --no-run failed; falling back to release test compile smoke."
cargo test --workspace --release --no-run

echo "Release compile smoke succeeded."
