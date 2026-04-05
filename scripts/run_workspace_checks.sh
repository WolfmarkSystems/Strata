#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/check_reliability.sh
python3 scripts/validate_forensic_contracts.py

echo "Workspace checks completed successfully."
