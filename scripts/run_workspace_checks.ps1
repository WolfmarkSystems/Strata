$ErrorActionPreference = 'Stop'

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python scripts/validate_forensic_contracts.py
powershell -ExecutionPolicy Bypass -File scripts/check_reliability.ps1

Write-Host 'Workspace checks completed successfully.'
