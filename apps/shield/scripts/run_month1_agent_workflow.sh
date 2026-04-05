#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${1:-$(pwd)}"
SCRIPT_PATH="$WORKSPACE/scripts/run_month1_agent_workflow.py"

if [[ ! -f "$SCRIPT_PATH" ]]; then
  echo "[ERROR] Missing workflow runner: $SCRIPT_PATH" >&2
  exit 1
fi

python3 "$SCRIPT_PATH" \
  --workspace "$WORKSPACE" \
  --changed-file engine/src/virtualization/vhd.rs \
  --changed-file gui/src-tauri/src/lib.rs \
  --task "Month 1 planning and AI integration execution"
