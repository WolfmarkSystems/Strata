#!/usr/bin/env python3
"""Sequential multi-agent workflow runner for Month 1 planning tasks.

The config file is stored as JSON-compatible YAML so this script can remain
dependency-free and portable across Windows and Linux.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_config(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"[ERROR] Config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[ERROR] Config must be JSON-compatible YAML: {exc}") from exc


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def make_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_agent_output(
    agent: dict[str, Any],
    task: dict[str, Any],
    previous_outputs: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "agent_id": agent["id"],
        "role": agent["role"],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "received": {
            "task_brief": task["task_brief"],
            "changed_files": task["changed_files"],
            "acceptance_criteria": task["acceptance_criteria"],
            "previous_agents": [item["agent_id"] for item in previous_outputs],
        },
        "produced": {
            "summary": f"{agent['role']} completed sequential review for {task['task_brief']}",
            "required_outputs": agent["outputs"],
            "next_handoff": agent["handoff_to"],
        },
        "guards": task["guards"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Month 1 Strata Shield agent workflow")
    parser.add_argument(
        "--config",
        default="docs/ai/month1_agent_orchestration.yaml",
        help="Path to JSON-compatible YAML config",
    )
    parser.add_argument(
        "--workspace",
        default="d:/forensic-suite" if os.name == "nt" else str(Path.home() / "forensic-suite"),
        help="Workspace root for the run",
    )
    parser.add_argument(
        "--changed-file",
        action="append",
        default=[],
        help="Changed file path to include in the task payload",
    )
    parser.add_argument(
        "--task",
        default="Month 1 planning and AI integration execution",
        help="Task brief for the run",
    )
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    config_path = (workspace / args.config).resolve()
    config = load_config(config_path)

    run_id = make_run_id()
    run_root = workspace / config["workflow_root"] / run_id
    ensure_dir(run_root)

    task_payload = {
        "run_id": run_id,
        "task_brief": args.task,
        "changed_files": args.changed_file,
        "acceptance_criteria": [
            "preserve evidence integrity",
            "emit deterministic outputs",
            "include tests or an explicit test gap",
        ],
        "guards": config["guards"],
    }
    write_json(run_root / "task.json", task_payload)

    agent_outputs: list[dict[str, Any]] = []
    for agent in config["agents"]:
        output = build_agent_output(agent, task_payload, agent_outputs)
        write_json(run_root / f"{agent['id']}_output.json", output)
        agent_outputs.append(output)
        print(f"[OK] {agent['role']} completed -> {run_root / f'{agent['id']}_output.json'}")

    final_summary = {
        "run_id": run_id,
        "status": "completed",
        "agents": [agent["id"] for agent in config["agents"]],
        "workspace": str(workspace),
        "artifacts": [f"{agent['id']}_output.json" for agent in config["agents"]],
    }
    write_json(run_root / "final_summary.json", final_summary)
    print(f"[OK] Final summary written -> {run_root / 'final_summary.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

