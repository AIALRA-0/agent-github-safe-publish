from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from . import __version__
from .compiler import run_compiler
from .detectors import inspect_tree
from .inventory import source_snapshot
from .planner import remediation_plan
from .policy import load_policy
from .state import load_state


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="github-safe-publish")
    parser.add_argument("--version", action="version", version=f"github-safe-publish {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "inspect", "plan", "sanitize", "verify", "publish", "resume"):
        command = commands.add_parser(name)
        command.add_argument("--source", required=True)
        command.add_argument("--policy", required=True)
        command.add_argument("--private-output", required=True)
    status = commands.add_parser("status")
    status.add_argument("--state", required=True)
    exposure = commands.add_parser("exposure")
    exposure.add_argument("scope", choices=("local", "fleet"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        state = load_state(Path(args.state))
        print(json.dumps({"workflow_id": state.workflow_id, "status": state.status, "iteration": state.iteration, "unresolved_count": state.unresolved_count}, sort_keys=True))
        return 0
    if args.command == "exposure":
        print(json.dumps({"scope": args.scope, "status": "legacy-command-required"}, sort_keys=True))
        return 0
    source = Path(args.source)
    policy = load_policy(Path(args.policy))
    if args.command == "inspect":
        snapshot = source_snapshot(source)
        findings, observations = inspect_tree(source, policy)
        print(json.dumps({"snapshot": asdict(snapshot), "finding_count": len(findings), "observation_count": len(observations)}, sort_keys=True))
        return 0
    if args.command == "plan":
        findings, _ = inspect_tree(source, policy)
        actions, needs_input = remediation_plan(findings, policy)
        print(json.dumps({"action_count": len(actions), "needs_input_count": len(needs_input)}, sort_keys=True))
        return 0 if not needs_input else 3
    if args.command not in {"run", "sanitize", "verify", "publish", "resume"}:
        return 2
    state = run_compiler(source, Path(args.policy), Path(args.private_output), publish=args.command in {"run", "publish", "resume"})
    print(json.dumps({"workflow_id": state.workflow_id, "status": state.status, "iteration": state.iteration, "unresolved_count": state.unresolved_count}, sort_keys=True))
    return 0 if state.status in {"certified", "published"} else 3


if __name__ == "__main__":
    raise SystemExit(main())
