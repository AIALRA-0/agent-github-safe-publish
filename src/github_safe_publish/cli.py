from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

from . import __version__
from .compiler import publish_compiler, resume_compiler, run_compiler, sanitize_compiler, verify_compiler
from .detectors import inspect_tree_detailed
from .inventory import source_snapshot
from .planner import remediation_plan
from .policy import default_policy, load_policy
from .receipts import validate_source_audit_receipt
from .state import load_state
from .signing import private_key_fingerprint


def _stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="github-safe-publish",
        description=(
            "Optional advanced compiler and compatibility CLI for the GitHub safe-publish guidance Skill. "
            "Ordinary publication does not require this package."
        ),
    )
    parser.add_argument("--version", action="version", version=f"github-safe-publish {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "inspect", "plan", "sanitize", "verify", "resume"):
        command = commands.add_parser(name, help=f"Run the optional advanced {name} workflow")
        command.add_argument("--source", required=True)
        command.add_argument("--policy", required=True)
        command.add_argument("--private-output", required=True)
    publish = commands.add_parser(
        "publish",
        help="Publish an already-certified candidate commit to its configured Git remote",
        description=(
            "Publish only an already-certified candidate commit to the Git remote configured in its authorization. "
            "This command does not create a GitHub Tag, Release, release asset, Pull Request, or repository setting."
        ),
    )
    publish.add_argument("--private-output", required=True)
    publish.add_argument("--source")
    publish.add_argument("--policy")
    keygen = commands.add_parser("keygen", help="Inspect the fingerprint for an optional signing key")
    keygen.add_argument("--key", required=True)
    policy_init = commands.add_parser(
        "policy-init",
        help="Create a private policy for the optional advanced workflow",
        description=(
            "Create a private policy for the optional advanced workflow. "
            "The policy binds intent; this CLI does not create GitHub Release objects."
        ),
    )
    policy_init.add_argument("--source", required=True)
    policy_init.add_argument("--output", required=True)
    policy_init.add_argument("--key", required=True)
    policy_init.add_argument("--remote-target", required=True)
    policy_init.add_argument("--branch", default="main")
    policy_init.add_argument("--mode", choices=("new-publication", "update-existing-public"), default="new-publication")
    policy_init.add_argument("--public-base")
    policy_init.add_argument("--expected-remote-base")
    policy_init.add_argument("--maximum-degradation", choices=("none", "minor"), default="minor")
    policy_init.add_argument("--workflow-in-scope", action="store_true")
    policy_init.add_argument(
        "--release-in-scope",
        action="store_true",
        help="Keep the compatible policy-intent field; this CLI does not create a GitHub Release object",
    )
    policy_init.add_argument("--validation-command", action="append", default=[])
    policy_init.add_argument("--optional-path", action="append", default=[])
    policy_init.add_argument("--container-image")
    policy_init.add_argument("--container-backend", choices=("docker", "wsl-docker"), default="docker")
    policy_init.add_argument("--wsl-distribution")
    policy_init.add_argument("--source-audit-report")
    policy_init.add_argument("--gitleaks-path", required=True)
    policy_init.add_argument("--private-temp-root", required=True)
    policy_init.add_argument("--approved-by", default="information-owner")
    status = commands.add_parser("status", help="Read an optional workflow state")
    status.add_argument("--state", required=True)
    exposure = commands.add_parser("exposure", help="Use the legacy exposure-report compatibility commands")
    exposure.add_argument("scope", choices=("local", "fleet"))
    exposure.add_argument("arguments", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        state = load_state(Path(args.state))
        print(json.dumps({"workflow_id": state.workflow_id, "status": state.status, "iteration": state.iteration, "unresolved_count": state.unresolved_count}, sort_keys=True))
        return 0
    if args.command == "exposure":
        from . import legacy

        mapped = "audit-local" if args.scope == "local" else "audit-fleet"
        return legacy.main([mapped, *args.arguments])
    if args.command == "keygen":
        print(json.dumps({"public_key_fingerprint": private_key_fingerprint(Path(args.key).expanduser().resolve())}, sort_keys=True))
        return 0
    if args.command == "policy-init":
        source = Path(args.source).expanduser().resolve()
        output = Path(args.output).expanduser().resolve()
        try:
            output.relative_to(source)
        except ValueError:
            pass
        else:
            raise ValueError("Private policy cannot be stored inside the source repository")
        key = Path(args.key).expanduser().resolve()
        gitleaks_path = Path(args.gitleaks_path).expanduser().resolve()
        private_temp_root = Path(args.private_temp_root).expanduser().resolve()
        if output.exists():
            raise ValueError("Private policy output already exists")
        if args.validation_command and not args.container_image:
            raise ValueError("Functional validation commands require a digest-pinned container image")
        if args.mode == "update-existing-public" and (not args.public_base or not args.expected_remote_base):
            raise ValueError("Existing-public mode requires a public base and expected remote base")
        for private_path in (gitleaks_path, private_temp_root):
            try:
                private_path.relative_to(source)
            except ValueError:
                pass
            else:
                raise ValueError("Scanner and private temporary storage must remain outside the source repository")
        if not gitleaks_path.is_file():
            raise ValueError("Gitleaks executable is missing")
        snapshot = source_snapshot(source)
        policy = default_policy()
        fingerprint = private_key_fingerprint(key)
        policy["publication"].update({
            "mode": args.mode,
            "allowed_writes": ["commit"],
            "idempotency_key": hashlib.sha256(f"{snapshot.commit}\0{args.remote_target}".encode()).hexdigest(),
            "trusted_public_key_fingerprint": fingerprint,
            "workflow_in_scope": bool(args.workflow_in_scope),
            "release_in_scope": bool(args.release_in_scope),
            "authorization_expires_at": (datetime.now(timezone.utc) + timedelta(days=31)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        })
        if args.public_base:
            policy["publication"]["public_base"] = args.public_base
        policy["history_strategy"]["mode"] = "new-root" if args.mode == "new-publication" else "public-base-overlay"
        policy["functional_contract"]["commands"] = list(args.validation_command)
        policy["degradation_policy"]["maximum_automatic"] = args.maximum_degradation
        policy["degradation_policy"]["optional_paths"] = list(args.optional_path)
        policy["security_runtime"]["certification_key_path"] = str(key)
        policy["security_runtime"]["private_temp_root"] = str(private_temp_root)
        policy["security_runtime"]["credential_scanner"] = {
            "path": str(gitleaks_path),
            "sha256": _stream_sha256(gitleaks_path),
            "version": "8.30.1",
        }
        if args.container_image:
            policy["security_runtime"].update({
                "container_required": True,
                "backend": args.container_backend,
                "image": args.container_image,
            })
            if args.wsl_distribution:
                policy["security_runtime"]["wsl_distribution"] = args.wsl_distribution
        policy["remote_target"].update({
            "repository": args.remote_target,
            "branch": args.branch,
            "expected_base": args.expected_remote_base,
        })
        if args.source_audit_report:
            report_path = Path(args.source_audit_report).expanduser().resolve()
            if report_path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("Source audit report exceeds the bounded size limit")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report_digest = _stream_sha256(report_path)
            policy["validation"]["source_audit_receipt"] = {
                "report_path": str(report_path),
                "report_sha256": report_digest,
                "source_commit": snapshot.commit,
                "source_tree": snapshot.tree,
                "scanner_sha256": report.get("scanner_sha256"),
                "policy_fingerprint": report.get("policy_fingerprint"),
                "report_fingerprint": report.get("report_fingerprint"),
                "worktree_file_count": snapshot.file_count,
                "issued_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=31)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "approved_by": args.approved_by,
                "review_trigger": "content-policy-scanner-or-expiry-change",
            }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(policy, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(output, 0o600)
        print(json.dumps({"schema_version": 4, "source_commit": snapshot.commit, "source_tree": snapshot.tree, "public_key_fingerprint": fingerprint}, sort_keys=True))
        return 0
    if args.command == "publish":
        state = publish_compiler(Path(args.source or "."), Path(args.policy or "."), Path(args.private_output))
        print(json.dumps({"workflow_id": state.workflow_id, "status": state.status, "iteration": state.iteration, "unresolved_count": state.unresolved_count}, sort_keys=True))
        return 0 if state.status == "published" else 3
    source = Path(args.source)
    policy = load_policy(Path(args.policy), source)
    if args.command == "inspect":
        snapshot = source_snapshot(source)
        receipt = validate_source_audit_receipt(policy, source, snapshot)
        findings, observations, _ = inspect_tree_detailed(source, policy, inherited_source=source, source_receipt=receipt)
        print(json.dumps({"snapshot": asdict(snapshot), "finding_count": len(findings), "observation_count": len(observations)}, sort_keys=True))
        return 0
    if args.command == "plan":
        snapshot = source_snapshot(source)
        receipt = validate_source_audit_receipt(policy, source, snapshot)
        findings, _, _ = inspect_tree_detailed(source, policy, inherited_source=source, source_receipt=receipt)
        actions, needs_input = remediation_plan(findings, policy)
        print(json.dumps({"action_count": len(actions), "needs_input_count": len(needs_input)}, sort_keys=True))
        return 0 if not needs_input else 3
    if args.command not in {"run", "sanitize", "verify", "resume"}:
        return 2
    dispatch = {
        "run": lambda: run_compiler(source, Path(args.policy), Path(args.private_output), publish=True),
        "sanitize": lambda: sanitize_compiler(source, Path(args.policy), Path(args.private_output)),
        "verify": lambda: verify_compiler(source, Path(args.policy), Path(args.private_output)),
        "resume": lambda: resume_compiler(source, Path(args.policy), Path(args.private_output), publish=True),
    }
    state = dispatch[args.command]()
    print(json.dumps({"workflow_id": state.workflow_id, "status": state.status, "iteration": state.iteration, "unresolved_count": state.unresolved_count}, sort_keys=True))
    return 0 if state.status in {"certified", "published"} else 3


if __name__ == "__main__":
    raise SystemExit(main())
