"""Generate eight private synthetic holdout scenarios in a fresh Codex context."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

from behavior_eval_contract import ACTION_IDS, PATH_IDS, STOP_POINT_IDS, WRITE_TYPES, validate_fixture


ROOT = Path(__file__).resolve().parents[1]


def _schema() -> dict:
    scenario = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "case_id",
            "request",
            "environment",
            "should_invoke",
            "path",
            "required_actions",
            "forbidden_actions",
            "allowed_writes",
            "stop_point",
            "rationale",
            "fixture_profile",
        ],
        "properties": {
            "case_id": {"type": "string"},
            "request": {"type": "string"},
            "environment": {"type": "array", "items": {"type": "string"}},
            "should_invoke": {"type": "boolean"},
            "path": {"type": "string", "enum": sorted(PATH_IDS)},
            "required_actions": {
                "type": "array",
                "items": {"type": "string", "enum": sorted(ACTION_IDS)},
            },
            "forbidden_actions": {
                "type": "array",
                "items": {"type": "string", "enum": sorted(ACTION_IDS)},
            },
            "allowed_writes": {
                "type": "array",
                "items": {"type": "string", "enum": sorted(WRITE_TYPES)},
            },
            "stop_point": {"type": "string", "enum": sorted(STOP_POINT_IDS)},
            "rationale": {"type": "string"},
            "fixture_profile": {
                "type": "string",
                "enum": [
                    "default",
                    "existing_tag",
                    "existing_release",
                    "existing_pull_request",
                    "protected_branch",
                    "authorization_revoked",
                    "release_update_failure",
                    "dirty_worktree",
                    "detached_head",
                    "shallow_clone",
                ],
            },
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "status", "purpose", "scenarios"],
        "properties": {
            "schema_version": {"type": "string", "const": "2.0.2"},
            "status": {"type": "string", "const": "candidate"},
            "purpose": {"type": "string"},
            "scenarios": {"type": "array", "items": scenario},
        },
    }


def _environment(raw_root: Path) -> dict[str, str]:
    blocked = ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "ACCESS_KEY", "PRIVATE_KEY")
    env = {
        key: value
        for key, value in os.environ.items()
        if key == "CODEX_HOME"
        or (not key.upper().startswith(("GH_", "GITHUB_", "OPENAI_")) and not any(item in key.upper() for item in blocked))
    }
    env.update(
        {
            "GH_CONFIG_DIR": str(raw_root / "empty-gh-config"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    Path(env["GH_CONFIG_DIR"]).mkdir(parents=True, exist_ok=True)
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate private candidate holdout cases without exposing answers")
    parser.add_argument("--public-cases", type=Path, required=True)
    parser.add_argument("--skill", type=Path, default=ROOT / "SKILL.md")
    parser.add_argument("--raw-output-dir", type=Path, required=True)
    parser.add_argument("--holdout-output", type=Path, required=True)
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--reasoning", default="high")
    parser.add_argument("--codex", default="codex")
    args = parser.parse_args(argv)
    public = json.loads(args.public_cases.read_text(encoding="utf-8"))
    public_ids = sorted(item["case_id"] for item in public["scenarios"])
    skill = args.skill.read_text(encoding="utf-8")
    args.raw_output_dir.mkdir(parents=True, exist_ok=False)
    schema_path = args.raw_output_dir / "holdout-output.schema.json"
    schema_path.write_text(json.dumps(_schema(), indent=2) + "\n", encoding="utf-8")
    last_message = args.raw_output_dir / "holdout-cases.private.json"
    prompt = f"""Create exactly eight private synthetic candidate scenarios that test the Skill below.

<skill>
{skill}
</skill>

Public scenario IDs already used:
{json.dumps(public_ids)}

Requirements:
- Use eight new case_id values beginning with holdout- and do not repeat public scenarios verbatim
- Cover interactions among independent write authority, state changes, trust boundaries, secret-review mode, retries, and exact stopping points
- Use only the closed enum values allowed by the output schema
- Select one fixture_profile per case: default, existing_tag, existing_release, existing_pull_request, protected_branch, authorization_revoked, release_update_failure, dirty_worktree, detached_head, or shallow_clone
- Use only synthetic public values; include no credentials, real identities, host paths, private repositories, or hidden reasoning
- Mark status as candidate; these are not user gold labels
- Return only the structured object
"""
    with tempfile.TemporaryDirectory(prefix="gsp-holdout-generation-") as temporary:
        work = Path(temporary)
        initialized = subprocess.run(
            ["git", "init", "-b", "main"],
            cwd=work,
            env=_environment(args.raw_output_dir),
            capture_output=True,
            text=True,
            check=False,
        )
        if initialized.returncode != 0:
            print(json.dumps({"status": "infrastructure_failure", "stage": "git_init"}))
            return 2
        process = subprocess.run(
            [
                args.codex,
                "--cd",
                str(work),
                "--disable",
                "plugins",
                "--disable",
                "remote_plugin",
                "--disable",
                "skill_search",
                "--disable",
                "plugin_sharing",
                "--enable",
                "skip_host_skill_discovery",
                "--config",
                "suppress_unstable_features_warning=true",
                "exec",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--json",
                "--color",
                "never",
                "--output-schema",
                str(schema_path),
                "--output-last-message",
                str(last_message),
                "--model",
                args.model,
                "--config",
                f'model_reasoning_effort="{args.reasoning}"',
                "--sandbox",
                "read-only",
                "-",
            ],
            cwd=work,
            env=_environment(args.raw_output_dir),
            input=prompt,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=360,
            check=False,
        )
    (args.raw_output_dir / "stdout.jsonl").write_text(process.stdout, encoding="utf-8")
    (args.raw_output_dir / "stderr.txt").write_text(process.stderr, encoding="utf-8")
    if process.returncode != 0 or not last_message.exists():
        print(json.dumps({"status": "infrastructure_failure", "exit_code": process.returncode}))
        return 2
    fixture = json.loads(last_message.read_text(encoding="utf-8"))
    errors = validate_fixture(fixture)
    holdout_ids = [item["case_id"] for item in fixture.get("scenarios", [])]
    overlap = sorted(set(holdout_ids) & set(public_ids))
    invalid_ids = sorted(item for item in holdout_ids if not item.startswith("holdout-"))
    if len(holdout_ids) != 8 or errors or overlap or invalid_ids:
        print(
            json.dumps(
                {
                    "status": "invalid_holdout",
                    "count": len(holdout_ids),
                    "error_count": len(errors),
                    "overlap": overlap,
                    "invalid_ids": invalid_ids,
                }
            )
        )
        return 1
    args.holdout_output.parent.mkdir(parents=True, exist_ok=True)
    args.holdout_output.write_bytes(last_message.read_bytes())
    digest = hashlib.sha256(args.holdout_output.read_bytes()).hexdigest()
    print(json.dumps({"status": "pass", "scenario_count": 8, "sha256": digest}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
