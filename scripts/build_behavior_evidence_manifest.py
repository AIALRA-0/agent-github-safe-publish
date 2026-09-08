"""Build the narrow v2.0.2 evidence manifest after evaluations complete."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INPUTS = [
    "SKILL.md",
    "agents/openai.yaml",
    "evals/candidate/publication-behavior-v2.0.2.json",
    "scripts/grade_skill_behavior.py",
]


def _git_show(commit: str, relative: str) -> bytes:
    process = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        raise RuntimeError(f"missing evaluated input {relative} at {commit}")
    return process.stdout


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _repository_file(relative: str) -> Path:
    candidate = (ROOT / relative).resolve()
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError as error:
        raise SystemExit(f"evidence path is outside the repository: {relative}") from error
    return candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bind selected behavior inputs and sanitized evidence outputs")
    parser.add_argument("--evaluated-commit", required=True)
    parser.add_argument("--public-report", required=True)
    parser.add_argument("--public-events", required=True)
    parser.add_argument("--output-file", action="append", default=[], required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{40}", args.evaluated_commit):
        raise SystemExit("--evaluated-commit must be a full commit SHA")
    outputs: dict[str, str] = {}
    for relative in args.output_file:
        path = _repository_file(relative)
        if not path.is_file():
            raise SystemExit(f"missing evidence output: {relative}")
        outputs[relative] = _sha256(path.read_bytes())
    if args.public_report not in outputs:
        raise SystemExit("--public-report must also be listed as --output-file")
    if args.public_events not in outputs:
        raise SystemExit("--public-events must also be listed as --output-file")
    manifest = {
        "schema_version": "2.0.2",
        "evaluated_commit": args.evaluated_commit,
        "evaluated_inputs": {
            relative: _sha256(_git_show(args.evaluated_commit, relative)) for relative in INPUTS
        },
        "evidence_outputs": outputs,
        "public_report": args.public_report,
        "public_events": args.public_events,
        "scope": "selected behavior inputs and sanitized public outputs only",
        "raw_output_storage": "repository-external",
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "pass", "input_count": len(INPUTS), "output_count": len(outputs)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
