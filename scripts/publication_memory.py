"""Optional local, data-only publication lessons; never scans, executes or publishes."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


CATEGORIES = {
    "credentials", "personal_data", "infrastructure", "rights",
    "private_assets", "write_integrity", "unlisted",
}
FIELDS = {"id", "category", "paths", "cause", "repair", "regression_check", "status"}


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True,
        encoding="utf-8", errors="surrogateescape", timeout=30,
    )
    return result.stdout


def journal_path(repo: Path) -> Path:
    common = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip())
    return common / "github-safe-publish" / "risks.json"


def validate_lesson(value: object, *, stored: bool = False) -> dict:
    if not isinstance(value, dict) or not FIELDS.issubset(value):
        raise ValueError("A lesson must contain all documented fields")
    allowed = FIELDS | {"issue_url"} | ({"updated_at"} if stored else set())
    if set(value) - allowed:
        raise ValueError("Unknown lesson fields")
    for key in FIELDS - {"paths"}:
        if not isinstance(value[key], str) or not value[key].strip():
            raise ValueError("Lesson text fields must be nonempty strings")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", value["id"]):
        raise ValueError("Use a nonsecret lowercase lesson id")
    if value["category"] not in CATEGORIES or value["status"] not in {"open", "fixed"}:
        raise ValueError("Unknown category or status")
    paths = value["paths"]
    if not isinstance(paths, list) or not paths:
        raise ValueError("At least one relative path glob is required")
    for pattern in paths:
        if (not isinstance(pattern, str) or not pattern or pattern.startswith("/")
                or "\\" in pattern or ":" in pattern or ".." in pattern.split("/")):
            raise ValueError("Use only repository-relative POSIX path globs")
    if "issue_url" in value and not re.fullmatch(
        r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*",
        str(value["issue_url"]),
    ):
        raise ValueError("Issue URL must identify a GitHub Issue without private query data")
    if stored and (not isinstance(value.get("updated_at"), str) or not value["updated_at"]):
        raise ValueError("Stored lesson is missing its update time")
    return value.copy()


def unique_object(pairs: list[tuple]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON field")
        value[key] = item
    return value


def read_journal(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": 1, "history": "unavailable", "lessons": []}
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or set(value) != {"schema_version", "lessons"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not isinstance(value["lessons"], list)):
        raise ValueError("Invalid journal; preserve it and recover the prior record")
    lessons = [validate_lesson(item, stored=True) for item in value["lessons"]]
    if len({item["id"] for item in lessons}) != len(lessons):
        raise ValueError("Duplicate lesson id; preserve the journal")
    return {"schema_version": 1, "history": "available", "lessons": lessons}


def record(repo: Path, lesson: dict) -> dict:
    lesson = validate_lesson(lesson)
    path = journal_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_suffix(".lock")
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    temporary = None
    try:
        os.close(descriptor)
        current = read_journal(path)
        lesson["updated_at"] = datetime.now(timezone.utc).isoformat()
        lessons = {item["id"]: item for item in current["lessons"]}
        lesson = {**lessons.get(lesson["id"], {}), **lesson}
        lessons[lesson["id"]] = lesson
        payload = {"schema_version": 1, "lessons": sorted(lessons.values(), key=lambda x: x["id"])}
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(payload, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        return lesson
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        lock.unlink()


def outgoing_paths(repo: Path, base: str, head: str) -> list[str]:
    base_sha = git(repo, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}").strip()
    head_sha = git(repo, "rev-parse", "--verify", "--end-of-options", f"{head}^{{commit}}").strip()
    git(repo, "merge-base", "--is-ancestor", base_sha, head_sha)
    commits = git(repo, "rev-list", f"{base_sha}..{head_sha}").splitlines()
    paths = set()
    for commit in commits:
        paths.update(filter(None, git(
            repo, "diff-tree", "--root", "-m", "-r", "--no-commit-id",
            "--no-renames", "--name-only", "-z", commit,
        ).split("\0")))
    return sorted(paths)


def relevant(journal: dict, paths: list[str]) -> list[dict]:
    # Fixed lessons remain relevant: repair is not an exemption from recurrence checks.
    return [item for item in journal["lessons"] if any(
        pattern == "*" or any(fnmatchcase(path, pattern) for path in paths)
        for pattern in item["paths"]
    )]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("show", help="Read existing lessons; missing is not a clean history")
    commands.add_parser("record", help="Read one manually sanitized lesson JSON from stdin")
    select = commands.add_parser("relevant", help="Select recurrence checks, NOT certify content")
    select.add_argument("--base", required=True)
    select.add_argument("--head", default="HEAD")
    args = parser.parse_args(argv)
    try:
        if args.command == "record":
            result = record(args.repo, json.loads(sys.stdin.read(), object_pairs_hook=unique_object))
        else:
            result = read_journal(journal_path(args.repo))
            if args.command == "relevant":
                paths = outgoing_paths(args.repo, args.base, args.head)
                result = {**result, "paths": paths, "lessons": relevant(result, paths),
                          "scope": "path selection only; review metadata and payloads separately"}
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError):
        # Never echo unreviewed records, command stderr, or private host paths.
        print("Memory unavailable or invalid input; preserve existing records and review explicitly.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
