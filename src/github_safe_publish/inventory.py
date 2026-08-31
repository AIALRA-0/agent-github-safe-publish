from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

from .model import SourceSnapshot


def git(repository: Path, *arguments: str, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        encoding="utf-8" if text else None,
    )


def source_snapshot(repository: Path) -> SourceSnapshot:
    repository = repository.resolve()
    commit = git(repository, "rev-parse", "HEAD").stdout.strip()
    tree = git(repository, "rev-parse", "HEAD^{tree}").stdout.strip()
    names = git(repository, "ls-tree", "-r", "--name-only", "-z", commit, text=False).stdout.split(b"\0")
    inventory: list[dict[str, str | int]] = []
    working_metadata: list[dict[str, str | int]] = []
    for raw_name in names:
        if not raw_name:
            continue
        name = raw_name.decode("utf-8", errors="surrogateescape")
        path = repository / name
        data = git(repository, "show", f"{commit}:{name}", text=False).stdout
        inventory.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        if path.exists():
            working_metadata.append({
                "path": name,
                "mtime_ns": path.stat().st_mtime_ns,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            })
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
    metadata_encoded = json.dumps(working_metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return SourceSnapshot(
        repository=repository.name,
        commit=commit,
        tree=tree,
        inventory_sha256=hashlib.sha256(encoded).hexdigest(),
        working_metadata_sha256=hashlib.sha256(metadata_encoded).hexdigest(),
        file_count=len(inventory),
        source_path=str(repository),
    )


def snapshot_unchanged(before: SourceSnapshot, repository: Path) -> bool:
    after = source_snapshot(repository)
    return (
        before.commit == after.commit
        and before.tree == after.tree
        and before.inventory_sha256 == after.inventory_sha256
        and before.working_metadata_sha256 == after.working_metadata_sha256
        and before.file_count == after.file_count
    )
