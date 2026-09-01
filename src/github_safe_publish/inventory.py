from __future__ import annotations

import hashlib
import json
import os
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


def _batch_blob_digests(repository: Path, object_ids: list[str]) -> dict[str, tuple[str, int]]:
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=repository,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None
    results: dict[str, tuple[str, int]] = {}
    try:
        for object_id in dict.fromkeys(object_ids):
            process.stdin.write(object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii").strip().split()
            if len(header) != 3 or header[1] != "blob":
                raise RuntimeError("Git batch stream returned an unexpected object")
            size = int(header[2])
            remaining = size
            digest = hashlib.sha256()
            while remaining:
                chunk = process.stdout.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise RuntimeError("Git batch stream ended before the object was complete")
                digest.update(chunk)
                remaining -= len(chunk)
            if process.stdout.read(1) != b"\n":
                raise RuntimeError("Git batch stream object delimiter is invalid")
            results[object_id] = (digest.hexdigest(), size)
        process.stdin.close()
        if process.wait() != 0:
            raise RuntimeError("Git batch stream failed")
        return results
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def committed_blob_sha256s(repository: Path, commit: str) -> dict[str, str]:
    records = git(repository, "ls-tree", "-r", "-z", "-l", commit, text=False).stdout.split(b"\0")
    parsed_records: list[tuple[str, str]] = []
    for raw_record in records:
        if not raw_record:
            continue
        metadata, raw_name = raw_record.split(b"\t", 1)
        _, object_type, object_id, _ = metadata.decode("ascii").split()
        if object_type == "blob":
            parsed_records.append((object_id, raw_name.decode("utf-8", errors="surrogateescape")))
    blob_digests = _batch_blob_digests(repository, [object_id for object_id, _ in parsed_records])
    return {name: blob_digests[object_id][0] for object_id, name in parsed_records}


def source_snapshot(repository: Path) -> SourceSnapshot:
    repository = repository.resolve()
    commit = git(repository, "rev-parse", "HEAD").stdout.strip()
    tree = git(repository, "rev-parse", "HEAD^{tree}").stdout.strip()
    records = git(repository, "ls-tree", "-r", "-z", "-l", commit, text=False).stdout.split(b"\0")
    parsed_records = []
    for raw_record in records:
        if not raw_record:
            continue
        metadata, raw_name = raw_record.split(b"\t", 1)
        mode, object_type, object_id, raw_size = metadata.decode("ascii").split()
        parsed_records.append((mode, object_type, object_id, raw_size, raw_name))
    blob_digests = _batch_blob_digests(repository, [item[2] for item in parsed_records if item[1] == "blob"])
    inventory: list[dict[str, str | int]] = []
    working_metadata: list[dict[str, str | int]] = []
    for mode, object_type, object_id, raw_size, raw_name in parsed_records:
        name = raw_name.decode("utf-8", errors="surrogateescape")
        path = repository / name
        if object_type == "blob":
            content_sha256, size = blob_digests[object_id]
            if size != int(raw_size):
                raise RuntimeError("Git tree size differs from the streamed object")
        else:
            content_sha256 = hashlib.sha256(f"{object_type}:{object_id}".encode("ascii")).hexdigest()
            size = 0
        inventory.append({"path": name, "mode": mode, "object": object_id, "sha256": content_sha256, "size": size})
        if path.exists() or path.is_symlink():
            working_digest = hashlib.sha256()
            if path.is_symlink():
                working_digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
            elif path.is_file():
                with path.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        working_digest.update(chunk)
            else:
                continue
            working_metadata.append({
                "path": name,
                "mtime_ns": path.lstat().st_mtime_ns,
                "sha256": working_digest.hexdigest(),
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
