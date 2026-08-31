from __future__ import annotations

import io
from pathlib import Path
import shutil
import subprocess
import tarfile

from .inventory import git
from .model import CandidateManifest, SourceSnapshot
from .transformers import transform_candidate


def _safe_extract(data: bytes, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            try:
                target.relative_to(destination.resolve())
            except ValueError as exc:
                raise RuntimeError("Git archive contains an unsafe path") from exc
        archive.extractall(destination, filter="data")


def _commit_candidate(destination: Path, message: str) -> tuple[str, str]:
    git(destination, "add", "-A")
    environment = {
        **dict(__import__("os").environ),
        "GIT_AUTHOR_NAME": "Example Publisher",
        "GIT_AUTHOR_EMAIL": "publisher@example.invalid",
        "GIT_COMMITTER_NAME": "Example Publisher",
        "GIT_COMMITTER_EMAIL": "publisher@example.invalid",
    }
    subprocess.run(
        ["git", "commit", "--allow-empty", "-m", message],
        cwd=destination,
        env=environment,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return git(destination, "rev-parse", "HEAD").stdout.strip(), git(destination, "rev-parse", "HEAD^{tree}").stdout.strip()


def build_candidate(
    source: Path,
    destination: Path,
    snapshot: SourceSnapshot,
    actions,
    policy: dict,
) -> CandidateManifest:
    if destination.exists():
        raise ValueError("Candidate destination already exists")
    mode = policy["publication"]["mode"]
    if mode == "new-publication":
        archived = git(source, "archive", "--format=tar", snapshot.commit, text=False).stdout
        _safe_extract(archived, destination)
        git(destination, "init", "-b", policy["remote_target"].get("branch", "main"))
    elif mode == "update-existing-public":
        public_base = policy["publication"].get("public_base")
        if not public_base:
            raise ValueError("Existing-public mode requires a public base")
        subprocess.run(["git", "clone", "--no-hardlinks", public_base, str(destination)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        archived = git(source, "archive", "--format=tar", snapshot.commit, text=False).stdout
        with tarfile.open(fileobj=io.BytesIO(archived), mode="r:") as archive:
            for member in archive.getmembers():
                target = (destination / member.name).resolve()
                target.relative_to(destination.resolve())
            archive.extractall(destination, filter="data")
    else:
        raise ValueError("History migration requires separate authorization")
    transformations, removed = transform_candidate(destination, actions, policy)
    commit, tree = _commit_candidate(destination, "chore: publish sanitized public candidate")
    degradation = "minor" if removed else "none"
    return CandidateManifest(mode, snapshot.commit, commit, tree, str(destination), transformations, removed, degradation)


def rebuild_commit(manifest: CandidateManifest) -> CandidateManifest:
    destination = Path(manifest.candidate_path)
    git(destination, "add", "-A")
    if git(destination, "diff", "--cached", "--quiet").returncode == 0:
        return manifest
    commit, tree = _commit_candidate(destination, "chore: continue sanitized public candidate")
    manifest.candidate_commit = commit
    manifest.candidate_tree = tree
    return manifest
