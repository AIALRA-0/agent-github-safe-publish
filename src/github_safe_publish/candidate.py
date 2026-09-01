from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

from .inventory import git
from .model import CandidateManifest, SourceSnapshot
from .transformers import transform_candidate


def _stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _candidate_git_environment() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.longpaths",
        "GIT_CONFIG_VALUE_0": "true",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _configure_candidate_repository(destination: Path) -> None:
    subprocess.run(
        ["git", "config", "--local", "core.longpaths", "true"],
        cwd=destination,
        env=_candidate_git_environment(),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _git_archive(source: Path, commit: str, temporary_parent: Path) -> Path:
    temporary_parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".source-archive-", suffix=".tar", dir=temporary_parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            completed = subprocess.run(
                ["git", "archive", "--format=tar", commit],
                cwd=source,
                env=_candidate_git_environment(),
                stdout=output,
                stderr=subprocess.PIPE,
            )
        if completed.returncode != 0:
            raise RuntimeError("Git could not create the bounded source archive")
        return Path(name)
    except Exception:
        Path(name).unlink(missing_ok=True)
        raise


def _safe_extract(archive_path: Path, destination: Path, *, create: bool, excluded_links: set[str]) -> None:
    if create:
        destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive_path, mode="r:") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            try:
                target.relative_to(destination.resolve())
            except ValueError as exc:
                raise RuntimeError("Git archive contains an unsafe path") from exc
            if (member.issym() or member.islnk()) and member.name in excluded_links:
                continue
            if member.issym() or member.islnk() or member.isdev():
                raise RuntimeError("Git archive contains an unsupported link or device")
        members = [member for member in archive.getmembers() if member.name not in excluded_links]
        archive.extractall(destination, members=members, filter="data")


def _commit_candidate(destination: Path, message: str, commit_date: str) -> tuple[str, str]:
    if not commit_date:
        raise RuntimeError("Candidate commit requires a deterministic source date")
    environment = {
        **_candidate_git_environment(),
        "GIT_AUTHOR_NAME": "Example Publisher",
        "GIT_AUTHOR_EMAIL": "publisher@example.invalid",
        "GIT_AUTHOR_DATE": commit_date,
        "GIT_COMMITTER_NAME": "Example Publisher",
        "GIT_COMMITTER_EMAIL": "publisher@example.invalid",
        "GIT_COMMITTER_DATE": commit_date,
    }
    subprocess.run(["git", "add", "-A"], cwd=destination, env=environment, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(
        ["git", "-c", f"core.hooksPath={os.devnull}", "commit", "--no-verify", "--allow-empty", "-m", message],
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
    excluded_links = {
        action.object_path
        for action in actions
        if action.action in {"remove", "remove-and-stub", "exclude-component"}
    }
    if mode == "new-publication":
        archive_path = _git_archive(source, snapshot.commit, destination.parent)
        try:
            _safe_extract(archive_path, destination, create=True, excluded_links=excluded_links)
        finally:
            archive_path.unlink(missing_ok=True)
        subprocess.run(
            ["git", "-c", f"core.hooksPath={os.devnull}", "init", "-b", policy["remote_target"].get("branch", "main")],
            cwd=destination,
            env=_candidate_git_environment(),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _configure_candidate_repository(destination)
    elif mode == "update-existing-public":
        public_base = policy["publication"].get("public_base")
        if not public_base:
            raise ValueError("Existing-public mode requires a public base")
        subprocess.run(
            ["git", "-c", f"core.hooksPath={os.devnull}", "clone", "--no-hardlinks", public_base, str(destination)],
            env=_candidate_git_environment(),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _configure_candidate_repository(destination)
        expected_base = policy["remote_target"].get("expected_base")
        if expected_base and git(destination, "rev-parse", "HEAD").stdout.strip() != expected_base:
            raise ValueError("Public base differs from the authorized remote base")
        source_paths = set(git(source, "ls-tree", "-r", "--name-only", snapshot.commit).stdout.splitlines())
        retained = {
            item["object"]: item["sha256"]
            for item in policy.get("retention_rules", [])
            if item.get("action") == "retain-public"
        }
        for relative in git(destination, "ls-files").stdout.splitlines():
            path = destination / relative
            if relative not in source_paths and relative in retained:
                if not path.is_file() or _stream_sha256(path) != retained[relative]:
                    raise ValueError("Retained public object differs from its exact evidence")
                continue
            if relative not in source_paths:
                if path.is_file() or path.is_symlink():
                    path.unlink()
        archive_path = _git_archive(source, snapshot.commit, destination.parent)
        try:
            _safe_extract(archive_path, destination, create=False, excluded_links=excluded_links)
        finally:
            archive_path.unlink(missing_ok=True)
    else:
        raise ValueError("History migration requires separate authorization")
    transformations, removed = transform_candidate(destination, actions, policy)
    source_date = git(source, "show", "-s", "--format=%aI", snapshot.commit).stdout.strip()
    commit, tree = _commit_candidate(destination, "chore: publish sanitized public candidate", source_date)
    degradation = "minor" if removed else "none"
    return CandidateManifest(mode, snapshot.commit, commit, tree, str(destination), transformations, removed, degradation)


def rebuild_commit(manifest: CandidateManifest) -> CandidateManifest:
    destination = Path(manifest.candidate_path)
    environment = _candidate_git_environment()
    subprocess.run(["git", "add", "-A"], cwd=destination, env=environment, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    unchanged = subprocess.run(
        ["git", "diff", "--cached", "--quiet", "--no-ext-diff"],
        cwd=destination,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if unchanged.returncode == 0:
        return manifest
    if unchanged.returncode != 1:
        raise RuntimeError("Git could not compare the candidate index")
    source_date = git(destination, "show", "-s", "--format=%aI", "HEAD").stdout.strip()
    commit, tree = _commit_candidate(destination, "chore: continue sanitized public candidate", source_date)
    manifest.candidate_commit = commit
    manifest.candidate_tree = tree
    return manifest
