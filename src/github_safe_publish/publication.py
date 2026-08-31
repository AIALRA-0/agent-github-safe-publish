from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess

from .inventory import git
from .model import PublicationAttestation, PublicationAuthorization, SafetyCertification
from .signing import verify_certification


def publish_local(
    candidate: Path,
    certification: SafetyCertification,
    authorization: PublicationAuthorization,
) -> PublicationAttestation:
    if not verify_certification(certification, authorization.trusted_public_key_fingerprint):
        raise ValueError("Certification signature is invalid or untrusted")
    if authorization.target_repository != certification.target_repository:
        raise ValueError("Authorization target differs from certification")
    if authorization.target_branch != certification.target_branch:
        raise ValueError("Authorization branch differs from certification")
    if "commit" not in authorization.allowed_writes:
        raise ValueError("Authorization does not permit a commit write")
    try:
        expires_at = datetime.fromisoformat(authorization.expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Authorization expiration is invalid") from exc
    if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
        raise ValueError("Publication authorization has expired")
    levels = {"none": 0, "minor": 1, "major": 2, "skeleton": 3}
    if levels.get(certification.degradation, 99) > levels.get(authorization.maximum_degradation, -1):
        raise ValueError("Candidate degradation exceeds publication authorization")
    current_commit = git(candidate, "rev-parse", "HEAD").stdout.strip()
    current_tree = git(candidate, "rev-parse", "HEAD^{tree}").stdout.strip()
    if current_commit != certification.candidate_commit or current_tree != certification.candidate_tree:
        raise ValueError("Candidate changed after certification")
    raw_target = authorization.target_repository
    is_network = raw_target.startswith(("https://", "ssh://", "git@")) or (
        "/" in raw_target and not Path(raw_target).is_absolute() and not raw_target.startswith(".")
    )
    target = f"https://github.com/{raw_target}.git" if is_network and "://" not in raw_target and not raw_target.startswith("git@") else raw_target
    if not is_network:
        local_target = Path(raw_target).resolve()
        if not local_target.exists():
            subprocess.run(["git", "init", "--bare", str(local_target)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        target = str(local_target)
    remote_ref = f"refs/heads/{authorization.target_branch}"
    environment = {**__import__("os").environ, "GIT_TERMINAL_PROMPT": "0"}
    existing = subprocess.run(
        ["git", "ls-remote", "--heads", str(target), remote_ref],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    if existing.returncode != 0:
        raise RuntimeError("Unable to read the authorized remote branch")
    existing_commit = existing.stdout.split()[0] if existing.stdout.strip() else None

    def remote_tree(commit: str) -> str:
        subprocess.run(
            ["git", "fetch", "--no-tags", str(target), commit],
            cwd=candidate,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        return git(candidate, "rev-parse", "FETCH_HEAD^{tree}").stdout.strip()

    if existing_commit == current_commit:
        observed_tree = remote_tree(existing_commit)
        if observed_tree != current_tree:
            raise RuntimeError("Idempotent remote commit has an unexpected tree")
        return PublicationAttestation("published", current_commit, current_tree, existing_commit, observed_tree, str(target), authorization.idempotency_key)
    if existing_commit != authorization.expected_remote_base:
        raise ValueError("Remote base differs from publication authorization")
    subprocess.run(
        ["git", "push", str(target), f"{current_commit}:{remote_ref}"],
        cwd=candidate,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    observed = subprocess.run(
        ["git", "ls-remote", "--heads", str(target), remote_ref],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    ).stdout.strip()
    remote_commit = observed.split()[0] if observed else ""
    observed_tree = remote_tree(remote_commit)
    if remote_commit != current_commit or observed_tree != current_tree:
        raise RuntimeError("Published remote differs from certification")
    return PublicationAttestation("published", current_commit, current_tree, remote_commit, observed_tree, str(target), authorization.idempotency_key)


def write_attestation(path: Path, attestation: PublicationAttestation) -> None:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": attestation.target, "digest": {"gitTree": attestation.remote_tree}}],
        "predicateType": "https://slsa.dev/verification_summary/v1",
        "predicate": {
            "verifier": {"id": "github-safe-publish"},
            "timeVerified": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "resourceUri": attestation.target,
            "verificationResult": attestation.status,
            "candidateCommit": attestation.candidate_commit,
            "remoteCommit": attestation.remote_commit,
            "idempotencyKey": attestation.idempotency_key,
        },
    }
    path.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
