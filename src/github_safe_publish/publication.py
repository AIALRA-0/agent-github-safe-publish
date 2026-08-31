from __future__ import annotations

import json
from pathlib import Path
import subprocess

from .inventory import git
from .model import PublicationAttestation, PublicationAuthorization, SafetyCertification


def publish_local(
    candidate: Path,
    certification: SafetyCertification,
    authorization: PublicationAuthorization,
) -> PublicationAttestation:
    if certification.signature is not None:
        raise ValueError("Alpha publisher does not accept an unverifiable signature")
    if authorization.target_repository != certification.target_repository:
        raise ValueError("Authorization target differs from certification")
    if authorization.target_branch != certification.target_branch:
        raise ValueError("Authorization branch differs from certification")
    current_commit = git(candidate, "rev-parse", "HEAD").stdout.strip()
    current_tree = git(candidate, "rev-parse", "HEAD^{tree}").stdout.strip()
    if current_commit != certification.candidate_commit or current_tree != certification.candidate_tree:
        raise ValueError("Candidate changed after certification")
    target = Path(authorization.target_repository).resolve()
    if not target.exists():
        subprocess.run(["git", "init", "--bare", str(target)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    remote_ref = f"refs/heads/{authorization.target_branch}"
    existing = subprocess.run(["git", "--git-dir", str(target), "rev-parse", "--verify", remote_ref], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    existing_commit = existing.stdout.strip() if existing.returncode == 0 else None
    if existing_commit != authorization.expected_remote_base:
        raise ValueError("Remote base differs from publication authorization")
    subprocess.run(["git", "push", str(target), f"{current_commit}:{remote_ref}"], cwd=candidate, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    remote_commit = subprocess.run(["git", "--git-dir", str(target), "rev-parse", remote_ref], check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
    remote_tree = subprocess.run(["git", "--git-dir", str(target), "rev-parse", f"{remote_commit}^{{tree}}"], check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
    if remote_commit != current_commit or remote_tree != current_tree:
        raise RuntimeError("Published remote differs from certification")
    return PublicationAttestation("published", current_commit, current_tree, remote_commit, remote_tree, str(target), authorization.idempotency_key)


def write_attestation(path: Path, attestation: PublicationAttestation) -> None:
    path.write_text(json.dumps(attestation.__dict__, indent=2) + "\n", encoding="utf-8")
