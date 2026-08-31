from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import __version__
from .detectors import inspect_tree_detailed, iter_candidate_files
from .credential_scanner import scan_gitleaks
from .inventory import git
from .model import SafetyCertification, VerificationResult
from .policy import policy_sha256
from .receipts import validate_source_audit_receipt


def verify_candidate(
    candidate: Path,
    policy: dict,
    validation_results: list[dict],
    *,
    source: Path | None = None,
    source_snapshot=None,
) -> VerificationResult:
    receipt = validate_source_audit_receipt(policy, source, source_snapshot)
    findings, observations, coverage = inspect_tree_detailed(
        candidate,
        policy,
        inherited_source=source,
        source_receipt=receipt,
    )
    credential_findings, credential_coverage = scan_gitleaks(candidate, policy)
    findings.extend(credential_findings)
    coverage.append(credential_coverage)
    commit = git(candidate, "rev-parse", "HEAD").stdout.strip()
    tree = git(candidate, "rev-parse", "HEAD^{tree}").stdout.strip()
    index_tree = git(candidate, "write-tree").stdout.strip()
    status = git(candidate, "status", "--porcelain", "-z").stdout
    patch = git(candidate, "diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD").stdout + git(
        candidate, "diff", "--cached", "--no-ext-diff", "--no-textconv", "--binary", "HEAD"
    ).stdout
    patch_sha256 = hashlib.sha256(patch.encode("utf-8", errors="surrogateescape")).hexdigest()
    clean = status == "" and index_tree == tree and patch == ""
    validation_ok = all(item["exit_code"] == 0 for item in validation_results)
    expected_objects = sum(1 for _ in iter_candidate_files(candidate))
    coverage_complete = (
        clean
        and len(coverage) == expected_objects + 1
        and all(item.get("status") == "checked" for item in coverage)
    )
    return VerificationResult(
        not findings and validation_ok and coverage_complete,
        findings,
        observations,
        coverage_complete,
        commit,
        tree,
        index_tree,
        patch_sha256,
        validation_results,
        coverage,
    )


def certify(
    result: VerificationResult,
    policy: dict,
    commit: str,
    degradation: str,
    authorization_sha256: str | None = None,
) -> SafetyCertification:
    if not result.safe or result.unresolved_findings or not result.coverage_complete:
        raise ValueError("Candidate is not certifiable")
    if commit != result.candidate_commit:
        raise ValueError("Candidate commit changed after verification")
    maximum = policy["degradation_policy"].get("maximum_automatic", "minor")
    if degradation not in {"none", "minor"} or (maximum == "none" and degradation != "none"):
        raise ValueError("Candidate degradation exceeds authorization")
    verification = json.dumps({
        "safe": result.safe,
        "coverage_complete": result.coverage_complete,
        "candidate_commit": result.candidate_commit,
        "candidate_tree": result.candidate_tree,
        "candidate_index_tree": result.candidate_index_tree,
        "candidate_patch_sha256": result.candidate_patch_sha256,
        "validation_results": result.validation_results,
        "coverage_records": result.coverage_records,
    }, sort_keys=True, separators=(",", ":")).encode()
    remote = policy["remote_target"]
    return SafetyCertification(
        1,
        commit,
        result.candidate_tree,
        policy_sha256(policy),
        __version__,
        hashlib.sha256(verification).hexdigest(),
        remote.get("repository", ""),
        remote.get("branch", "main"),
        remote.get("expected_base"),
        degradation,
        authorization_sha256,
    )
