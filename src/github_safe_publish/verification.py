from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .detectors import inspect_tree
from .inventory import git
from .model import SafetyCertification, VerificationResult
from .policy import policy_sha256


def verify_candidate(candidate: Path, policy: dict, validation_results: list[dict]) -> VerificationResult:
    findings, observations = inspect_tree(candidate, policy)
    tree = git(candidate, "rev-parse", "HEAD^{tree}").stdout.strip()
    validation_ok = all(item["exit_code"] == 0 for item in validation_results)
    return VerificationResult(not findings and validation_ok, findings, observations, True, tree, validation_results)


def certify(result: VerificationResult, policy: dict, commit: str, degradation: str) -> SafetyCertification:
    if not result.safe or result.unresolved_findings or not result.coverage_complete:
        raise ValueError("Candidate is not certifiable")
    maximum = policy["degradation_policy"].get("maximum_automatic", "minor")
    if degradation not in {"none", "minor"} or (maximum == "none" and degradation != "none"):
        raise ValueError("Candidate degradation exceeds authorization")
    verification = json.dumps({
        "safe": result.safe,
        "coverage_complete": result.coverage_complete,
        "candidate_tree": result.candidate_tree,
        "validation_results": result.validation_results,
    }, sort_keys=True, separators=(",", ":")).encode()
    remote = policy["remote_target"]
    return SafetyCertification(
        1,
        commit,
        result.candidate_tree,
        policy_sha256(policy),
        "2.0.0-alpha.1",
        hashlib.sha256(verification).hexdigest(),
        remote.get("repository", ""),
        remote.get("branch", "main"),
        remote.get("expected_base"),
        degradation,
    )
