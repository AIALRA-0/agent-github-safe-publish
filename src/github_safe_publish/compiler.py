from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import shutil
import uuid

from .candidate import build_candidate
from .detectors import inspect_tree
from .inventory import snapshot_unchanged, source_snapshot
from .model import PublicationAuthorization, WorkflowState
from .planner import remediation_plan
from .policy import load_policy
from .publication import publish_local, write_attestation
from .state import save_state
from .validation import validate_candidate
from .verification import certify, verify_candidate


def run_compiler(source: Path, policy_path: Path, private_output: Path, *, publish: bool = True) -> WorkflowState:
    source = source.resolve()
    private_output = private_output.resolve()
    policy = load_policy(policy_path)
    workflow = WorkflowState(str(uuid.uuid4()), "received")
    state_path = private_output / "workflow-state.private.json"
    private_output.mkdir(parents=True, exist_ok=False)
    workflow.status = "snapshotting"
    save_state(state_path, workflow)
    snapshot = source_snapshot(source)
    workflow.source_snapshot = snapshot
    workflow.status = "assessing"
    save_state(state_path, workflow)

    findings, _ = inspect_tree(source, policy)
    workflow.finding_count = len(findings)
    workflow.unresolved_count = len(findings)
    workflow.status = "planning"
    save_state(state_path, workflow)
    actions, needs_input = remediation_plan(findings, policy)
    if needs_input:
        workflow.status = "needs_input"
        workflow.pause_reason = "At least one finding requires an information-owner decision"
        save_state(state_path, workflow)
        return workflow

    workflow.status = "sanitizing"
    save_state(state_path, workflow)
    candidate_path = private_output / "candidate"
    manifest = build_candidate(source, candidate_path, snapshot, actions, policy)
    workflow.candidate_manifest = manifest
    workflow.iteration = 1
    workflow.status = "validating"
    save_state(state_path, workflow)
    validation_results = validate_candidate(candidate_path, policy)
    workflow.status = "verifying"
    save_state(state_path, workflow)
    verification = verify_candidate(candidate_path, policy, validation_results)
    if not verification.safe:
        workflow.unresolved_count = len(verification.unresolved_findings)
        workflow.status = "internal_error"
        workflow.pause_reason = (
            f"The first remediation pass did not converge: "
            f"{len(verification.unresolved_findings)} unresolved findings and "
            f"{sum(item['exit_code'] != 0 for item in validation_results)} failed validation commands; "
            f"rules={sorted({item.rule_id for item in verification.unresolved_findings})}"
        )
        save_state(state_path, workflow)
        return workflow
    certification = certify(verification, policy, manifest.candidate_commit, manifest.degradation)
    workflow.certification = certification
    workflow.unresolved_count = 0
    workflow.status = "certified"
    (private_output / "certification.private.json").write_text(json.dumps(asdict(certification), indent=2) + "\n", encoding="utf-8")
    if not snapshot_unchanged(snapshot, source):
        workflow.status = "internal_error"
        workflow.pause_reason = "Source changed during compilation"
        save_state(state_path, workflow)
        return workflow
    if not publish:
        save_state(state_path, workflow)
        return workflow
    remote = policy["remote_target"]
    authorization = PublicationAuthorization(
        remote["repository"],
        remote.get("branch", "main"),
        remote.get("expected_base"),
        tuple(policy["publication"].get("allowed_writes", ["commit"])),
        policy["degradation_policy"].get("maximum_automatic", "minor"),
        bool(policy["publication"].get("workflow_in_scope", False)),
        bool(policy["publication"].get("release_in_scope", False)),
        policy["publication"].get("authorization_expires_at", "2099-01-01T00:00:00Z"),
        policy["publication"].get("idempotency_key", hashlib.sha256(manifest.candidate_tree.encode()).hexdigest()),
    )
    workflow.status = "publishing"
    save_state(state_path, workflow)
    attestation = publish_local(candidate_path, certification, authorization)
    workflow.attestation = attestation
    workflow.status = "published"
    write_attestation(private_output / "publication-attestation.private.json", attestation)
    save_state(state_path, workflow)
    return workflow
