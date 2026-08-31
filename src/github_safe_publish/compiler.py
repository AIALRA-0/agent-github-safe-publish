from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import uuid

from .candidate import build_candidate, rebuild_commit
from .detectors import inspect_tree
from .inventory import snapshot_unchanged, source_snapshot
from .model import PublicationAuthorization, WorkflowState
from .planner import remediation_plan
from .policy import load_policy, policy_sha256
from .publication import publish_local, write_attestation
from .sandbox import SandboxUnavailable
from .signing import sign_certification
from .state import save_state
from .transformers import transform_candidate
from .validation import validate_candidate
from .verification import certify, verify_candidate


def _state_path(private_output: Path) -> Path:
    return private_output / "workflow-state.private.json"


def _load_bound_state(source: Path, policy: dict, private_output: Path) -> WorkflowState:
    from .state import load_state

    workflow = load_state(_state_path(private_output))
    if workflow.policy_sha256 != policy_sha256(policy):
        raise ValueError("Policy differs from the checkpoint binding")
    if not workflow.source_snapshot or not snapshot_unchanged(workflow.source_snapshot, source):
        raise ValueError("Source differs from the checkpoint binding")
    return workflow


def sanitize_compiler(source: Path, policy_path: Path, private_output: Path) -> WorkflowState:
    source = source.resolve()
    private_output = private_output.resolve()
    policy = load_policy(policy_path)
    workflow = WorkflowState(str(uuid.uuid4()), "received")
    workflow.policy_sha256 = policy_sha256(policy)
    state_path = _state_path(private_output)
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
    return workflow


def verify_compiler(source: Path, policy_path: Path, private_output: Path) -> WorkflowState:
    source = source.resolve()
    private_output = private_output.resolve()
    policy = load_policy(policy_path)
    workflow = _load_bound_state(source, policy, private_output)
    state_path = _state_path(private_output)
    if workflow.status in {"published", "certified"}:
        return workflow
    manifest = workflow.candidate_manifest
    if manifest is None:
        workflow.status = "needs_input"
        workflow.pause_reason = "No candidate exists in the bound checkpoint"
        save_state(state_path, workflow)
        return workflow
    candidate_path = Path(manifest.candidate_path)
    maximum_iterations = int(policy["validation"].get("maximum_iterations", 5))
    while workflow.iteration <= maximum_iterations:
        workflow.status = "validating"
        save_state(state_path, workflow)
        try:
            validation_results = validate_candidate(candidate_path, policy)
        except SandboxUnavailable:
            workflow.status = "needs_input"
            workflow.pause_reason = "The required no-credential container sandbox is unavailable"
            save_state(state_path, workflow)
            return workflow
        workflow.status = "verifying"
        save_state(state_path, workflow)
        verification = verify_candidate(candidate_path, policy, validation_results)
        workflow.unresolved_count = len(verification.unresolved_findings)
        if verification.safe:
            break
        if any(item["exit_code"] != 0 for item in validation_results) and not verification.unresolved_findings:
            workflow.status = "needs_input"
            workflow.pause_reason = "The candidate is safe but its functional contract failed"
            save_state(state_path, workflow)
            return workflow
        next_actions, next_needs_input = remediation_plan(verification.unresolved_findings, policy)
        if next_needs_input:
            workflow.status = "needs_input"
            workflow.pause_reason = "Candidate remediation requires an information-owner decision"
            save_state(state_path, workflow)
            return workflow
        workflow.status = "sanitizing"
        save_state(state_path, workflow)
        changed, removed = transform_candidate(candidate_path, next_actions, policy)
        if not changed:
            workflow.status = "internal_error"
            workflow.pause_reason = "Remediation did not change the rejected candidate"
            save_state(state_path, workflow)
            return workflow
        manifest.transformations.extend(changed)
        manifest.removed_objects.extend(item for item in removed if item not in manifest.removed_objects)
        if removed:
            manifest.degradation = "minor"
        manifest = rebuild_commit(manifest)
        workflow.candidate_manifest = manifest
        workflow.iteration += 1
    else:
        workflow.status = "internal_error"
        workflow.pause_reason = "Remediation exceeded the bounded convergence limit"
        save_state(state_path, workflow)
        return workflow
    certification = certify(verification, policy, manifest.candidate_commit, manifest.degradation)
    configured_key = policy["security_runtime"].get("certification_key_path")
    key_path = Path(configured_key).resolve() if configured_key else private_output / "certification-ed25519.private.key"
    certification = sign_certification(certification, key_path)
    workflow.certification = certification
    workflow.unresolved_count = 0
    workflow.status = "certified"
    (private_output / "certification.private.json").write_text(json.dumps(asdict(certification), indent=2) + "\n", encoding="utf-8")
    if not workflow.source_snapshot or not snapshot_unchanged(workflow.source_snapshot, source):
        workflow.status = "internal_error"
        workflow.pause_reason = "Source changed during compilation"
        save_state(state_path, workflow)
        return workflow
    save_state(state_path, workflow)
    return workflow


def publish_compiler(source: Path, policy_path: Path, private_output: Path) -> WorkflowState:
    source = source.resolve()
    private_output = private_output.resolve()
    policy = load_policy(policy_path)
    workflow = _load_bound_state(source, policy, private_output)
    state_path = _state_path(private_output)
    if workflow.status == "published":
        return workflow
    certification = workflow.certification
    manifest = workflow.candidate_manifest
    if workflow.status != "certified" or certification is None or manifest is None:
        workflow.status = "needs_input"
        workflow.pause_reason = "Publication requires a certified candidate"
        save_state(state_path, workflow)
        return workflow
    candidate_path = Path(manifest.candidate_path)
    remote = policy["remote_target"]
    trusted_fingerprint = policy["publication"].get("trusted_public_key_fingerprint")
    if not trusted_fingerprint or trusted_fingerprint != certification.public_key_fingerprint:
        workflow.status = "needs_input"
        workflow.pause_reason = "Publication trust root is missing or differs from the certification key"
        save_state(state_path, workflow)
        return workflow
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
        trusted_fingerprint,
    )
    workflow.status = "publishing"
    save_state(state_path, workflow)
    attestation = publish_local(candidate_path, certification, authorization)
    workflow.attestation = attestation
    workflow.status = "published"
    write_attestation(private_output / "publication-attestation.private.json", attestation)
    save_state(state_path, workflow)
    return workflow


def resume_compiler(source: Path, policy_path: Path, private_output: Path, *, publish: bool = True) -> WorkflowState:
    source = source.resolve()
    private_output = private_output.resolve()
    policy = load_policy(policy_path)
    workflow = _load_bound_state(source, policy, private_output)
    if workflow.status == "published":
        return workflow
    if workflow.status != "certified":
        workflow = verify_compiler(source, policy_path, private_output)
    if publish and workflow.status == "certified":
        workflow = publish_compiler(source, policy_path, private_output)
    return workflow


def run_compiler(source: Path, policy_path: Path, private_output: Path, *, publish: bool = True) -> WorkflowState:
    workflow = sanitize_compiler(source, policy_path, private_output)
    if workflow.status == "needs_input":
        return workflow
    workflow = verify_compiler(source, policy_path, private_output)
    if publish and workflow.status == "certified":
        workflow = publish_compiler(source, policy_path, private_output)
    return workflow
