from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

from .candidate import build_candidate, rebuild_commit
from .credential_scanner import CredentialScannerUnavailable
from .detectors import inspect_tree_detailed
from .inventory import snapshot_unchanged, source_snapshot
from .model import DegradationReport, PublicationAuthorization, WorkflowState
from .planner import optional_removal_fallback, remediation_plan
from .policy import load_policy, policy_sha256
from .publication import authorization_sha256, publish_local, write_attestation
from .receipts import validate_source_audit_receipt
from .sandbox import SandboxUnavailable
from .signing import private_key_fingerprint, sign_certification
from .state import save_state
from .transformers import transform_candidate
from .validation import validate_candidate
from .verification import certify, verify_candidate


def _state_path(private_output: Path) -> Path:
    return private_output / "workflow-state.private.json"


def _write_private_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def _preserve_current_workflow(private_output: Path, collection: str) -> Path:
    revisions = private_output / collection
    revisions.mkdir(parents=True, exist_ok=True)
    prefix = {"revisions": "revision", "retries": "retry"}.get(collection, "snapshot")
    preserved = revisions / f"{prefix}-{len(list(revisions.iterdir())) + 1:04d}"
    preserved.mkdir()
    for name in (
        "candidate",
        "workflow-state.private.json",
        "certification.private.json",
        "publication-authorization.private.json",
        "publication-attestation.private.json",
        "degradation.private.json",
    ):
        current = private_output / name
        if current.exists():
            shutil.move(str(current), str(preserved / name))
    return preserved


def _authorization(policy: dict, manifest, fingerprint: str) -> PublicationAuthorization:
    remote = policy["remote_target"]
    return PublicationAuthorization(
        remote["repository"],
        remote.get("branch", "main"),
        remote.get("expected_base"),
        tuple(policy["publication"].get("allowed_writes", ["commit"])),
        policy["degradation_policy"].get("maximum_automatic", "minor"),
        bool(policy["publication"].get("workflow_in_scope", False)),
        bool(policy["publication"].get("release_in_scope", False)),
        policy["publication"].get("authorization_expires_at", "2099-01-01T00:00:00Z"),
        policy["publication"].get("idempotency_key", hashlib.sha256(manifest.candidate_tree.encode()).hexdigest()),
        fingerprint,
    )


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
    try:
        private_output.relative_to(source)
    except ValueError:
        pass
    else:
        raise ValueError("Private output cannot be inside the source repository")
    policy = load_policy(policy_path, source)
    workflow = WorkflowState(str(uuid.uuid4()), "received")
    workflow.policy_sha256 = policy_sha256(policy)
    state_path = _state_path(private_output)
    private_output.mkdir(parents=True, exist_ok=True)
    if state_path.exists() or (private_output / "candidate").exists():
        raise ValueError("Private output already contains an active workflow")
    workflow.status = "snapshotting"
    save_state(state_path, workflow)
    snapshot = source_snapshot(source)
    workflow.source_snapshot = snapshot
    workflow.status = "assessing"
    save_state(state_path, workflow)

    receipt = validate_source_audit_receipt(policy, source, snapshot)
    findings, _, _ = inspect_tree_detailed(
        source,
        policy,
        inherited_source=source,
        source_receipt=receipt,
    )
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
    try:
        manifest = build_candidate(source, candidate_path, snapshot, actions, policy)
    except ValueError as exc:
        workflow.status = "needs_input"
        workflow.pause_reason = f"Candidate construction requires an owner decision: {exc}"
        save_state(state_path, workflow)
        return workflow
    except (OSError, subprocess.CalledProcessError):
        workflow.status = "retryable_failure"
        workflow.pause_reason = "Candidate construction could not complete and may be retried"
        save_state(state_path, workflow)
        return workflow
    except RuntimeError:
        workflow.status = "internal_error"
        workflow.pause_reason = "Candidate construction rejected an unsafe or unsupported source object"
        save_state(state_path, workflow)
        return workflow
    workflow.candidate_manifest = manifest
    degradation = DegradationReport(manifest.degradation, list(manifest.removed_objects), [])
    _write_private_json(private_output / "degradation.private.json", asdict(degradation))
    workflow.iteration = 1
    workflow.status = "validating"
    save_state(state_path, workflow)
    return workflow


def verify_compiler(source: Path, policy_path: Path, private_output: Path) -> WorkflowState:
    source = source.resolve()
    private_output = private_output.resolve()
    policy = load_policy(policy_path, source)
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
        try:
            verification = verify_candidate(
                candidate_path,
                policy,
                validation_results,
                source=source,
                source_snapshot=workflow.source_snapshot,
            )
        except CredentialScannerUnavailable:
            workflow.status = "needs_input"
            workflow.pause_reason = "The required digest-bound credential scanner is unavailable or invalid"
            save_state(state_path, workflow)
            return workflow
        workflow.unresolved_count = len(verification.unresolved_findings)
        if (
            verification.candidate_commit != manifest.candidate_commit
            or verification.candidate_tree != manifest.candidate_tree
            or verification.candidate_index_tree != manifest.candidate_tree
        ):
            workflow.status = "operator_attention"
            workflow.pause_reason = "The candidate commit, tree, or index differs from the bound manifest"
            save_state(state_path, workflow)
            return workflow
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
        try:
            changed, removed = transform_candidate(candidate_path, next_actions, policy)
        except ValueError:
            fallback_actions, fallback_needs_input = optional_removal_fallback(verification.unresolved_findings, policy)
            if fallback_needs_input:
                workflow.status = "needs_input"
                workflow.pause_reason = "A required candidate artifact could not be transformed safely"
                save_state(state_path, workflow)
                return workflow
            try:
                changed, removed = transform_candidate(candidate_path, fallback_actions, policy)
            except (OSError, RuntimeError, ValueError):
                workflow.status = "internal_error"
                workflow.pause_reason = "The optional-artifact fallback could not complete safely"
                save_state(state_path, workflow)
                return workflow
        except (OSError, RuntimeError):
            workflow.status = "internal_error"
            workflow.pause_reason = "Candidate transformation failed before a safe fixed point"
            save_state(state_path, workflow)
            return workflow
        if not changed:
            fallback_actions, fallback_needs_input = optional_removal_fallback(verification.unresolved_findings, policy)
            if fallback_needs_input:
                workflow.status = "needs_input"
                workflow.pause_reason = "Automatic remediation could not safely transform a required candidate object"
                save_state(state_path, workflow)
                return workflow
            changed, removed = transform_candidate(candidate_path, fallback_actions, policy)
            if not changed:
                workflow.status = "internal_error"
                workflow.pause_reason = "The optional-object fallback did not change the rejected candidate"
                save_state(state_path, workflow)
                return workflow
        manifest.transformations.extend(changed)
        manifest.removed_objects.extend(item for item in removed if item not in manifest.removed_objects)
        if removed:
            manifest.degradation = "minor"
        manifest = rebuild_commit(manifest)
        workflow.candidate_manifest = manifest
        degradation = DegradationReport(manifest.degradation, list(manifest.removed_objects), [])
        _write_private_json(private_output / "degradation.private.json", asdict(degradation))
        workflow.iteration += 1
    else:
        workflow.status = "internal_error"
        workflow.pause_reason = "Remediation exceeded the bounded convergence limit"
        save_state(state_path, workflow)
        return workflow
    configured_key = policy["security_runtime"].get("certification_key_path")
    key_path = Path(configured_key).resolve() if configured_key else private_output / "certification-ed25519.private.key"
    fingerprint = private_key_fingerprint(key_path)
    trusted_fingerprint = policy["publication"].get("trusted_public_key_fingerprint")
    if not trusted_fingerprint or trusted_fingerprint != fingerprint:
        workflow.status = "needs_input"
        workflow.pause_reason = "The configured trust root differs from the certification key"
        save_state(state_path, workflow)
        return workflow
    authorization = _authorization(policy, manifest, fingerprint)
    certification = certify(
        verification,
        policy,
        manifest.candidate_commit,
        manifest.degradation,
        authorization_sha256(authorization),
    )
    certification = sign_certification(certification, key_path)
    workflow.certification = certification
    workflow.unresolved_count = 0
    workflow.status = "certified"
    _write_private_json(private_output / "certification.private.json", asdict(certification))
    _write_private_json(private_output / "publication-authorization.private.json", asdict(authorization))
    if not workflow.source_snapshot or not snapshot_unchanged(workflow.source_snapshot, source):
        workflow.status = "internal_error"
        workflow.pause_reason = "Source changed during compilation"
        save_state(state_path, workflow)
        return workflow
    save_state(state_path, workflow)
    return workflow


def publish_compiler(source: Path, policy_path: Path, private_output: Path) -> WorkflowState:
    private_output = private_output.resolve()
    from .state import load_state

    workflow = load_state(_state_path(private_output))
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
    authorization_document = json.loads((private_output / "publication-authorization.private.json").read_text(encoding="utf-8"))
    authorization = PublicationAuthorization(**authorization_document)
    if isinstance(authorization.allowed_writes, list):
        authorization.allowed_writes = tuple(authorization.allowed_writes)
    workflow.status = "publishing"
    save_state(state_path, workflow)
    try:
        attestation = publish_local(candidate_path, certification, authorization)
    except ValueError:
        workflow.status = "operator_attention"
        workflow.pause_reason = "The certified candidate or authorization binding differs"
        save_state(state_path, workflow)
        return workflow
    except (OSError, RuntimeError, subprocess.SubprocessError):
        workflow.status = "retryable_failure"
        workflow.pause_reason = "The remote publication could not complete and may be retried"
        save_state(state_path, workflow)
        return workflow
    workflow.attestation = attestation
    workflow.status = "published"
    write_attestation(
        private_output / "publication-attestation.private.json",
        attestation,
        certification,
        authorization,
    )
    save_state(state_path, workflow)
    return workflow


def resume_compiler(source: Path, policy_path: Path, private_output: Path, *, publish: bool = True) -> WorkflowState:
    source = source.resolve()
    private_output = private_output.resolve()
    policy = load_policy(policy_path, source)
    from .state import load_state

    workflow = load_state(_state_path(private_output))
    incoming_policy_sha256 = policy_sha256(policy)
    if workflow.status in {"cancelled", "superseded", "legal_hold"}:
        return workflow
    if workflow.policy_sha256 != incoming_policy_sha256:
        if workflow.status != "needs_input":
            raise ValueError("Policy differs from the checkpoint binding")
        _preserve_current_workflow(private_output, "revisions")
        workflow = sanitize_compiler(source, policy_path, private_output)
        if workflow.status == "needs_input":
            return workflow
    else:
        workflow = _load_bound_state(source, policy, private_output)
    if workflow.status == "published":
        return workflow
    if workflow.status == "retryable_failure" and workflow.certification is not None and publish:
        return publish_compiler(source, policy_path, private_output)
    if workflow.status == "retryable_failure" and workflow.candidate_manifest is None:
        _preserve_current_workflow(private_output, "retries")
        workflow = sanitize_compiler(source, policy_path, private_output)
        if workflow.status in {"needs_input", "retryable_failure", "internal_error"}:
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
