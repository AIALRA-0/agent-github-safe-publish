from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


WorkflowStatus = Literal[
    "received",
    "snapshotting",
    "assessing",
    "planning",
    "sanitizing",
    "repairing",
    "validating",
    "verifying",
    "certified",
    "publishing",
    "published",
    "needs_input",
    "retryable_failure",
    "internal_error",
    "operator_attention",
    "cancelled",
    "superseded",
    "legal_hold",
]


@dataclass(frozen=True)
class SourceSnapshot:
    repository: str
    commit: str
    tree: str
    inventory_sha256: str
    working_metadata_sha256: str
    file_count: int
    source_path: str


@dataclass(frozen=True)
class SourceFinding:
    finding_id: str
    rule_id: str
    category: str
    object_path: str
    object_sha256: str
    remediation_hint: str
    status: str = "unresolved"


@dataclass(frozen=True)
class PublicObservation:
    rule_id: str
    object_path: str
    reason: str


@dataclass(frozen=True)
class RemediationAction:
    action_id: str
    finding_id: str
    action: str
    object_path: str
    replacement: str | None = None
    depends_on: tuple[str, ...] = ()


@dataclass
class CandidateManifest:
    mode: str
    source_commit: str
    candidate_commit: str
    candidate_tree: str
    candidate_path: str
    transformations: list[dict[str, Any]] = field(default_factory=list)
    removed_objects: list[str] = field(default_factory=list)
    degradation: str = "none"


@dataclass
class DegradationReport:
    level: str
    removed_optional_objects: list[str] = field(default_factory=list)
    changed_capabilities: list[str] = field(default_factory=list)


@dataclass
class VerificationResult:
    safe: bool
    unresolved_findings: list[SourceFinding]
    observations: list[PublicObservation]
    coverage_complete: bool
    candidate_tree: str
    validation_results: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SafetyCertification:
    schema_version: int
    candidate_commit: str
    candidate_tree: str
    policy_sha256: str
    tool_version: str
    verification_sha256: str
    target_repository: str
    target_branch: str
    expected_remote_base: str | None
    degradation: str
    signature: str | None = None
    public_key: str | None = None
    public_key_fingerprint: str | None = None


@dataclass
class PublicationAuthorization:
    target_repository: str
    target_branch: str
    expected_remote_base: str | None
    allowed_writes: tuple[str, ...]
    maximum_degradation: str
    workflow_in_scope: bool
    release_in_scope: bool
    expires_at: str
    idempotency_key: str
    trusted_public_key_fingerprint: str | None = None


@dataclass
class PublicationAttestation:
    status: str
    candidate_commit: str
    candidate_tree: str
    remote_commit: str
    remote_tree: str
    target: str
    idempotency_key: str


@dataclass
class WorkflowState:
    workflow_id: str
    status: WorkflowStatus
    source_snapshot: SourceSnapshot | None = None
    finding_count: int = 0
    unresolved_count: int = 0
    iteration: int = 0
    candidate_manifest: CandidateManifest | None = None
    certification: SafetyCertification | None = None
    attestation: PublicationAttestation | None = None
    pause_reason: str | None = None
    policy_sha256: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
