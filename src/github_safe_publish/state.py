from __future__ import annotations

from dataclasses import fields
import json
import os
from pathlib import Path
import tempfile

from .model import CandidateManifest, PublicationAttestation, SafetyCertification, SourceSnapshot, WorkflowState


def save_state(path: Path, state: WorkflowState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".workflow-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state.as_dict(), handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _construct(cls, value):
    if value is None:
        return None
    allowed = {item.name for item in fields(cls)}
    return cls(**{key: item for key, item in value.items() if key in allowed})


def load_state(path: Path) -> WorkflowState:
    document = json.loads(path.read_text(encoding="utf-8"))
    document["source_snapshot"] = _construct(SourceSnapshot, document.get("source_snapshot"))
    document["candidate_manifest"] = _construct(CandidateManifest, document.get("candidate_manifest"))
    document["certification"] = _construct(SafetyCertification, document.get("certification"))
    document["attestation"] = _construct(PublicationAttestation, document.get("attestation"))
    return _construct(WorkflowState, document)
