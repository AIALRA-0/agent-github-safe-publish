from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from .model import SourceSnapshot


def _stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_source_audit_receipt(policy: dict, source: Path | None, snapshot: SourceSnapshot | None) -> dict | None:
    receipt = policy.get("validation", {}).get("source_audit_receipt")
    if not receipt:
        return None
    required = {
        "report_path",
        "report_sha256",
        "source_commit",
        "source_tree",
        "scanner_sha256",
        "policy_fingerprint",
        "report_fingerprint",
        "worktree_file_count",
        "issued_at",
        "expires_at",
        "approved_by",
        "review_trigger",
    }
    if not isinstance(receipt, dict) or not required.issubset(receipt):
        raise ValueError("Source audit receipt is incomplete")
    if source is None or snapshot is None:
        raise ValueError("Source audit receipt requires the bound source snapshot")
    report_path = Path(receipt["report_path"]).expanduser().resolve()
    try:
        report_path.relative_to(source.resolve())
    except ValueError:
        pass
    else:
        raise ValueError("Source audit receipt cannot be stored inside the source repository")
    if report_path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Source audit report exceeds the bounded size limit")
    if _stream_sha256(report_path) != receipt["report_sha256"]:
        raise ValueError("Source audit receipt file digest differs")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if receipt["source_commit"] != snapshot.commit or receipt["source_tree"] != snapshot.tree:
        raise ValueError("Source audit receipt targets another source snapshot")
    if int(receipt["worktree_file_count"]) != snapshot.file_count:
        raise ValueError("Source audit receipt file count differs")
    if report.get("source_commit") != snapshot.commit:
        raise ValueError("Source audit report targets another commit")
    if report.get("scanner_sha256") != receipt["scanner_sha256"]:
        raise ValueError("Source audit scanner binding differs")
    if report.get("policy_fingerprint") != receipt["policy_fingerprint"]:
        raise ValueError("Source audit policy binding differs")
    if report.get("report_fingerprint") != receipt["report_fingerprint"]:
        raise ValueError("Source audit report fingerprint differs")
    summary = report.get("summary", {})
    progress = report.get("worktree_progress", {})
    if int(summary.get("critical_finding_count", 1)) != 0 or int(summary.get("critical_coverage_gap_count", 1)) != 0:
        raise ValueError("Source audit receipt contains an unresolved critical result")
    if progress.get("status") != "complete" or int(progress.get("processed_file_count", -1)) != snapshot.file_count:
        raise ValueError("Source audit receipt does not cover every source file")
    expires_at = datetime.fromisoformat(str(receipt["expires_at"]).replace("Z", "+00:00"))
    if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
        raise ValueError("Source audit receipt has expired")
    if receipt["review_trigger"] != "content-policy-scanner-or-expiry-change":
        raise ValueError("Source audit receipt review trigger is invalid")
    return receipt
