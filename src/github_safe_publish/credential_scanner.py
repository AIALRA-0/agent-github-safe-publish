from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from . import __version__
from .model import SourceFinding


class CredentialScannerUnavailable(RuntimeError):
    pass


_VERIFIED_SCANNERS: set[str] = set()


def _retained_public(policy: dict, relative: str, digest: str, scanner_id: str) -> bool:
    expected_scanner = f"gitleaks-8.30.1:{scanner_id}"
    return any(
        rule.get("action") == "retain-public"
        and not rule.get("legacy_review_only")
        and rule.get("object") == relative
        and rule.get("sha256") == digest
        and rule.get("tool_version") == __version__
        and expected_scanner in rule.get("scanner_ids", [])
        for rule in policy.get("retention_rules", [])
    )


def _stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _load_report(path: Path) -> list[dict]:
    if not path.exists() or path.stat().st_size > 16 * 1024 * 1024:
        raise CredentialScannerUnavailable("Credential scanner report is missing or exceeds its bound")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CredentialScannerUnavailable("Credential scanner report is invalid") from exc
    if not isinstance(report, list):
        raise CredentialScannerUnavailable("Credential scanner report has an unexpected schema")
    return report


def _run(executable: Path, source: Path, report: Path, timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [
                str(executable), "dir", "--no-banner", "--no-color", "--redact=100",
                "--report-format", "json", "--report-path", str(report), str(source),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CredentialScannerUnavailable("Credential scanner could not complete") from exc


def scan_gitleaks(candidate: Path, policy: dict) -> tuple[list[SourceFinding], dict]:
    scanner = policy["security_runtime"].get("credential_scanner")
    if not isinstance(scanner, dict) or not {"path", "sha256", "version"}.issubset(scanner):
        raise CredentialScannerUnavailable("Credential scanner binding is missing")
    if scanner["version"] != "8.30.1":
        raise CredentialScannerUnavailable("Credential scanner version is not the locked release")
    executable = Path(scanner["path"]).expanduser().resolve()
    if not executable.is_file() or _stream_sha256(executable) != scanner["sha256"]:
        raise CredentialScannerUnavailable("Credential scanner executable digest differs")
    private_root_value = policy["security_runtime"].get("private_temp_root")
    if not private_root_value:
        raise CredentialScannerUnavailable("Credential scanner private temporary root is missing")
    private_root = Path(private_root_value).expanduser().resolve()
    private_root.mkdir(parents=True, exist_ok=True)
    try:
        private_root.relative_to(candidate.resolve())
    except ValueError:
        pass
    else:
        raise CredentialScannerUnavailable("Credential scanner temporary root cannot be inside the candidate")
    scanner_key = f"{scanner['sha256']}:{scanner['version']}"
    timeout = int(policy["validation"].get("credential_scanner_timeout_seconds", 330))
    if scanner_key not in _VERIFIED_SCANNERS:
        with tempfile.TemporaryDirectory(prefix="gitleaks-canary-", dir=private_root) as temporary:
            canary_root = Path(temporary)
            marker = "gh" + "p_" + "7H4G2J9K5M8N3P6Q1R4S7T0V2W5X8Y6Z9B3C"
            (canary_root / "canary.txt").write_text("GITHUB_TOKEN=" + marker + "\n", encoding="utf-8")
            report_path = canary_root / "report.json"
            result = _run(executable, canary_root, report_path, min(timeout, 60))
            records = _load_report(report_path)
            if result.returncode not in {0, 1} or not records:
                raise CredentialScannerUnavailable("Credential scanner did not detect its runtime canary")
        _VERIFIED_SCANNERS.add(scanner_key)
    with tempfile.TemporaryDirectory(prefix="gitleaks-candidate-", dir=private_root) as temporary:
        report_path = Path(temporary) / "report.json"
        result = _run(executable, candidate, report_path, timeout)
        if result.returncode not in {0, 1}:
            raise CredentialScannerUnavailable("Credential scanner returned an unexpected status")
        records = _load_report(report_path) if report_path.exists() else []
    findings: list[SourceFinding] = []
    for record in records:
        reported = Path(str(record.get("File", "")))
        path = reported.resolve() if reported.is_absolute() else (candidate / reported).resolve()
        try:
            relative = path.relative_to(candidate.resolve()).as_posix()
        except ValueError as exc:
            raise CredentialScannerUnavailable("Credential scanner reported an out-of-tree object") from exc
        if not path.is_file():
            raise CredentialScannerUnavailable("Credential scanner finding cannot be bound to a candidate object")
        digest = _stream_sha256(path)
        scanner_rule = str(record.get("RuleID", "unknown"))
        if _retained_public(policy, relative, digest, scanner_rule):
            continue
        rule_id = "gitleaks." + scanner_rule
        finding_id = hashlib.sha256(f"{rule_id}\0{relative}\0{digest}".encode("utf-8")).hexdigest()[:24]
        findings.append(SourceFinding(finding_id, rule_id, "credential", relative, digest, "externalize"))
    return findings, {
        "path": "@credential-scanner",
        "status": "checked",
        "parser": "gitleaks-8.30.1-redacted",
        "sha256": scanner["sha256"],
    }
