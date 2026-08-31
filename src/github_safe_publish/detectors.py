from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Iterable

from .model import PublicObservation, SourceFinding


TEXT_EXTENSIONS = {
    ".c", ".cc", ".cfg", ".conf", ".cpp", ".css", ".csv", ".env", ".go",
    ".h", ".hpp", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".md",
    ".ps1", ".py", ".rb", ".rs", ".sh", ".sql", ".toml", ".ts", ".tsx",
    ".txt", ".xml", ".yaml", ".yml",
}

CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|cookie|session)\b\s*[:=]\s*(\"[^\"\r\n]{8,}\"|'[^'\r\n]{8,}'|[^\s\"'`,;]{8,})"
)
PRIVATE_IPV4 = re.compile(r"(?<!\d)(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?!\d)")
URL = re.compile(r"https?://[^\s\"'<>()]+", re.I)
BRAND = re.compile(r"(?i)(?<![A-Za-z0-9])AIALRA(?![A-Za-z0-9])")


def _active_credential_match(text: str) -> bool:
    for match in CREDENTIAL_ASSIGNMENT.finditer(text):
        value = match.group(2).strip("\"'")
        lowered = value.lower()
        if value.startswith(("${", "<")) or "environ" in lowered or "process.env" in lowered:
            continue
        if lowered in {"changeme", "change-me", "placeholder", "redacted"}:
            continue
        return True
    return False


def _finding(rule_id: str, category: str, path: str, data: bytes, hint: str) -> SourceFinding:
    digest = hashlib.sha256(data).hexdigest()
    stable = hashlib.sha256(f"{rule_id}\0{path}\0{digest}".encode("utf-8")).hexdigest()[:24]
    return SourceFinding(stable, rule_id, category, path, digest, hint)


def iter_candidate_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if ".git" in path.parts or path.is_symlink() or not path.is_file():
            continue
        yield path


def inspect_tree(root: Path, policy: dict) -> tuple[list[SourceFinding], list[PublicObservation]]:
    findings: list[SourceFinding] = []
    observations: list[PublicObservation] = []
    mapping_by_entity = {item.get("entity_id"): item.get("replacement") for item in policy["synthetic_mappings"]}
    for path in iter_candidate_files(root):
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        if path.name == ".env" or relative.endswith("/.env"):
            findings.append(_finding("path.private-env", "credential", relative, data, "externalize"))
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {"Dockerfile", "Makefile"}:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            findings.append(_finding("artifact.undecodable", "unsupported-artifact", relative, data, "remove-and-stub"))
            continue
        if _active_credential_match(text):
            findings.append(_finding("credential.assignment", "credential", relative, data, "externalize"))
        if PRIVATE_IPV4.search(text):
            findings.append(_finding("infrastructure.private-ip", "private-infrastructure", relative, data, "parameterize"))
        for entity in policy["sensitive_entities"]:
            value = entity["value"]
            matched = value in text if entity["kind"] == "literal" else re.search(value, text) is not None
            if matched:
                hint = policy["remediation_defaults"].get(entity["category"], "replace")
                if mapping_by_entity.get(entity["id"]):
                    hint = "replace"
                findings.append(_finding(entity["id"], entity["category"], relative, data, hint))
        if URL.search(text):
            observations.append(PublicObservation("public.url", relative, "Public URL remains visible for review"))
        if BRAND.search(text):
            observations.append(PublicObservation("public.brand", relative, "Repository brand remains visible"))
    return findings, observations
