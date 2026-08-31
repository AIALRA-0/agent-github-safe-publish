from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Iterable
import zipfile

from .model import PublicObservation, SourceFinding


TEXT_EXTENSIONS = {
    ".c", ".cc", ".cfg", ".conf", ".cpp", ".css", ".csv", ".env", ".go",
    ".h", ".hpp", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".md",
    ".ps1", ".py", ".rb", ".rs", ".sh", ".sql", ".toml", ".ts", ".tsx",
    ".txt", ".xml", ".yaml", ".yml",
}
DATABASE_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}
ARCHIVE_EXTENSIONS = {".zip"}
REMOVABLE_ARTIFACT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".7z", ".rar", ".mp3", ".mp4", ".mov", ".wav", ".exe", ".dll", ".bin"}

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


def _contains_private_text(text: str, policy: dict) -> bool:
    if _active_credential_match(text) or PRIVATE_IPV4.search(text):
        return True
    for entity in policy["sensitive_entities"]:
        if entity["kind"] == "literal" and entity["value"] in text:
            return True
        if entity["kind"] == "regex" and re.search(entity["value"], text):
            return True
    return False


def _sqlite_requires_synthesis(path: Path, policy: dict) -> bool:
    try:
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        try:
            rows = connection.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
            if any(_contains_private_text(str(sql or ""), policy) for _, sql in rows):
                return True
            for name, _ in rows:
                quoted = name.replace('"', '""')
                if connection.execute(f'SELECT 1 FROM "{quoted}" LIMIT 1').fetchone() is not None:
                    return True
            return False
        finally:
            connection.close()
    except sqlite3.Error:
        return True


def _notebook_requires_sanitization(data: bytes, policy: dict) -> bool:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return True
    if document.get("metadata"):
        return True
    for cell in document.get("cells", []):
        if cell.get("outputs") or cell.get("execution_count") is not None:
            return True
        source = cell.get("source", [])
        text = "".join(source) if isinstance(source, list) else str(source)
        if _contains_private_text(text, policy):
            return True
    return False


def _zip_requires_sanitization(path: Path, policy: dict) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                normalized = Path(member.filename)
                if normalized.is_absolute() or ".." in normalized.parts or member.is_dir():
                    return not member.is_dir()
                if normalized.suffix.lower() not in TEXT_EXTENSIONS and normalized.suffix:
                    return True
                try:
                    if _contains_private_text(archive.read(member).decode("utf-8"), policy):
                        return True
                except UnicodeDecodeError:
                    return True
        return False
    except (OSError, zipfile.BadZipFile):
        return True


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
        suffix = path.suffix.lower()
        if suffix in DATABASE_EXTENSIONS:
            if _sqlite_requires_synthesis(path, policy):
                findings.append(_finding("data.sqlite", "real-data", relative, data, "synthesize"))
            continue
        if suffix == ".ipynb":
            if _notebook_requires_sanitization(data, policy):
                findings.append(_finding("data.notebook", "real-data", relative, data, "regenerate"))
            continue
        if suffix in ARCHIVE_EXTENSIONS:
            if _zip_requires_sanitization(path, policy):
                findings.append(_finding("artifact.archive", "unsupported-artifact", relative, data, "repack"))
            continue
        if suffix in REMOVABLE_ARTIFACT_EXTENSIONS:
            findings.append(_finding("artifact.unsupported", "unsupported-artifact", relative, data, "remove-and-stub"))
            continue
        if path.name == ".env" or relative.endswith("/.env"):
            findings.append(_finding("path.private-env", "credential", relative, data, "externalize"))
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            rule = "artifact.undecodable" if suffix in TEXT_EXTENSIONS else "artifact.opaque"
            findings.append(_finding(rule, "unsupported-artifact", relative, data, "remove-and-stub"))
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
