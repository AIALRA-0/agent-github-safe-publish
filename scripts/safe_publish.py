#!/usr/bin/env python3
"""Fail-closed repository sanitization and publication gate.

The program deliberately keeps raw matches out of process output and public reports.
Raw candidates are written only by commands that enforce the private CODEX_HOME path.
"""

from __future__ import annotations

import argparse
from array import array
import base64
import bisect
import binascii
import dataclasses
import datetime as dt
import fnmatch
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any, Iterable
import urllib.request
import zipfile


SCHEMA_VERSION = 1
GITLEAKS_VERSION = "8.30.1"
MAX_SECRET_BYTES = 48 * 1024
DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_EXPANDED_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3
MAX_FINDINGS = 50_000

LEGAL_NAMES = {"license", "license.md", "license.txt", "notice", "notice.md", "notice.txt", "citation.cff"}
OFFICE_SUFFIXES = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".svg", ".ico"}
ARCHIVE_SUFFIXES = {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar"}
DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".sql", ".dump", ".bak"}
OPAQUE_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar", ".wasm", ".pyc"}


@dataclasses.dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    pattern: re.Pattern[str]
    value_group: int = 0


@dataclasses.dataclass
class Finding:
    repository: str
    surface: str
    object: str
    location: str
    rule_id: str
    category: str
    severity: str
    status: str
    legal_protected: bool = False

    def public_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Coverage:
    surface: str
    status: str
    reason: str = ""
    object_count: int = 0

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


GENERIC_RULES = (
    Rule("credential.private-key", "credential", "block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    Rule(
        "credential.assignment",
        "credential",
        "block",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|cookie|session|recovery[_-]?code)\b\s*[:=]\s*[\"']?([^\s\"'`,;]{4,})"
        ),
        1,
    ),
    Rule(
        "credential.database-uri",
        "credential",
        "block",
        re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql)://[^\s:@/]+:[^\s@/]+@[^\s]+"),
    ),
    Rule(
        "credential.signed-url",
        "credential",
        "block",
        re.compile(r"(?i)https?://[^\s\"'<>]+(?:x-amz-signature|x-goog-signature|[?&](?:sig|signature|access_token|token)=)[^\s\"'<>]+"),
    ),
    Rule("identity.email", "identity", "review", re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}(?![\w.-])", re.I)),
    Rule(
        "identity.phone",
        "identity",
        "review",
        re.compile(r"(?<!\w)(?:(?:\+\d{1,3}[ .-]?)?\(\d{2,4}\)[ .-]?\d{3,4}[ .-]?\d{4}|\+\d{1,3}[ .-]\d{2,4}[ .-]\d{3,4}[ .-]\d{4}|\d{3}[ .-]\d{3}[ .-]\d{4})(?!\w)"),
    ),
    Rule("identity.uid", "identity", "review", re.compile(r"(?i)\b(?:uid|user[_-]?id|account[_-]?id|device[_-]?id|contact[_-]?id)\b\s*[:=]\s*[\"']?([A-Za-z0-9._:-]{4,})"), 1),
    Rule("identity.address-cn", "identity", "review", re.compile(r"[\u4e00-\u9fff]{2,20}(?:省|市|自治区|区|县|镇|乡|街道)[\u4e00-\u9fff0-9\-]{2,80}\d+(?:号|栋|单元|室)")),
    Rule("identity.address-us", "identity", "review", re.compile(r"(?i)\b\d{1,6}\s+[A-Za-z0-9 .'-]{2,80}\s(?:street|st\.?|road|rd\.?|avenue|ave\.?|lane|ln\.?|drive|dr\.?|boulevard|blvd\.?)\b")),
    Rule("identity.aialra", "identity", "review", re.compile(r"(?i)(?<![A-Za-z0-9])aialra(?![A-Za-z0-9])")),
    Rule("identity.aialra-confusable", "identity", "review", re.compile(r"(?i)(?<!\w)(?:a|[ΑА])(?:i|[ΙІі])(?:a|[ΑА])(?:l|[ΙІ])r(?:a|[ΑА])(?!\w)")),
    Rule("infrastructure.ipv4", "infrastructure", "block", re.compile(r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)")),
    Rule("infrastructure.mac", "infrastructure", "block", re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")),
    Rule("infrastructure.windows-path", "infrastructure", "block", re.compile(r"(?i)\b[A-Z]:\\(?:Users|Documents and Settings)\\[^\s\"'<>|]+")),
    Rule("infrastructure.unix-home", "infrastructure", "block", re.compile(r"(?<![\w/])/(?:home|Users)/[^\s\"'<>]+")),
    Rule("infrastructure.url", "infrastructure", "review", re.compile(r"(?i)\bhttps?://[^\s\"'<>\])}]+")),
)

PLACEHOLDER_VALUES = {
    "changeme",
    "change-me",
    "example",
    "example_password",
    "example-token",
    "password",
    "placeholder",
    "redacted",
    "replace_me",
    "replace-me",
    "secret",
    "test",
    "your_api_key",
    "your-token",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def run(command: list[str], cwd: Path | None = None, *, text: bool = True, input_data: bytes | str | None = None) -> subprocess.CompletedProcess[Any]:
    """Run a child process without inheriting output that could contain a match."""
    options: dict[str, Any] = {
        "cwd": str(cwd) if cwd else None,
        "input": input_data,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": text,
        "check": False,
    }
    if text:
        options["encoding"] = "utf-8"
        options["errors"] = "replace"
    return subprocess.run(
        command,
        **options,
    )


def get_codex_home() -> Path:
    configured = os.environ.get("CODEX_HOME")
    if configured:
        return Path(configured).expanduser().resolve()
    return (Path.home() / ".codex").resolve()


def private_root() -> Path:
    return (get_codex_home() / "private" / "github-safe-publish").resolve()


def ensure_private_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    root = private_root()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Private output must be below {root}") from exc
    root.mkdir(parents=True, exist_ok=True)
    return resolved


def write_json(path: Path, data: Any, *, private: bool = False) -> None:
    resolved = ensure_private_path(path) if private else path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    temporary = resolved.with_name(f".{resolved.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, resolved)
    if private:
        os.chmod(resolved, stat.S_IRUSR | stat.S_IWUSR)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def policy_fingerprint(policy: dict[str, Any] | None) -> str | None:
    if policy is None:
        return None
    encoded = json.dumps(policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded)


def empty_policy() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "identifiers": [],
        "replacements": [],
        "approved_locations": [],
        "blocked_paths": [],
        "binary_approvals": [],
        "exceptions": [],
    }


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    required = {
        "schema_version",
        "identifiers",
        "replacements",
        "approved_locations",
        "blocked_paths",
        "binary_approvals",
        "exceptions",
    }
    if not isinstance(policy, dict) or not required.issubset(policy):
        raise ValueError("Private policy is missing required fields")
    if policy["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Private policy schema version is unknown")
    for name in required - {"schema_version"}:
        if not isinstance(policy[name], list):
            raise ValueError(f"Private policy field must be a list: {name}")

    seen_ids: set[str] = set()
    for item in policy["identifiers"]:
        if not isinstance(item, dict) or not {"id", "kind", "value", "severity"}.issubset(item):
            raise ValueError("Each identifier requires id, kind, value, and severity")
        if item["id"] in seen_ids or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,127}", item["id"]):
            raise ValueError("Identifier IDs must be unique, stable rule IDs")
        seen_ids.add(item["id"])
        if item["kind"] not in {"literal", "regex"} or item["severity"] not in {"review", "block"}:
            raise ValueError("Identifier kind or severity is invalid")
        if not isinstance(item["value"], str) or not item["value"]:
            raise ValueError("Identifier values must be non-empty strings")
        if item["kind"] == "regex":
            compiled = re.compile(item["value"])
            if compiled.match(""):
                raise ValueError("Private identifier regex cannot match an empty string")

    for mapping in policy["replacements"]:
        if not isinstance(mapping, dict) or not {"identifier_id", "replacement"}.issubset(mapping):
            raise ValueError("Each replacement requires identifier_id and replacement")
        if mapping["identifier_id"] not in seen_ids or not isinstance(mapping["replacement"], str):
            raise ValueError("Replacement references an unknown identifier")

    for approval in policy["approved_locations"]:
        if not isinstance(approval, dict) or not {"rule_id", "object", "approved_by", "reason"}.issubset(approval):
            raise ValueError("Each approved location requires rule_id, object, approved_by, and reason")
        if any(symbol in approval["object"] for symbol in "*?["):
            raise ValueError("Approved locations must be exact and cannot contain wildcards")

    for approval in policy["binary_approvals"]:
        if not isinstance(approval, dict) or not {"object", "sha256", "approved_by", "reason"}.issubset(approval):
            raise ValueError("Each binary approval requires object, sha256, approved_by, and reason")
        if not re.fullmatch(r"[0-9a-f]{64}", approval["sha256"]):
            raise ValueError("Binary approval SHA-256 is invalid")

    for exception in policy["exceptions"]:
        required_exception = {"rule_id", "object", "approved_by", "reason", "expires_at", "review_trigger"}
        if not isinstance(exception, dict) or not required_exception.issubset(exception):
            raise ValueError("Each exception requires an exact object, approval, expiry, and review trigger")
        if any(symbol in exception["object"] for symbol in "*?["):
            raise ValueError("Exceptions must target an exact object")
        dt.datetime.fromisoformat(exception["expires_at"].replace("Z", "+00:00"))

    if any(not isinstance(pattern, str) or not pattern for pattern in policy["blocked_paths"]):
        raise ValueError("Blocked paths must be non-empty glob strings")
    return policy


def load_policy(path: Path, source: Path | None = None) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if source is not None:
        source_resolved = source.expanduser().resolve()
        try:
            resolved.relative_to(source_resolved)
        except ValueError:
            pass
        else:
            raise ValueError("Private policy cannot be loaded from inside the source repository")
    with resolved.open("r", encoding="utf-8") as handle:
        return validate_policy(json.load(handle))


def load_policy_from_env(variable: str) -> dict[str, Any]:
    encoded = os.environ.get(variable, "")
    if not encoded:
        raise ValueError("Private policy Secret is missing")
    if len(encoded.encode("utf-8")) > MAX_SECRET_BYTES:
        raise ValueError("Encoded private policy exceeds 48 KB")
    try:
        raw = base64.b64decode(encoded, validate=True)
        decoded = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Private policy Secret cannot be decoded") from exc
    return validate_policy(decoded)


class ScanState:
    def __init__(self, repository: str, policy: dict[str, Any] | None, collect_raw: bool = False) -> None:
        self.repository = repository
        self.policy = policy or empty_policy()
        self.collect_raw = collect_raw
        self.findings: list[Finding] = []
        self.raw_candidates: list[dict[str, Any]] = []
        self.coverage: list[Coverage] = []
        self._finding_keys: set[tuple[str, str, str, str]] = set()
        self._candidate_keys: set[tuple[str, str, str, str, str]] = set()
        self._private_rules = self._compile_private_rules()

    def _compile_private_rules(self) -> tuple[Rule, ...]:
        rules: list[Rule] = []
        for item in self.policy["identifiers"]:
            if item["kind"] == "literal":
                pattern = re.compile(re.escape(item["value"]))
            else:
                pattern = re.compile(item["value"])
            rules.append(Rule(item["id"], "private-identifier", item["severity"], pattern))
        return tuple(rules)

    def add_coverage(self, surface: str, status: str, reason: str = "", object_count: int = 0) -> None:
        self.coverage.append(Coverage(surface, status, reason, object_count))

    def _handling_status(self, rule_id: str, object_id: str, severity: str, legal: bool) -> tuple[str, str]:
        if legal:
            return "review", "review"
        for approval in self.policy["approved_locations"]:
            if approval["rule_id"] == rule_id and approval["object"] == object_id:
                return severity, "approved"
        now = dt.datetime.now(dt.timezone.utc)
        for exception in self.policy["exceptions"]:
            if exception["rule_id"] == rule_id and exception["object"] == object_id:
                expires = dt.datetime.fromisoformat(exception["expires_at"].replace("Z", "+00:00"))
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=dt.timezone.utc)
                if expires > now:
                    return severity, "excepted"
        return severity, severity

    def add_finding(
        self,
        *,
        surface: str,
        object_id: str,
        location: str,
        rule: Rule,
        raw_value: str | None,
        legal: bool,
    ) -> None:
        if len(self.findings) >= MAX_FINDINGS:
            if not any(item.reason == "finding-limit-exceeded" for item in self.coverage):
                self.add_coverage(surface, "tool_failed", "finding-limit-exceeded")
            return
        severity, status = self._handling_status(rule.rule_id, object_id, rule.severity, legal)
        key = (object_id, location, rule.rule_id, status)
        if key not in self._finding_keys:
            self._finding_keys.add(key)
            self.findings.append(
                Finding(self.repository, surface, object_id, location, rule.rule_id, rule.category, severity, status, legal)
            )
        if self.collect_raw and raw_value is not None:
            candidate_key = (self.repository, surface, object_id, rule.rule_id, raw_value)
            if candidate_key not in self._candidate_keys:
                self._candidate_keys.add(candidate_key)
                self.raw_candidates.append(
                    {
                        "repository": self.repository,
                        "surface": surface,
                        "object": object_id,
                        "location": location,
                        "rule_id": rule.rule_id,
                        "severity": severity,
                        "raw_value": raw_value,
                    }
                )

    def binary_is_approved(self, object_id: str, data: bytes) -> bool:
        digest = sha256_bytes(data)
        return any(item["object"] == object_id and item["sha256"] == digest for item in self.policy["binary_approvals"])


def is_legal_path(path: str) -> bool:
    name = Path(path.replace("\\", "/")).name.lower()
    return name in LEGAL_NAMES or name.startswith("license.") or name.startswith("notice.")


def line_and_column(newlines: array[int], offset: int) -> tuple[int, int]:
    line_index = bisect.bisect_left(newlines, offset)
    line = line_index + 1
    previous = newlines[line_index - 1] if line_index else -1
    column = offset - previous
    return line, column


def is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("{}[]()<>").lower()
    if normalized in PLACEHOLDER_VALUES:
        return True
    return any(token in normalized for token in ("example", "placeholder", "redacted", "replace_me", "replace-me", "your_"))


def rule_can_match(rule_id: str, text: str, lowered: str) -> bool:
    """Avoid running expensive regex engines when a required literal is absent."""
    if rule_id == "credential.private-key":
        return "private key" in lowered
    if rule_id == "credential.assignment":
        return any(token in lowered for token in ("password", "passwd", "pwd", "secret", "token", "api_key", "api-key", "cookie", "session"))
    if rule_id == "credential.database-uri":
        return "://" in text and any(scheme in lowered for scheme in ("postgres", "mysql", "mariadb", "mongodb", "redis", "mssql"))
    if rule_id == "credential.signed-url":
        return "http" in lowered and any(token in lowered for token in ("signature", "sig=", "access_token", "token="))
    if rule_id == "identity.email":
        return "@" in text
    if rule_id == "identity.phone":
        return any(symbol in text for symbol in ("+", "(", ")")) or bool(re.search(r"\d{3}[ .-]\d{3}[ .-]\d{4}", text))
    if rule_id == "identity.uid":
        return any(token in lowered for token in ("uid", "user_id", "user-id", "account_id", "account-id", "device_id", "device-id", "contact_id", "contact-id"))
    if rule_id == "identity.address-cn":
        return bool(re.search(r"[0-9]", text)) and any(token in text for token in ("省", "市", "自治区", "区", "县", "镇", "乡", "街道"))
    if rule_id == "identity.address-us":
        return any(token in lowered for token in (" street", " st.", " road", " rd.", " avenue", " ave.", " lane", " ln.", " drive", " dr.", " boulevard", " blvd."))
    if rule_id == "identity.aialra":
        return "aialra" in lowered
    if rule_id == "identity.aialra-confusable":
        return "aialra" in lowered or any(character in text for character in "ΑАΙІі")
    if rule_id == "infrastructure.ipv4":
        return "." in text and bool(re.search(r"[0-9]", text))
    if rule_id == "infrastructure.mac":
        return ":" in text or "-" in text
    if rule_id == "infrastructure.windows-path":
        return ":\\" in text
    if rule_id == "infrastructure.unix-home":
        return "/home/" in text or "/Users/" in text
    if rule_id == "infrastructure.url":
        return "http://" in lowered or "https://" in lowered
    return True


def scan_text(state: ScanState, text: str, *, surface: str, object_id: str, display_path: str) -> None:
    legal = is_legal_path(display_path)
    newlines: array[int] | None = None
    lowered = text.lower()
    private_aialra = any(rule.rule_id != "identity.aialra" and rule.pattern.pattern == re.escape("AIALRA") for rule in state._private_rules)
    generic_rules = tuple(rule for rule in GENERIC_RULES if not (private_aialra and rule.rule_id == "identity.aialra"))
    for rule in (*generic_rules, *state._private_rules):
        if not rule_can_match(rule.rule_id, text, lowered):
            continue
        for match in rule.pattern.finditer(text):
            raw = match.group(rule.value_group)
            if rule.rule_id == "credential.assignment" and is_placeholder(raw):
                continue
            if rule.rule_id == "identity.aialra-confusable" and raw.lower() == "aialra":
                continue
            if rule.rule_id == "identity.email" and raw.lower().endswith("@example.invalid"):
                continue
            if rule.rule_id == "infrastructure.url" and re.match(r"(?i)^https?://(?:[^/]+\.)?example\.invalid(?:[/:?#]|$)", raw):
                continue
            if newlines is None:
                newlines = array("I", (newline.start() for newline in re.finditer("\n", text)))
            line, column = line_and_column(newlines, match.start())
            state.add_finding(
                surface=surface,
                object_id=object_id,
                location=f"{display_path}:{line}:{column}",
                rule=rule,
                raw_value=raw,
                legal=legal,
            )


def decode_text(data: bytes) -> str | None:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            decoded = data.decode("utf-8", errors="replace")
        except Exception:
            return None
        if decoded.count("\ufffd") / max(1, len(decoded)) > 0.01:
            return None
        return decoded


def scan_zip(
    state: ScanState,
    data: bytes,
    *,
    surface: str,
    object_id: str,
    display_path: str,
    depth: int,
    office: bool = False,
) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                state.add_coverage(surface, "tool_failed", f"archive-member-limit:{object_id}")
                return
            expanded = sum(info.file_size for info in infos)
            if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                state.add_coverage(surface, "tool_failed", f"archive-expansion-limit:{object_id}")
                return
            if any(info.flag_bits & 0x1 for info in infos):
                state.add_coverage(surface, "unreadable", f"encrypted-archive:{object_id}")
                return
            for info in infos:
                if info.is_dir():
                    continue
                member = info.filename.replace("\\", "/")
                if member.startswith("/") or ".." in Path(member).parts:
                    state.add_coverage(surface, "unreadable", f"unsafe-archive-path:{object_id}")
                    continue
                member_data = archive.read(info)
                member_object = f"{object_id}!{member}"
                member_display = f"{display_path}!{member}"
                if office and not member.lower().endswith((".xml", ".rels", ".txt", ".csv", ".json")):
                    continue
                scan_bytes(
                    state,
                    member_data,
                    surface=surface,
                    object_id=member_object,
                    display_path=member_display,
                    depth=depth + 1,
                )
    except (zipfile.BadZipFile, RuntimeError, OSError):
        state.add_coverage(surface, "unreadable", f"invalid-zip:{object_id}")


def scan_tar(
    state: ScanState,
    data: bytes,
    *,
    surface: str,
    object_id: str,
    display_path: str,
    depth: int,
) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                state.add_coverage(surface, "tool_failed", f"archive-member-limit:{object_id}")
                return
            expanded = sum(member.size for member in members if member.isfile())
            if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                state.add_coverage(surface, "tool_failed", f"archive-expansion-limit:{object_id}")
                return
            for member in members:
                if not member.isfile():
                    continue
                member_path = member.name.replace("\\", "/")
                if member_path.startswith("/") or ".." in Path(member_path).parts:
                    state.add_coverage(surface, "unreadable", f"unsafe-archive-path:{object_id}")
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    state.add_coverage(surface, "unreadable", f"archive-member-unreadable:{object_id}")
                    continue
                scan_bytes(
                    state,
                    extracted.read(),
                    surface=surface,
                    object_id=f"{object_id}!{member_path}",
                    display_path=f"{display_path}!{member_path}",
                    depth=depth + 1,
                )
    except (tarfile.TarError, OSError):
        state.add_coverage(surface, "unreadable", f"invalid-tar:{object_id}")


def scan_bytes(
    state: ScanState,
    data: bytes,
    *,
    surface: str,
    object_id: str,
    display_path: str,
    depth: int = 0,
) -> None:
    if len(data) > DEFAULT_MAX_FILE_BYTES:
        state.add_coverage(surface, "unreadable", f"oversized-object:{object_id}")
        return
    suffix = Path(display_path.split("!")[-1]).suffix.lower()
    if suffix in DATABASE_SUFFIXES:
        database_rule = Rule("data.database-artifact", "data", "block", re.compile(r"$^"))
        state.add_finding(
            surface=surface,
            object_id=object_id,
            location=display_path,
            rule=database_rule,
            raw_value=None,
            legal=is_legal_path(display_path),
        )
    if depth > MAX_ARCHIVE_DEPTH:
        state.add_coverage(surface, "tool_failed", f"archive-depth-limit:{object_id}")
        return
    if suffix in OFFICE_SUFFIXES:
        scan_zip(state, data, surface=surface, object_id=object_id, display_path=display_path, depth=depth, office=True)
        return
    if suffix == ".zip":
        scan_zip(state, data, surface=surface, object_id=object_id, display_path=display_path, depth=depth)
        return
    if suffix in {".tar", ".tgz", ".gz", ".bz2", ".xz"}:
        scan_tar(state, data, surface=surface, object_id=object_id, display_path=display_path, depth=depth)
        return
    if suffix in {".7z", ".rar"}:
        if not state.binary_is_approved(object_id, data):
            state.add_coverage(surface, "unreadable", f"unsupported-archive:{object_id}")
        return
    if suffix in IMAGE_SUFFIXES | {".pdf"} | OPAQUE_SUFFIXES:
        if not state.binary_is_approved(object_id, data):
            state.add_coverage(surface, "unreadable", f"binary-review-required:{object_id}")
        return
    text = decode_text(data)
    if text is None:
        if not state.binary_is_approved(object_id, data):
            state.add_coverage(surface, "unreadable", f"opaque-binary:{object_id}")
        return
    scan_text(state, text, surface=surface, object_id=object_id, display_path=display_path)


def iter_working_tree(source: Path) -> Iterable[tuple[str, Path]]:
    git_files = run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], source, text=False)
    if git_files.returncode == 0:
        for raw in git_files.stdout.split(b"\x00"):
            if raw:
                relative = raw.decode("utf-8", errors="surrogateescape")
                yield relative, source / relative
        return
    for path in source.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        yield path.relative_to(source).as_posix(), path


def scan_working_tree(state: ScanState, source: Path) -> None:
    count = 0
    for relative, path in iter_working_tree(source):
        count += 1
        object_id = f"working-tree:{relative}"
        if any(fnmatch.fnmatch(relative, pattern) for pattern in state.policy["blocked_paths"]):
            rule = Rule("policy.blocked-path", "data", "block", re.compile(r"$^"))
            state.add_finding(surface="working-tree", object_id=object_id, location=relative, rule=rule, raw_value=None, legal=is_legal_path(relative))
        try:
            if path.is_symlink():
                target = os.readlink(path)
                scan_text(state, target, surface="working-tree", object_id=object_id, display_path=relative)
                resolved = path.resolve()
                try:
                    resolved.relative_to(source.resolve())
                except ValueError:
                    state.add_coverage("working-tree", "unreadable", f"external-symlink:{object_id}")
                continue
            scan_bytes(state, path.read_bytes(), surface="working-tree", object_id=object_id, display_path=relative)
        except (OSError, PermissionError):
            state.add_coverage("working-tree", "permission_denied", f"file-unreadable:{object_id}")
    state.add_coverage("working-tree", "checked", object_count=count)


def git_head(source: Path) -> str | None:
    result = run(["git", "rev-parse", "HEAD"], source)
    return result.stdout.strip() if result.returncode == 0 else None


def scan_git_history(state: ScanState, source: Path, *, time_limit_seconds: int | None = None) -> None:
    started = time.monotonic()
    shallow = run(["git", "rev-parse", "--is-shallow-repository"], source)
    if shallow.returncode != 0:
        state.add_coverage("git-history", "tool_failed", "git-repository-unavailable")
        return
    if shallow.stdout.strip().lower() == "true":
        state.add_coverage("git-history", "unreadable", "shallow-history")
        return
    objects = run(["git", "rev-list", "--objects", "--all"], source, text=False)
    if objects.returncode != 0:
        state.add_coverage("git-history", "tool_failed", "git-object-enumeration-failed")
        return
    object_entries: list[tuple[str, str]] = []
    for line in objects.stdout.splitlines():
        if not line:
            continue
        oid_raw, separator, path_raw = line.partition(b" ")
        oid = oid_raw.decode("ascii", errors="ignore")
        path = path_raw.decode("utf-8", errors="replace") if separator else ""
        if oid:
            object_entries.append((oid, path))
    try:
        process = subprocess.Popen(
            ["git", "cat-file", "--batch"],
            cwd=str(source),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None and process.stdout is not None
        blob_count = 0
        completed = True
        for oid, path in object_entries:
            if time_limit_seconds is not None and time.monotonic() - started > time_limit_seconds:
                state.add_coverage("git-history", "tool_failed", "git-history-time-limit-exceeded", blob_count)
                completed = False
                break
            process.stdin.write(f"{oid}\n".encode("ascii"))
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii", errors="replace").strip()
            parts = header.split()
            if len(parts) < 3 or parts[1] == "missing":
                state.add_coverage("git-history", "unreadable", f"git-object-unreadable:{oid}")
                continue
            object_type, size_text = parts[1], parts[2]
            try:
                size = int(size_text)
            except ValueError:
                state.add_coverage("git-history", "tool_failed", f"git-object-header-invalid:{oid}")
                continue
            content = process.stdout.read(size)
            process.stdout.read(1)
            if object_type != "blob":
                continue
            blob_count += 1
            display = path or f"blob-{oid[:12]}"
            scan_bytes(
                state,
                content,
                surface="git-history",
                object_id=f"git:{oid}:{display}",
                display_path=display,
            )
        process.stdin.close()
        if not completed:
            process.terminate()
        process.wait(timeout=30)
        process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        if not completed:
            return
        # Commit authors, committers, and messages are separate sensitive surfaces from file blobs.
        log = run(
            ["git", "log", "--all", "-z", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x00%x1e"],
            source,
            text=False,
        )
        if log.returncode != 0:
            state.add_coverage("git-history", "tool_failed", "git-commit-metadata-enumeration-failed")
        else:
            for record in log.stdout.split(b"\x1e\x00"):
                fields = record.strip(b"\x00").split(b"\x00", 5)
                if len(fields) != 6:
                    continue
                commit, author_name, author_email, committer_name, committer_email, message = fields
                commit_id = commit.decode("ascii", errors="ignore")
                values = (
                    ("author-name", author_name),
                    ("author-email", author_email),
                    ("committer-name", committer_name),
                    ("committer-email", committer_email),
                    ("message", message),
                )
                for field_name, raw_value in values:
                    scan_text(
                        state,
                        raw_value.decode("utf-8", errors="replace"),
                        surface="git-history",
                        object_id=f"git-commit:{commit_id}:{field_name}",
                        display_path=f"git-commit:{commit_id}:{field_name}",
                    )
        state.add_coverage("git-history", "checked", object_count=blob_count)
    except (OSError, subprocess.SubprocessError, AssertionError):
        state.add_coverage("git-history", "tool_failed", "git-cat-file-failed")


def scan_submodules(state: ScanState, source: Path) -> None:
    raw_log = run(["git", "log", "--all", "--format=", "--raw", "--no-abbrev"], source)
    if raw_log.returncode != 0:
        state.add_coverage("submodules", "tool_failed", "submodule-history-enumeration-failed")
        return
    pointers = sum(1 for line in raw_log.stdout.splitlines() if line.startswith(":") and "160000" in line.split("\t", 1)[0])
    modules = run(["git", "show", "HEAD:.gitmodules"], source)
    if modules.returncode == 0:
        scan_text(state, modules.stdout, surface="submodules", object_id="submodule-config:HEAD", display_path=".gitmodules")
    status = "checked" if pointers or modules.returncode == 0 else "not_present"
    state.add_coverage("submodules", status, object_count=pointers)


def git_dir(source: Path) -> Path | None:
    result = run(["git", "rev-parse", "--git-dir"], source)
    if result.returncode != 0:
        return None
    path = Path(result.stdout.strip())
    return (source / path).resolve() if not path.is_absolute() else path.resolve()


def scan_lfs(state: ScanState, source: Path, *, fetch: bool = False) -> None:
    if shutil.which("git-lfs") is None and run(["git", "lfs", "version"], source).returncode != 0:
        state.add_coverage("git-lfs", "tool_failed", "git-lfs-unavailable")
        return
    listing = run(["git", "lfs", "ls-files", "--all", "--long"], source)
    if listing.returncode != 0:
        state.add_coverage("git-lfs", "tool_failed", "git-lfs-enumeration-failed")
        return
    entries: list[tuple[str, str]] = []
    for line in listing.stdout.splitlines():
        match = re.match(r"([0-9a-f]{64})\s+[-*]\s+(.+)$", line.strip())
        if match:
            entries.append((match.group(1), match.group(2)))
    if not entries:
        state.add_coverage("git-lfs", "not_present")
        return
    if fetch:
        fetched = run(["git", "lfs", "fetch", "--all", "origin"], source)
        if fetched.returncode != 0:
            state.add_coverage("git-lfs", "permission_denied", "git-lfs-fetch-failed", len(entries))
            return
    repository_git_dir = git_dir(source)
    if repository_git_dir is None:
        state.add_coverage("git-lfs", "tool_failed", "git-directory-unavailable", len(entries))
        return
    missing = 0
    for oid, path in entries:
        object_path = repository_git_dir / "lfs" / "objects" / oid[:2] / oid[2:4] / oid
        if not object_path.exists():
            missing += 1
            continue
        scan_bytes(
            state,
            object_path.read_bytes(),
            surface="git-lfs",
            object_id=f"lfs:{oid}:{path}",
            display_path=path,
        )
    if missing:
        state.add_coverage("git-lfs", "unreadable", "missing-lfs-objects", len(entries))
    else:
        state.add_coverage("git-lfs", "checked", object_count=len(entries))


def gitleaks_asset_name() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    architecture = "arm64" if machine in {"arm64", "aarch64"} else "x64"
    if system == "windows":
        return f"gitleaks_{GITLEAKS_VERSION}_windows_{architecture}.zip", "gitleaks.exe"
    if system == "darwin":
        return f"gitleaks_{GITLEAKS_VERSION}_darwin_{architecture}.tar.gz", "gitleaks"
    if system == "linux":
        return f"gitleaks_{GITLEAKS_VERSION}_linux_{architecture}.tar.gz", "gitleaks"
    raise RuntimeError("Unsupported Gitleaks platform")


def ensure_gitleaks() -> Path:
    asset_name, executable_name = gitleaks_asset_name()
    cache = get_codex_home() / "cache" / "github-safe-publish" / f"gitleaks-{GITLEAKS_VERSION}"
    executable = cache / executable_name
    if executable.exists():
        return executable
    cache.mkdir(parents=True, exist_ok=True)
    base = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}"
    archive_path = cache / asset_name
    checksums_path = cache / "gitleaks_checksums.txt"
    request_headers = {"User-Agent": "github-safe-publish"}
    for url, destination in ((f"{base}/{asset_name}", archive_path), (f"{base}/gitleaks_{GITLEAKS_VERSION}_checksums.txt", checksums_path)):
        with urllib.request.urlopen(urllib.request.Request(url, headers=request_headers), timeout=120) as response:
            data = response.read()
        destination.write_bytes(data)
    expected: str | None = None
    for line in checksums_path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-1].lstrip("*") == asset_name:
            expected = fields[0].lower()
            break
    if expected is None or sha256_bytes(archive_path.read_bytes()) != expected:
        raise RuntimeError("Gitleaks release checksum verification failed")
    if asset_name.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as archive:
            archive.extract(executable_name, cache)
    else:
        with tarfile.open(archive_path, "r:gz") as archive:
            member = next((item for item in archive.getmembers() if Path(item.name).name == executable_name), None)
            if member is None:
                raise RuntimeError("Gitleaks executable is missing from the verified archive")
            member.name = executable_name
            archive.extract(member, cache, filter="data")
    if os.name != "nt":
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    return executable


def run_gitleaks(state: ScanState, source: Path, binary: Path | None = None) -> None:
    try:
        executable = binary or ensure_gitleaks()
    except Exception:
        state.add_coverage("gitleaks", "tool_failed", "gitleaks-install-or-verification-failed")
        return
    with tempfile.TemporaryDirectory(prefix="safe-publish-gitleaks-") as temporary:
        report = Path(temporary) / "report.json"
        result = run(
            [
                str(executable),
                "git",
                "--no-banner",
                "--redact=100",
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--timeout",
                "300",
                str(source),
            ]
        )
        if result.returncode not in {0, 1}:
            state.add_coverage("gitleaks", "tool_failed", f"gitleaks-exit-{result.returncode}")
            return
        records: list[dict[str, Any]] = []
        if report.exists():
            try:
                records = json.loads(report.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                state.add_coverage("gitleaks", "tool_failed", "gitleaks-report-invalid")
                return
        for record in records:
            path = str(record.get("File", "unknown"))
            commit = str(record.get("Commit", "working-tree"))
            rule_id = str(record.get("RuleID", "gitleaks.unknown"))
            line = int(record.get("StartLine", 0) or 0)
            rule = Rule(f"gitleaks.{rule_id}", "credential", "block", re.compile(r"$^"))
            state.add_finding(
                surface="gitleaks",
                object_id=f"gitleaks:{commit}:{path}",
                location=f"{path}:{line}",
                rule=rule,
                raw_value=None,
                legal=is_legal_path(path),
            )
        state.add_coverage("gitleaks", "checked", object_count=len(records))


def scan_metadata(state: ScanState, metadata: dict[str, Any]) -> None:
    count = 0
    for field in ("description", "homepage"):
        value = metadata.get(field)
        if isinstance(value, str) and value:
            count += 1
            scan_text(state, value, surface="repository-metadata", object_id=f"metadata:{field}", display_path=field)
    topics = metadata.get("topics") or []
    if isinstance(topics, list):
        for index, value in enumerate(topics):
            if isinstance(value, str):
                count += 1
                scan_text(state, value, surface="repository-metadata", object_id=f"metadata:topic:{index}", display_path=f"topic:{index}")
    state.add_coverage("repository-metadata", "checked" if count else "not_present", object_count=count)


def consolidated_coverage(coverage: list[Coverage]) -> list[dict[str, Any]]:
    return [item.as_dict() for item in sorted(coverage, key=lambda value: (value.surface, value.status, value.reason))]


def decision_for(state: ScanState, *, force_incomplete: bool = False) -> str:
    if force_incomplete or any(item.status not in {"checked", "not_present"} for item in state.coverage):
        return "incomplete"
    unresolved = [item for item in state.findings if item.status not in {"approved", "excepted"}]
    if any(item.status == "block" for item in unresolved):
        return "block"
    if any(item.status == "review" for item in unresolved):
        return "review"
    return "pass"


def sorted_findings(state: ScanState) -> list[dict[str, Any]]:
    return [
        item.public_dict()
        for item in sorted(
            state.findings,
            key=lambda value: (value.repository, value.surface, value.object, value.location, value.rule_id, value.status),
        )
    ]


def gate_report(state: ScanState, source: Path, policy: dict[str, Any] | None, *, force_incomplete: bool = False) -> dict[str, Any]:
    decision = decision_for(state, force_incomplete=force_incomplete)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "decision": decision,
        "repository": state.repository,
        "source_commit": git_head(source),
        "gitleaks_version": GITLEAKS_VERSION,
        "policy_fingerprint": policy_fingerprint(policy),
        "coverage": consolidated_coverage(state.coverage),
        "findings": sorted_findings(state),
        "summary": {
            "finding_count": len(state.findings),
            "block_count": sum(item.status == "block" for item in state.findings),
            "review_count": sum(item.status == "review" for item in state.findings),
            "approved_count": sum(item.status in {"approved", "excepted"} for item in state.findings),
            "coverage_gap_count": sum(item.status not in {"checked", "not_present"} for item in state.coverage),
        },
    }


def scan_release_paths(state: ScanState, release_paths: list[Path]) -> None:
    if not release_paths:
        state.add_coverage("release-assets", "not_present")
        return
    checked = 0
    for path in release_paths:
        object_id = f"release:proposed:{path.name}"
        try:
            scan_bytes(state, path.read_bytes(), surface="release-assets", object_id=object_id, display_path=path.name)
            checked += 1
        except (OSError, PermissionError):
            state.add_coverage("release-assets", "permission_denied", f"release-asset-unreadable:{object_id}")
    state.add_coverage("release-assets", "checked", object_count=checked)


def command_gate(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve()
    repository = args.repository or source.name
    policy: dict[str, Any] | None = None
    force_incomplete = bool(args.generic_only)
    policy_error = False
    try:
        if args.policy:
            policy = load_policy(Path(args.policy), source)
        elif args.policy_b64_env:
            policy = load_policy_from_env(args.policy_b64_env)
        elif not args.generic_only:
            policy_error = True
    except (OSError, ValueError):
        policy_error = True
    state = ScanState(repository, policy)
    if policy_error:
        state.add_coverage("private-policy", "unreadable", "private-policy-unavailable-or-invalid")
    elif args.generic_only:
        state.add_coverage("private-policy", "unreadable", "generic-only-cannot-pass-publication")
    else:
        state.add_coverage("private-policy", "checked", object_count=len(policy["identifiers"]) if policy else 0)
    if not source.is_dir():
        state.add_coverage("working-tree", "unreadable", "source-directory-unavailable")
    else:
        scan_working_tree(state, source)
        scan_git_history(state, source)
        scan_submodules(state, source)
        scan_lfs(state, source)
        run_gitleaks(state, source, Path(args.gitleaks_path).resolve() if args.gitleaks_path else None)
    scan_release_paths(state, [Path(item).expanduser().resolve() for item in args.release_asset])
    report = gate_report(state, source, policy, force_incomplete=force_incomplete)
    write_json(Path(args.report), report)
    print(json.dumps({"decision": report["decision"], **report["summary"]}, sort_keys=True))
    return {"pass": 0, "review": 2, "block": 3, "incomplete": 4}[report["decision"]]


def command_policy_candidates(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve()
    output = ensure_private_path(Path(args.output))
    state = ScanState(args.repository or source.name, empty_policy(), collect_raw=True)
    scan_working_tree(state, source)
    candidate_document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "source_commit": git_head(source),
        "candidate_count": len(state.raw_candidates),
        "candidates": sorted(state.raw_candidates, key=lambda item: (item["repository"], item["object"], item["rule_id"], item["location"])),
    }
    write_json(output, candidate_document, private=True)
    print(json.dumps({"candidate_count": len(state.raw_candidates), "coverage_gap_count": sum(item.status not in {"checked", "not_present"} for item in state.coverage)}, sort_keys=True))
    return 0 if not any(item.status not in {"checked", "not_present"} for item in state.coverage) else 4


def safe_extract_git_archive(data: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        destination_resolved = destination.resolve()
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            try:
                target.relative_to(destination_resolved)
            except ValueError as exc:
                raise ValueError("Git archive contains an unsafe path") from exc
        archive.extractall(destination, filter="data")


def apply_replacements(destination: Path, policy: dict[str, Any]) -> dict[str, Any]:
    identifiers = {item["id"]: item for item in policy["identifiers"]}
    mappings = {item["identifier_id"]: item["replacement"] for item in policy["replacements"]}
    changed: list[dict[str, Any]] = []
    for relative, path in iter_working_tree(destination):
        if is_legal_path(relative) or path.is_symlink():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        text = decode_text(data)
        if text is None:
            continue
        updated = text
        replacement_count = 0
        for identifier_id, replacement in mappings.items():
            identifier = identifiers[identifier_id]
            if identifier["kind"] == "literal":
                count = updated.count(identifier["value"])
                updated = updated.replace(identifier["value"], replacement)
            else:
                updated, count = re.subn(identifier["value"], replacement, updated)
            replacement_count += count
        if updated != text:
            path.write_text(updated, encoding="utf-8", newline="\n")
            changed.append({"path": relative, "replacement_count": replacement_count})
    return {"changed_file_count": len(changed), "changed_files": changed}


def command_prepare(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve()
    destination = Path(args.destination).expanduser().resolve()
    if destination.exists():
        raise ValueError("Destination already exists; use a new disposable publication path")
    try:
        destination.relative_to(source)
    except ValueError:
        pass
    else:
        raise ValueError("Destination must be outside the private source directory")
    policy = load_policy(Path(args.policy), source)
    commit_check = run(["git", "rev-parse", "--verify", f"{args.commit}^{{commit}}"], source)
    if commit_check.returncode != 0:
        raise ValueError("Source commit is unavailable")
    exact_commit = commit_check.stdout.strip()
    if args.mode == "preserve-history":
        cloned = run(["git", "clone", "--no-hardlinks", str(source), str(destination)])
        if cloned.returncode != 0:
            raise RuntimeError("Unable to create isolated publication clone")
        checked_out = run(["git", "checkout", "--detach", exact_commit], destination)
        if checked_out.returncode != 0:
            raise RuntimeError("Unable to check out the exact source commit")
    else:
        destination.mkdir(parents=True)
        archived = run(["git", "archive", "--format=tar", exact_commit], source, text=False)
        if archived.returncode != 0:
            raise RuntimeError("Unable to export the exact source commit")
        safe_extract_git_archive(archived.stdout, destination)
        initialized = run(["git", "init", "-b", "main"], destination)
        if initialized.returncode != 0:
            raise RuntimeError("Unable to initialize the clean publication root")
    replacement_report = apply_replacements(destination, policy)
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "source_commit": exact_commit,
        "mode": args.mode,
        "destination": str(destination),
        "policy_fingerprint": policy_fingerprint(policy),
        **replacement_report,
    }
    write_json(Path(args.report), report, private=True)
    print(json.dumps({"source_commit": exact_commit, "mode": args.mode, "changed_file_count": replacement_report["changed_file_count"]}, sort_keys=True))
    return 0


def gh_json(endpoint: str) -> tuple[Any | None, str | None]:
    result = run(["gh", "api", "--paginate", endpoint])
    if result.returncode != 0:
        lowered = result.stderr.lower()
        reason = "permission_denied" if "403" in lowered or "resource not accessible" in lowered else "tool_failed"
        return None, reason
    text = result.stdout.strip()
    try:
        if not text:
            return [], None
        decoder = json.JSONDecoder()
        values: list[Any] = []
        index = 0
        while index < len(text):
            value, next_index = decoder.raw_decode(text, index)
            values.extend(value if isinstance(value, list) else [value])
            index = next_index
            while index < len(text) and text[index].isspace():
                index += 1
        return values, None
    except json.JSONDecodeError:
        return None, "tool_failed"


def prepare_mirror(owner: str, repository: str, local_source: Path | None, mirror: Path) -> tuple[Path | None, str | None]:
    remote_url = f"https://github.com/{owner}/{repository}.git"
    if not mirror.exists():
        mirror.parent.mkdir(parents=True, exist_ok=True)
        if local_source and local_source.exists():
            cloned = run(["git", "clone", "--mirror", "--shared", str(local_source), str(mirror)])
            if cloned.returncode == 0:
                run(["git", "remote", "set-url", "origin", remote_url], mirror)
        else:
            cloned = run(["git", "clone", "--mirror", remote_url, str(mirror)])
        if cloned.returncode != 0:
            error_text = cloned.stderr.decode("utf-8", errors="ignore") if isinstance(cloned.stderr, bytes) else cloned.stderr
            denied = "403" in error_text or "authentication" in error_text.lower()
            return None, "permission_denied" if denied else "tool_failed"
    fetched = run(["git", "fetch", "--prune", "--tags", "origin", "+refs/*:refs/*"], mirror)
    if fetched.returncode != 0:
        return None, "permission_denied" if "403" in fetched.stderr or "authentication" in fetched.stderr.lower() else "tool_failed"
    return mirror, None


def download_release_assets(owner: str, repository: str, state: ScanState, download_root: Path) -> None:
    releases, error = gh_json(f"repos/{owner}/{repository}/releases?per_page=100")
    if error:
        state.add_coverage("release-assets", error, "release-enumeration-failed")
        return
    assets: list[tuple[int, str, str, int]] = []
    for release in releases or []:
        release_id = int(release.get("id", 0))
        for asset in release.get("assets", []):
            assets.append((release_id, str(asset.get("name", "asset")), str(asset.get("url", "")), int(asset.get("size", 0))))
    if not assets:
        state.add_coverage("release-assets", "not_present")
        return
    checked = 0
    for release_id, name, url, size in assets:
        object_id = f"release:{release_id}:{name}"
        if size > DEFAULT_MAX_FILE_BYTES:
            state.add_coverage("release-assets", "unreadable", f"oversized-release-asset:{object_id}")
            continue
        result = run(["gh", "api", url, "-H", "Accept: application/octet-stream"], text=False)
        if result.returncode != 0:
            state.add_coverage("release-assets", "permission_denied", f"release-asset-download-failed:{object_id}")
            continue
        destination = download_root / str(release_id) / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(result.stdout)
        scan_bytes(state, result.stdout, surface="release-assets", object_id=object_id, display_path=name)
        checked += 1
    state.add_coverage("release-assets", "checked", object_count=checked)


def repository_security(owner: str, name: str) -> dict[str, Any]:
    detail, error = gh_json(f"repos/{owner}/{name}")
    if error or not detail:
        return {"status": error or "tool_failed"}
    data = detail[0] if isinstance(detail, list) else detail
    security = data.get("security_and_analysis") or {}
    return {
        "status": "checked",
        "secret_scanning": (security.get("secret_scanning") or {}).get("status", "unavailable"),
        "secret_scanning_push_protection": (security.get("secret_scanning_push_protection") or {}).get("status", "unavailable"),
    }


def aggregate_local_inventory(local_map: dict[str, Path]) -> dict[str, int]:
    gitleaks_count = 0
    ci_security_count = 0
    env_ignored_count = 0
    for repository in local_map.values():
        if (repository / ".gitleaks.toml").exists():
            gitleaks_count += 1
        workflows = repository / ".github" / "workflows"
        security_workflow = False
        if workflows.exists():
            for workflow in (*workflows.glob("*.yml"), *workflows.glob("*.yaml")):
                try:
                    content = workflow.read_text(encoding="utf-8", errors="replace").lower()
                except OSError:
                    continue
                if any(token in content for token in ("gitleaks", "secret scan", "privacy", "sensitive")):
                    security_workflow = True
                    break
        if security_workflow:
            ci_security_count += 1
        gitignore = repository / ".gitignore"
        if gitignore.exists():
            try:
                ignored_lines = {line.strip() for line in gitignore.read_text(encoding="utf-8", errors="replace").splitlines()}
            except OSError:
                ignored_lines = set()
            if any(line in ignored_lines for line in (".env", "**/.env", ".env.*", "*.env")):
                env_ignored_count += 1
    return {
        "synchronized_repository_count": len(local_map),
        "gitleaks_config_repository_count": gitleaks_count,
        "ci_security_workflow_repository_count": ci_security_count,
        "env_ignored_repository_count": env_ignored_count,
    }


def command_audit_fleet(args: argparse.Namespace) -> int:
    root = private_root()
    output = ensure_private_path(Path(args.output))
    candidates_output = ensure_private_path(Path(args.candidates_output))
    local_root = Path(args.local_root).expanduser().resolve() if args.local_root else None
    policy = load_policy(Path(args.policy)) if args.policy else empty_policy()
    repos, error = gh_json("user/repos?affiliation=owner&per_page=100&sort=full_name")
    if error:
        raise RuntimeError("Unable to enumerate the authenticated GitHub repository fleet")
    owned = [repo for repo in repos if (repo.get("owner") or {}).get("login", "").lower() == args.owner.lower()]
    owned_by_id = {int(repo["id"]): repo for repo in owned}
    repositories = [owned_by_id[key] for key in sorted(owned_by_id)]
    local_map: dict[str, Path] = {}
    if local_root and local_root.exists():
        for child in local_root.iterdir():
            if child.is_dir() and (child / ".git").exists():
                local_map[child.name.lower()] = child
    detailed: list[dict[str, Any]] = []
    all_candidates: list[dict[str, Any]] = []
    for index, repo in enumerate(repositories, start=1):
        name = str(repo["name"])
        state = ScanState(name, policy, collect_raw=True)
        mirror = root / "mirrors" / f"{int(repo['id'])}.git"
        prepared, mirror_error = prepare_mirror(args.owner, name, local_map.get(name.lower()), mirror)
        if mirror_error or prepared is None:
            state.add_coverage("git-history", mirror_error or "tool_failed", "mirror-preparation-failed")
            state.add_coverage("git-lfs", "unreadable", "git-mirror-unavailable")
            state.add_coverage("submodules", "unreadable", "git-mirror-unavailable")
            state.add_coverage("gitleaks", "unreadable", "git-mirror-unavailable")
        else:
            scan_git_history(state, prepared, time_limit_seconds=args.history_time_limit_seconds)
            scan_submodules(state, prepared)
            scan_lfs(state, prepared, fetch=True)
            run_gitleaks(state, prepared, Path(args.gitleaks_path).resolve() if args.gitleaks_path else None)
        scan_metadata(state, repo)
        download_release_assets(args.owner, name, state, root / "release-assets" / str(repo["id"]))
        remote_refs = run(["git", "for-each-ref", "--format=%(refname) %(objectname)"], prepared) if prepared else None
        ref_count = len(remote_refs.stdout.splitlines()) if remote_refs and remote_refs.returncode == 0 else 0
        if prepared and (not remote_refs or remote_refs.returncode != 0):
            state.add_coverage("git-refs", "tool_failed", "visible-ref-enumeration-failed")
        else:
            state.add_coverage("git-refs", "checked", object_count=ref_count)
        report = gate_report(state, prepared or mirror, policy, force_incomplete=False)
        detailed.append(
            {
                "repository_id": int(repo["id"]),
                "name": name,
                "visibility": repo.get("visibility", "private" if repo.get("private") else "public"),
                "fork": bool(repo.get("fork")),
                "archived": bool(repo.get("archived")),
                "default_branch": repo.get("default_branch"),
                "default_branch_commit": repo.get("default_branch") and run(["git", "rev-parse", f"refs/heads/{repo['default_branch']}"] , prepared).stdout.strip() if prepared else None,
                "visible_ref_count": ref_count,
                "security": repository_security(args.owner, name),
                "decision": report["decision"],
                "coverage": report["coverage"],
                "findings": report["findings"],
                "summary": report["summary"],
            }
        )
        all_candidates.extend(state.raw_candidates)
        print(json.dumps({"progress": index, "repository_count": len(repositories)}, sort_keys=True), flush=True)
    decision_counts = {decision: sum(item["decision"] == decision for item in detailed) for decision in ("pass", "review", "block", "incomplete")}
    fleet_report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "owner": args.owner,
        "repository_count": len(detailed),
        "decision_counts": decision_counts,
        "policy_fingerprint": policy_fingerprint(policy),
        "declared_exclusions": [
            "issues",
            "pull-request-text-and-comments",
            "discussions",
            "wiki",
            "github-pages",
            "historical-actions-logs-and-artifacts",
            "packages",
            "container-images",
            "caches",
            "gists",
            "external-clones",
        ],
        "repositories": detailed,
    }
    candidate_document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "owner": args.owner,
        "candidate_count": len(all_candidates),
        "candidates": sorted(all_candidates, key=lambda item: (item["repository"], item["object"], item["rule_id"], item["location"])),
    }
    write_json(output, fleet_report, private=True)
    write_json(candidates_output, candidate_document, private=True)
    if args.public_summary:
        public_summary = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": fleet_report["generated_at"],
            "owner_repository_count": len(detailed),
            "public_count": sum(item["visibility"] == "public" for item in detailed),
            "private_count": sum(item["visibility"] == "private" for item in detailed),
            "fork_count": sum(item["fork"] for item in detailed),
            "archived_count": sum(item["archived"] for item in detailed),
            "candidate_count": len(all_candidates),
            "decision_counts": decision_counts,
            "finding_counts_by_rule": {},
            "coverage_gap_counts_by_surface": {},
            "coverage_status_counts": {},
            "coverage_gap_reason_counts": {},
            "repository_security_setting_counts": {},
            "user_level_push_protection": "unknown",
            "legacy_local_inventory": aggregate_local_inventory(local_map),
        }
        for item in detailed:
            for finding in item["findings"]:
                rule_id = finding["rule_id"]
                public_summary["finding_counts_by_rule"][rule_id] = public_summary["finding_counts_by_rule"].get(rule_id, 0) + 1
            for coverage in item["coverage"]:
                status_key = f"{coverage['surface']}::{coverage['status']}"
                public_summary["coverage_status_counts"][status_key] = public_summary["coverage_status_counts"].get(status_key, 0) + 1
                if coverage["status"] not in {"checked", "not_present"}:
                    surface = coverage["surface"]
                    public_summary["coverage_gap_counts_by_surface"][surface] = public_summary["coverage_gap_counts_by_surface"].get(surface, 0) + 1
                    reason = coverage["reason"].split(":", 1)[0] if coverage["reason"] else "unspecified"
                    public_summary["coverage_gap_reason_counts"][reason] = public_summary["coverage_gap_reason_counts"].get(reason, 0) + 1
            security = item["security"]
            security_key = f"{security.get('secret_scanning', 'unknown')}::{security.get('secret_scanning_push_protection', 'unknown')}"
            public_summary["repository_security_setting_counts"][security_key] = public_summary["repository_security_setting_counts"].get(security_key, 0) + 1
        write_json(Path(args.public_summary), public_summary)
    print(json.dumps({"repository_count": len(detailed), "candidate_count": len(all_candidates), "decision_counts": decision_counts}, sort_keys=True))
    return 0 if len(detailed) == len(owned_by_id) else 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit and gate a sanitized GitHub publication without exposing raw matches")
    subcommands = parser.add_subparsers(dest="command", required=True)

    audit = subcommands.add_parser("audit-fleet", help="Audit an authenticated GitHub owner's finite repository fleet")
    audit.add_argument("--owner", required=True)
    audit.add_argument("--local-root")
    audit.add_argument("--policy")
    audit.add_argument("--output", required=True)
    audit.add_argument("--candidates-output", required=True)
    audit.add_argument("--public-summary")
    audit.add_argument("--gitleaks-path")
    audit.add_argument("--history-time-limit-seconds", type=int, default=300)
    audit.set_defaults(handler=command_audit_fleet)

    candidates = subcommands.add_parser("policy-candidates", help="Write raw candidates to the restricted local policy directory")
    candidates.add_argument("--source", required=True)
    candidates.add_argument("--repository")
    candidates.add_argument("--output", required=True)
    candidates.set_defaults(handler=command_policy_candidates)

    prepare = subcommands.add_parser("prepare", help="Create a disposable publication copy from an exact source commit")
    prepare.add_argument("--source", required=True)
    prepare.add_argument("--commit", required=True)
    prepare.add_argument("--destination", required=True)
    prepare.add_argument("--policy", required=True)
    prepare.add_argument("--mode", required=True, choices=("clean-root", "preserve-history"))
    prepare.add_argument("--report", required=True)
    prepare.set_defaults(handler=command_prepare)

    gate = subcommands.add_parser("gate", help="Fail closed unless every publication surface is clean and readable")
    gate.add_argument("--source", required=True)
    gate.add_argument("--repository")
    gate.add_argument("--policy")
    gate.add_argument("--policy-b64-env")
    gate.add_argument("--generic-only", action="store_true")
    gate.add_argument("--release-asset", action="append", default=[])
    gate.add_argument("--gitleaks-path")
    gate.add_argument("--report", required=True)
    gate.set_defaults(handler=command_gate)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, RuntimeError, ValueError) as exc:
        # The exception class is safe to expose; the message is intentionally generic.
        print(json.dumps({"decision": "incomplete", "error": exc.__class__.__name__}, sort_keys=True), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
