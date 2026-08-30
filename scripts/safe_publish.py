#!/usr/bin/env python3
"""Fail-closed repository sanitization and publication gate.

The program deliberately keeps raw matches out of process output and public reports.
Raw candidates are written only by commands that enforce the private CODEX_HOME path.
"""

from __future__ import annotations

import argparse
import atexit
from array import array
import base64
import bisect
import binascii
import dataclasses
import datetime as dt
import fnmatch
import hashlib
from html.parser import HTMLParser
import importlib
import io
import ipaddress
import json
import multiprocessing
import os
from pathlib import Path
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unicodedata
from typing import Any, Iterable
import urllib.parse
import urllib.request
import urllib.error
import warnings
import xml.etree.ElementTree as ET
import zipfile


# Pillow emits this advisory while converting some palette frames. It is not a
# coverage failure, and allowing it through would expose host installation paths.
warnings.filterwarnings(
    "ignore",
    message="Palette images with Transparency expressed in bytes should be converted to RGBA images",
    category=UserWarning,
    module=r"PIL\.Image",
)


SCHEMA_VERSION = 3
SUPPORTED_POLICY_VERSIONS = {1, 2, 3}
TOOL_VERSION = "1.1.0"
GITLEAKS_VERSION = "8.30.1"
MAX_SECRET_BYTES = 48 * 1024
DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_INLINE_TEXT_BYTES = 1 * 1024 * 1024
DEFAULT_IMAGE_OCR_BUDGET_SECONDS = 300
DEFAULT_OCR_UNIT_TIMEOUT_SECONDS = 120
DEFAULT_ARTIFACT_UNIT_TIMEOUT_SECONDS = 180
DEFAULT_ASSOCIATED_SURFACE_BUDGET_SECONDS = 300
DEFAULT_REMOTE_REQUEST_TIMEOUT_SECONDS = 60
DEFAULT_RELEASE_ASSET_BUDGET_SECONDS = 300
DEFAULT_LOCAL_FILE_BUDGET_SECONDS = 600
DEFAULT_GATE_HISTORY_BUDGET_SECONDS = 900
DEFAULT_HISTORY_CHECKPOINT_INTERVAL = 10_000
DEFAULT_GATE_WORKTREE_BUDGET_SECONDS = 900
DEFAULT_WORKTREE_CHECKPOINT_INTERVAL = 100
HISTORY_CHECKPOINT_SCHEMA_VERSION = 2
WORKTREE_CHECKPOINT_SCHEMA_VERSION = 1
OCR_CHECKPOINT_SCHEMA_VERSION = 1
DEFAULT_FINDING_PAGE_SIZE = 10_000
MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_EXPANDED_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3
MAX_ARRAY_MEMBERS = 1_024
MAX_ARRAY_ELEMENTS = 25_000_000
MAX_ARRAY_BYTES = 128 * 1024 * 1024
MAX_ARRAY_TEXT_BYTES = 5 * 1024 * 1024
MAX_RAW_CANDIDATES_PER_STATE = 100_000
MAX_PRIVATE_CANDIDATE_ATTEMPTS = 250_000
VERIFIED_GITLEAKS: set[str] = set()
PACKAGE_CACHE: dict[str, tuple[list[dict[str, Any]], str | None]] = {}
RAPID_OCR_ENGINE: Any | None = None
IMAGE_EXTRACTION_CACHE: dict[str, tuple[list[tuple[str, str]], set[str], list[tuple[str, str]]]] = {}
RESTRICTED_PRIVATE_PATHS: set[str] = set()
IN_ARTIFACT_WORKER = False
PRIVATE_ROOT_OVERRIDE: Path | None = None


class SameOriginLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        for field in ("src", "href"):
            value = values.get(field)
            if value:
                self.links.append(value)

LEGAL_NAMES = {"license", "license.md", "license.txt", "notice", "notice.md", "notice.txt", "citation.cff"}
OFFICE_SUFFIXES = {
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm", ".ppam",
}
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".ico"}
MEDIA_SUFFIXES = {".mp3", ".wav", ".flac", ".m4a", ".mp4", ".mov", ".mkv", ".webm", ".avi"}
ARCHIVE_SUFFIXES = {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar"}
DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".sql", ".dump", ".bak"}
OPAQUE_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".jar", ".wasm", ".pyc"}
NUMPY_SUFFIXES = {".npy", ".npz"}
SVG_DATA_URI_PATTERN = re.compile(r'''(?:href|xlink:href)\s*=\s*["']data:([^;,"']+);base64,([^"']+)["']''', re.IGNORECASE)
SVG_MIME_SUFFIXES = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif", "image/webp": ".webp"}
SAFE_STANDARD_URLS = {"http://www.w3.org/2000/svg", "http://www.w3.org/1999/xlink"}
RELEASE_PROFILES = {"permissive-noncritical", "strict"}
NONCRITICAL_FINDING_RULES = {
    "identity.aialra",
    "identity.aialra-confusable",
    "infrastructure.url",
}
REPOSITORY_ASSOCIATED_SURFACES = {
    "actions-artifact-content",
    "actions-artifacts",
    "actions-cache-content",
    "actions-cache-metadata",
    "actions-caches",
    "actions-job-summaries",
    "actions-logs",
    "actions-permissions",
    "actions-retention",
    "actions-secret-metadata",
    "actions-variables",
    "branch-protection",
    "container-images",
    "deployment-statuses",
    "deployments",
    "discussion-comments",
    "discussions",
    "environments",
    "github-pages",
    "github-pages-rendered",
    "immutable-releases-setting",
    "issue-comments",
    "issues",
    "labels",
    "milestones",
    "package-content",
    "package-metadata",
    "packages",
    "pull-comments",
    "pull-requests",
    "pull-reviews",
    "rulesets",
    "wiki",
}
NONCRITICAL_COVERAGE_SURFACES = {
    "actions-artifact-content",
    "actions-job-summaries",
    "actions-logs",
    "deployment-statuses",
    "discussion-comments",
    "discussions",
    "github-pages",
    "github-pages-rendered",
    "issues",
    "packages",
    "pull-comments",
    "pull-requests",
    "pull-reviews",
    "wiki",
} | REPOSITORY_ASSOCIATED_SURFACES
ZERO_WIDTH_TRANSLATION = str.maketrans("", "", "\u200b\u200c\u200d\u2060\ufeff")
CONFUSABLE_TRANSLATION = str.maketrans({"Α": "A", "А": "A", "Ι": "I", "І": "I", "і": "i", "ⅼ": "l"})
ENCODED_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])(?:(?:%[0-9A-Fa-f]{2}){6,}|[0-9A-Fa-f]{12,}|[A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])")
MIME_SIGNATURES = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF8", "image/gif"),
    (b"PK\x03\x04", "application/zip"),
    (b"SQLite format 3\x00", "application/x-sqlite3"),
    (b"MZ", "application/x-dosexec"),
    (b"\x7fELF", "application/x-elf"),
)


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
    Rule("infrastructure.ipv6", "infrastructure", "block", re.compile(r"(?i)(?<![0-9a-f:])(?=[0-9a-f:]{2,39}(?![0-9a-f:]))(?=(?:[0-9a-f]*:){2})[0-9a-f:]+")),
    Rule("infrastructure.cidr", "infrastructure", "block", re.compile(r"(?i)(?<![0-9a-f:.])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{2,})/(?:\d|[1-9]\d|1[01]\d|12[0-8])(?!\d)")),
    Rule("infrastructure.mac", "infrastructure", "block", re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")),
    Rule("infrastructure.hostname-port", "infrastructure", "review", re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:internal|local|lan|corp|home|test):\d{1,5}\b")),
    Rule("infrastructure.cloud-resource", "infrastructure", "review", re.compile(r"(?i)\b(?:arn:aws:[^\s\"'<>]+|projects/[a-z0-9._-]+/(?:locations|zones)/[^\s\"'<>]+|/subscriptions/[0-9a-f-]{36}/resourcegroups/[^\s\"'<>]+)")),
    Rule("identity.coordinates", "identity", "review", re.compile(r"(?i)\b(?:lat(?:itude)?|lng|lon(?:gitude)?)\s*[:=]\s*-?\d{1,3}\.\d{4,}\b")),
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


def run(
    command: list[str],
    cwd: Path | None = None,
    *,
    text: bool = True,
    input_data: bytes | str | None = None,
    timeout_seconds: int | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[Any]:
    """Run a child process without inheriting output that could contain a match."""
    options: dict[str, Any] = {
        "cwd": str(cwd) if cwd else None,
        "input": input_data,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": text,
        "check": False,
        "timeout": timeout_seconds,
        "env": {**os.environ, **env} if env else None,
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
    if PRIVATE_ROOT_OVERRIDE is not None:
        return PRIVATE_ROOT_OVERRIDE
    return (get_codex_home() / "private" / "github-safe-publish").resolve()


def ensure_private_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    root = private_root()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Private output must be below {root}") from exc
    root.mkdir(parents=True, exist_ok=True)
    restrict_private_path(root, directory=True)
    return resolved


def restrict_private_path(path: Path, *, directory: bool = False) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | (stat.S_IXUSR if directory else 0))
    except OSError:
        pass
    if os.name == "nt":
        cache_key = os.path.normcase(str(path.resolve()))
        if cache_key in RESTRICTED_PRIVATE_PATHS:
            return
        current = run(["whoami"])
        identity = current.stdout.strip() if current.returncode == 0 else ""
        if not identity:
            raise RuntimeError("Current Windows identity is unavailable")
        grant = f"{identity}:(OI)(CI)F" if directory else f"{identity}:F"
        result = run(["icacls", str(path), "/inheritance:r", "/grant:r", grant])
        if result.returncode != 0:
            raise RuntimeError("Private path ACL could not be restricted")
        RESTRICTED_PRIVATE_PATHS.add(cache_key)


def write_json(path: Path, data: Any, *, private: bool = False) -> None:
    resolved = ensure_private_path(path) if private else path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    temporary = resolved.with_name(f".{resolved.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, resolved)
    if private:
        restrict_private_path(resolved)


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
        "risk_acceptances": [],
    }


def migrate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Upgrade an older private policy in memory without modifying its source file."""
    if not isinstance(policy, dict) or policy.get("schema_version") not in SUPPORTED_POLICY_VERSIONS:
        raise ValueError("Private policy schema version is unknown")
    migrated = json.loads(json.dumps(policy))
    if migrated["schema_version"] == 1:
        for item in migrated.get("identifiers", []):
            item.setdefault("normalization", ["nfkc"])
            item.setdefault("scopes", ["all"])
        for item in migrated.get("binary_approvals", []):
            item.setdefault("inspection_layers", ["manual"])
            item.setdefault("tool_versions", {})
            item.setdefault("review_trigger", "content-or-scanner-change")
        migrated["schema_version"] = 2
    if migrated["schema_version"] == 2:
        migrated.setdefault("risk_acceptances", [])
        migrated["schema_version"] = SCHEMA_VERSION
    return migrated


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    policy = migrate_policy(policy)
    required = {
        "schema_version",
        "identifiers",
        "replacements",
        "approved_locations",
        "blocked_paths",
        "binary_approvals",
        "exceptions",
        "risk_acceptances",
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
        allowed_normalization = {"none", "nfkc", "casefold", "zero-width", "confusable"}
        if not isinstance(item.get("normalization"), list) or not set(item["normalization"]).issubset(allowed_normalization):
            raise ValueError("Identifier normalization is invalid")
        if not isinstance(item.get("scopes"), list) or not item["scopes"] or not all(isinstance(value, str) for value in item["scopes"]):
            raise ValueError("Identifier scopes must be a non-empty string list")

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
        required_binary = {"object", "sha256", "approved_by", "reason", "inspection_layers", "tool_versions", "review_trigger"}
        if not isinstance(approval, dict) or not required_binary.issubset(approval):
            raise ValueError("Each binary approval requires exact evidence and a review trigger")
        if not re.fullmatch(r"[0-9a-f]{64}", approval["sha256"]):
            raise ValueError("Binary approval SHA-256 is invalid")
        if not isinstance(approval["inspection_layers"], list) or not approval["inspection_layers"]:
            raise ValueError("Binary approval inspection layers are required")
        if not isinstance(approval["tool_versions"], dict) or not isinstance(approval["review_trigger"], str) or not approval["review_trigger"]:
            raise ValueError("Binary approval evidence is invalid")

    for exception in policy["exceptions"]:
        required_exception = {"rule_id", "object", "approved_by", "reason", "expires_at", "review_trigger"}
        if not isinstance(exception, dict) or not required_exception.issubset(exception):
            raise ValueError("Each exception requires an exact object, approval, expiry, and review trigger")
        if any(symbol in exception["object"] for symbol in "*?["):
            raise ValueError("Exceptions must target an exact object")
        dt.datetime.fromisoformat(exception["expires_at"].replace("Z", "+00:00"))

    for acceptance in policy["risk_acceptances"]:
        required_acceptance = {
            "repository",
            "rule_id",
            "object",
            "object_sha256",
            "scanner_sha256",
            "approved_by",
            "reason",
            "expires_at",
            "review_trigger",
        }
        if not isinstance(acceptance, dict) or not required_acceptance.issubset(acceptance):
            raise ValueError("Each risk acceptance requires exact repository, object, evidence, approval, expiry, and review trigger")
        if acceptance["rule_id"] not in NONCRITICAL_FINDING_RULES:
            raise ValueError("Risk acceptances cannot override a critical finding rule")
        if any(symbol in acceptance["object"] for symbol in "*?["):
            raise ValueError("Risk acceptances must target an exact object")
        if not all(isinstance(acceptance[field], str) and acceptance[field] for field in required_acceptance):
            raise ValueError("Risk acceptance fields must be non-empty strings")
        if not re.fullmatch(r"[0-9a-f]{64}", acceptance["object_sha256"]):
            raise ValueError("Risk acceptance object SHA-256 is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", acceptance["scanner_sha256"]):
            raise ValueError("Risk acceptance scanner SHA-256 is invalid")
        if acceptance["review_trigger"] != "content-or-scanner-change":
            raise ValueError("Risk acceptance review trigger must detect content or scanner changes")
        dt.datetime.fromisoformat(acceptance["expires_at"].replace("Z", "+00:00"))

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


class OcrCheckpointStore:
    """Persist redacted OCR scan deltas so another process can resume safely."""

    def __init__(self, path: Path, binding: dict[str, Any]) -> None:
        self.path = ensure_private_path(path)
        self.binding = binding
        self.path.parent.mkdir(parents=True, exist_ok=True)
        restrict_private_path(self.path.parent, directory=True)
        existed = self.path.exists()
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA journal_mode=DELETE")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS results ("
            "task_key TEXT PRIMARY KEY, content_sha256 TEXT NOT NULL, findings_json TEXT NOT NULL, "
            "coverage_json TEXT NOT NULL, completed_at TEXT NOT NULL)"
        )
        encoded = json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        row = self.connection.execute("SELECT value FROM metadata WHERE key='binding'").fetchone()
        if row is not None and row[0] != encoded:
            self.connection.close()
            raise ValueError("OCR checkpoint binding mismatch")
        self.connection.execute("INSERT OR REPLACE INTO metadata(key, value) VALUES('binding', ?)", (encoded,))
        self.connection.commit()
        if existed:
            # The first creator already restricted this file below a restricted directory. Reapplying
            # Windows ACLs while another scanner holds the SQLite file can fail because of file locking.
            RESTRICTED_PRIVATE_PATHS.add(os.path.normcase(str(self.path.resolve())))
        else:
            restrict_private_path(self.path)

    def load(self, task_key: str, content_sha256: str) -> tuple[list[Finding], list[Coverage]] | None:
        row = self.connection.execute(
            "SELECT findings_json, coverage_json FROM results WHERE task_key=? AND content_sha256=?",
            (task_key, content_sha256),
        ).fetchone()
        if row is None:
            return None
        try:
            findings = [Finding(**item) for item in json.loads(row[0])]
            coverage = [Coverage(**item) for item in json.loads(row[1])]
        except (TypeError, ValueError, json.JSONDecodeError):
            raise ValueError("OCR checkpoint result is invalid")
        return findings, coverage

    def save(
        self,
        task_key: str,
        content_sha256: str,
        findings: list[Finding],
        coverage: list[Coverage],
    ) -> None:
        findings_json = json.dumps([item.public_dict() for item in findings], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        coverage_json = json.dumps([item.as_dict() for item in coverage], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.connection.execute(
            "INSERT OR REPLACE INTO results(task_key, content_sha256, findings_json, coverage_json, completed_at) VALUES(?,?,?,?,?)",
            (task_key, content_sha256, findings_json, coverage_json, utc_now()),
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


class ScanState:
    def __init__(
        self,
        repository: str,
        policy: dict[str, Any] | None,
        collect_raw: bool = False,
        ocr_store: OcrCheckpointStore | None = None,
    ) -> None:
        self.repository = repository
        self.policy = policy or empty_policy()
        self.collect_raw = collect_raw
        self.findings: list[Finding] = []
        self.raw_candidates: list[dict[str, Any]] = []
        self.coverage: list[Coverage] = []
        self._finding_keys: set[tuple[str, str, str, str]] = set()
        self._candidate_keys: set[tuple[str, str, str, str, str]] = set()
        self._raw_candidate_total = 0
        self._private_rule_config: dict[str, dict[str, Any]] = {}
        self.object_sha256: dict[str, str] = {}
        self.scanner_sha256 = sha256_bytes(Path(__file__).read_bytes())
        try:
            budget = int(os.environ.get("SAFE_PUBLISH_IMAGE_OCR_BUDGET_SECONDS", DEFAULT_IMAGE_OCR_BUDGET_SECONDS))
        except ValueError:
            budget = 0
        self.image_ocr_budget_seconds = max(0, budget)
        self.image_ocr_started_at: float | None = None
        self.history_progress: dict[str, Any] | None = None
        self.worktree_progress: dict[str, Any] | None = None
        self.ocr_store = ocr_store
        self._private_rules = self._compile_private_rules()

    def replay_redacted_result(self, findings: list[Finding], coverage: list[Coverage]) -> None:
        for finding in findings:
            key = (finding.object, finding.location, finding.rule_id, finding.status)
            if key not in self._finding_keys:
                self._finding_keys.add(key)
                self.findings.append(finding)
        self.coverage.extend(coverage)

    def register_object(self, object_id: str, data: bytes) -> None:
        """Keep an in-memory whole-object digest for exact private risk acceptance checks."""
        self.object_sha256.setdefault(object_id, sha256_bytes(data))

    def _compile_private_rules(self) -> tuple[Rule, ...]:
        rules: list[Rule] = []
        for item in self.policy["identifiers"]:
            self._private_rule_config[item["id"]] = item
            flags = re.IGNORECASE if "casefold" in item.get("normalization", []) else 0
            value = normalize_private_text(item["value"], item.get("normalization", []))
            if item["kind"] == "literal":
                pattern = re.compile(re.escape(value), flags)
            else:
                pattern = re.compile(value, flags)
            rules.append(Rule(item["id"], "private-identifier", item["severity"], pattern))
        return tuple(rules)

    def add_coverage(self, surface: str, status: str, reason: str = "", object_count: int = 0) -> None:
        self.coverage.append(Coverage(surface, status, reason, object_count))

    def _handling_status(self, rule_id: str, object_id: str, severity: str, legal: bool) -> tuple[str, str]:
        for approval in self.policy["approved_locations"]:
            if approval["rule_id"] == rule_id and approval["object"] == object_id:
                return severity, "approved"
        if legal:
            return "review", "review"
        now = dt.datetime.now(dt.timezone.utc)
        for exception in self.policy["exceptions"]:
            if (
                severity == "review"
                and rule_id in NONCRITICAL_FINDING_RULES
                and exception["rule_id"] == rule_id
                and exception["object"] == object_id
            ):
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
                if self._raw_candidate_total >= MAX_RAW_CANDIDATES_PER_STATE:
                    if not any(item.reason == "raw-candidate-limit-exceeded" for item in self.coverage):
                        self.add_coverage(surface, "tool_failed", "raw-candidate-limit-exceeded")
                    return
                self._candidate_keys.add(candidate_key)
                self._raw_candidate_total += 1
                self.raw_candidates.append(
                    {
                        "repository": self.repository,
                        "surface": surface,
                        "object": object_id,
                        "location": location,
                        "rule_id": rule.rule_id,
                        "severity": severity,
                        "object_sha256": self.object_sha256.get(object_id),
                        "raw_value": raw_value,
                    }
                )

    def binary_is_approved(self, object_id: str, data: bytes) -> bool:
        digest = sha256_bytes(data)
        return any(item["object"] == object_id and item["sha256"] == digest for item in self.policy["binary_approvals"])


def is_legal_path(path: str) -> bool:
    name = Path(path.replace("\\", "/")).name.lower()
    return name in LEGAL_NAMES or name.startswith("license.") or name.startswith("notice.")


def normalize_private_text(text: str, operations: Iterable[str]) -> str:
    result = text
    selected = set(operations)
    if "nfkc" in selected:
        result = unicodedata.normalize("NFKC", result)
    if "zero-width" in selected:
        result = result.translate(ZERO_WIDTH_TRANSLATION)
    if "confusable" in selected:
        result = result.translate(CONFUSABLE_TRANSLATION)
    if "casefold" in selected:
        result = result.casefold()
    return result


def bounded_decoded_variants(text: str) -> Iterable[tuple[str, str]]:
    """Yield a small set of decoded views without recursively expanding attacker input."""
    yielded = 0
    for index, match in enumerate(ENCODED_TOKEN_PATTERN.finditer(text)):
        if index >= 128:
            break
        token = match.group(0)
        candidates: list[tuple[str, bytes | str]] = []
        if token.startswith("%"):
            candidates.append(("url", urllib.parse.unquote(token)))
        elif re.fullmatch(r"[0-9A-Fa-f]{12,}", token) and len(token) % 2 == 0:
            try:
                candidates.append(("hex", bytes.fromhex(token)))
            except ValueError:
                pass
        elif len(token) % 4 == 0:
            try:
                candidates.append(("base64", base64.b64decode(token, validate=True)))
            except (binascii.Error, ValueError):
                pass
        for encoding, value in candidates:
            decoded = value if isinstance(value, str) else decode_text(value)
            if decoded and decoded != token and len(decoded) <= 8192:
                yielded += 1
                yield f"decoded-{encoding}-{yielded}", decoded


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


def parse_network_literal(rule_id: str, value: str) -> ipaddress._BaseAddress | ipaddress._BaseNetwork | None:
    try:
        if rule_id == "infrastructure.ipv4":
            return ipaddress.IPv4Address(value)
        if rule_id == "infrastructure.ipv6":
            return ipaddress.IPv6Address(value)
        if rule_id == "infrastructure.cidr":
            return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    return None


def is_public_example_address(value: ipaddress._BaseAddress) -> bool:
    if value.is_loopback or value.is_unspecified or value.is_multicast:
        return True
    documentation_networks = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    )
    return any(value in network for network in documentation_networks if value.version == network.version)


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
    if rule_id in {"infrastructure.ipv6", "infrastructure.cidr"}:
        return ":" in text or "/" in text
    if rule_id == "infrastructure.mac":
        return ":" in text or "-" in text
    if rule_id == "infrastructure.hostname-port":
        return ":" in text and any(token in lowered for token in (".internal", ".local", ".lan", ".corp", ".home", ".test"))
    if rule_id == "infrastructure.cloud-resource":
        return "arn:aws:" in lowered or "/subscriptions/" in lowered or "projects/" in lowered
    if rule_id == "identity.coordinates":
        return any(token in lowered for token in ("lat=", "lat:", "latitude", "lng=", "lng:", "lon=", "longitude"))
    if rule_id == "infrastructure.windows-path":
        return ":\\" in text
    if rule_id == "infrastructure.unix-home":
        return "/home/" in text or "/Users/" in text
    if rule_id == "infrastructure.url":
        return "http://" in lowered or "https://" in lowered
    return True


def scan_text(state: ScanState, text: str, *, surface: str, object_id: str, display_path: str) -> None:
    state.register_object(object_id, text.encode("utf-8"))
    legal = is_legal_path(display_path)
    newlines: array[int] | None = None
    lowered = text.lower()
    private_aialra = any(rule.rule_id != "identity.aialra" and rule.pattern.pattern == re.escape("AIALRA") for rule in state._private_rules)
    generic_rules = tuple(rule for rule in GENERIC_RULES if not (private_aialra and rule.rule_id == "identity.aialra"))
    for rule in (*generic_rules, *state._private_rules):
        scan_value = text
        if rule.category == "private-identifier":
            config = state._private_rule_config[rule.rule_id]
            scopes = set(config.get("scopes", ["all"]))
            if "all" not in scopes and surface not in scopes:
                continue
            scan_value = normalize_private_text(text, config.get("normalization", []))
        scan_lowered = scan_value.lower()
        if not rule_can_match(rule.rule_id, scan_value, scan_lowered):
            continue
        for match in rule.pattern.finditer(scan_value):
            raw = match.group(rule.value_group)
            if rule.rule_id == "credential.assignment" and is_placeholder(raw):
                continue
            if rule.rule_id in {"infrastructure.ipv4", "infrastructure.ipv6", "infrastructure.cidr"}:
                parsed_network = parse_network_literal(rule.rule_id, raw)
                if parsed_network is None:
                    continue
                if isinstance(parsed_network, (ipaddress.IPv4Address, ipaddress.IPv6Address)) and is_public_example_address(parsed_network):
                    continue
            if rule.rule_id == "identity.aialra-confusable" and raw.lower() == "aialra":
                continue
            if rule.rule_id == "identity.email" and raw.lower().rsplit("@", 1)[-1] in {"example.com", "example.net", "example.org", "example.invalid"}:
                continue
            if rule.rule_id == "infrastructure.url" and re.match(r"(?i)^https?://(?:[^/]+\.)?example\.invalid(?:[/:?#]|$)", raw):
                continue
            if rule.rule_id == "infrastructure.url" and raw.lower() in SAFE_STANDARD_URLS:
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
    if not object_id.endswith(":decoded-view"):
        for label, decoded in bounded_decoded_variants(text):
            scan_text(
                state,
                decoded,
                surface=surface,
                object_id=f"{object_id}:decoded-view",
                display_path=f"{display_path}!{label}",
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


def detected_mime(data: bytes, suffix: str) -> str:
    for signature, mime in MIME_SIGNATURES:
        if data.startswith(signature):
            return mime
    if data.startswith((b"RIFF", b"ID3", b"fLaC")) or b"ftyp" in data[:32]:
        return "media/container"
    if suffix == ".svg" or data.lstrip().startswith(b"<svg"):
        return "image/svg+xml"
    return "application/octet-stream"


def rapid_ocr_engine() -> Any:
    global RAPID_OCR_ENGINE
    if RAPID_OCR_ENGINE is None:
        from rapidocr_onnxruntime import RapidOCR

        RAPID_OCR_ENGINE = RapidOCR()
    return RAPID_OCR_ENGINE


def direct_ocr(image_data: bytes, *, multi_frame: bool) -> list[tuple[int, int, str]]:
    from PIL import Image, ImageSequence
    import numpy as np

    engine = rapid_ocr_engine()
    extracted: list[tuple[int, int, str]] = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        image = Image.open(io.BytesIO(image_data))
    with image:
        frames = ImageSequence.Iterator(image) if multi_frame else [image]
        for frame_index, frame in enumerate(frames):
            result, _ = engine(np.asarray(frame.convert("RGB")))
            for text_index, row in enumerate(result or []):
                if len(row) >= 2 and isinstance(row[1], str):
                    extracted.append((frame_index, text_index, row[1]))
    return extracted


def ocr_worker_loop(connection: Any) -> None:
    """Keep one OCR engine isolated while processing bounded units over a private pipe."""
    try:
        while True:
            request = connection.recv()
            if request is None:
                return
            image_data, multi_frame = request
            try:
                extracted = direct_ocr(image_data, multi_frame=multi_frame)
                connection.send(("ok", extracted))
            except Exception:
                connection.send(("error", []))
    except (EOFError, OSError):
        return
    finally:
        connection.close()


class OcrProcessRunner:
    """Reuse an isolated OCR engine and replace it after any timeout or crash."""

    def __init__(self) -> None:
        self.process: Any | None = None
        self.connection: Any | None = None

    def _start(self) -> None:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        process = context.Process(target=ocr_worker_loop, args=(child,))
        process.daemon = True
        process.start()
        child.close()
        self.process = process
        self.connection = parent

    def _stop(self, *, graceful: bool) -> None:
        process, connection = self.process, self.connection
        self.process, self.connection = None, None
        if process is None:
            return
        if graceful and connection is not None and process.is_alive():
            try:
                connection.send(None)
            except (BrokenPipeError, EOFError, OSError):
                pass
        process.join(timeout=10 if graceful else 0)
        if process.is_alive():
            process.terminate()
            process.join(timeout=10)
        if process.is_alive():
            process.kill()
            process.join(timeout=10)
        if connection is not None:
            connection.close()

    def run(self, image_data: bytes, *, multi_frame: bool, timeout_seconds: int) -> list[tuple[int, int, str]]:
        if self.process is None or not self.process.is_alive() or self.connection is None:
            self._stop(graceful=False)
            self._start()
        assert self.connection is not None
        try:
            self.connection.send((image_data, multi_frame))
            if not self.connection.poll(timeout_seconds):
                self._stop(graceful=False)
                raise TimeoutError("OCR unit exceeded its time limit")
            status, extracted = self.connection.recv()
        except (BrokenPipeError, EOFError, OSError):
            self._stop(graceful=False)
            raise RuntimeError("OCR worker failed")
        if status != "ok":
            raise RuntimeError("OCR worker failed")
        return [(int(frame), int(index), str(text)) for frame, index, text in extracted]

    def close(self) -> None:
        self._stop(graceful=True)


OCR_PROCESS_RUNNER = OcrProcessRunner()
atexit.register(OCR_PROCESS_RUNNER.close)


def bounded_ocr(image_data: bytes, *, multi_frame: bool) -> list[tuple[int, int, str]]:
    """Run one OCR unit with a hard timeout in a reusable isolated process."""
    if IN_ARTIFACT_WORKER:
        return direct_ocr(image_data, multi_frame=multi_frame)
    try:
        timeout_seconds = max(1, int(os.environ.get("SAFE_PUBLISH_OCR_UNIT_TIMEOUT_SECONDS", DEFAULT_OCR_UNIT_TIMEOUT_SECONDS)))
    except ValueError:
        timeout_seconds = DEFAULT_OCR_UNIT_TIMEOUT_SECONDS
    return OCR_PROCESS_RUNNER.run(image_data, multi_frame=multi_frame, timeout_seconds=timeout_seconds)


def normalized_barcode_values(result: Any) -> list[str]:
    """Normalize OpenCV barcode results without depending on one tuple ABI."""
    if not isinstance(result, tuple):
        raise ValueError("OpenCV barcode result is not a tuple")
    if len(result) == 3:
        decoded, _decoded_type, _points = result
        detected = bool(decoded)
    elif len(result) == 4:
        detected, decoded, _decoded_type, _points = result
    else:
        raise ValueError("OpenCV barcode result length is unsupported")
    if not detected or decoded is None:
        return []
    values = [decoded] if isinstance(decoded, str) else list(decoded)
    return [value for value in values if isinstance(value, str) and value]


def ocr_task_key(kind: str, surface: str, object_id: str, unit: str = "") -> str:
    return json.dumps([kind, surface, object_id, unit], ensure_ascii=False, separators=(",", ":"))


def replay_ocr_result(state: ScanState, task_key: str, content_sha256: str) -> bool:
    if state.ocr_store is None:
        return False
    cached = state.ocr_store.load(task_key, content_sha256)
    if cached is None:
        return False
    state.replay_redacted_result(*cached)
    return True


def save_ocr_result(
    state: ScanState,
    task_key: str,
    content_sha256: str,
    finding_start: int,
    coverage_start: int,
) -> None:
    if state.ocr_store is None:
        return
    state.ocr_store.save(
        task_key,
        content_sha256,
        state.findings[finding_start:],
        state.coverage[coverage_start:],
    )


def extract_image_layers(data: bytes, *, allow_ocr: bool = True) -> tuple[list[tuple[str, str]], set[str], list[tuple[str, str]]]:
    digest = sha256_bytes(data)
    cached = IMAGE_EXTRACTION_CACHE.get(digest)
    if cached is not None:
        return cached
    extracted: list[tuple[str, str]] = []
    layers: set[str] = set()
    failures: list[tuple[str, str]] = []
    try:
        from PIL import Image, ImageSequence

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            image = Image.open(io.BytesIO(data))
        with image:
            metadata = {str(key): str(value) for key, value in image.info.items() if key not in {"icc_profile", "exif"}}
            try:
                metadata.update({str(key): str(value) for key, value in image.getexif().items()})
            except Exception:
                pass
            if metadata:
                extracted.append(("metadata", json.dumps(metadata, ensure_ascii=False)))
            layers.add("metadata")
            frame_count = int(getattr(image, "n_frames", 1))
            if frame_count > 500:
                failures.append(("unreadable", "image-frame-limit"))
                result = (extracted, layers, failures)
                IMAGE_EXTRACTION_CACHE[digest] = result
                return result
            # QR and barcode decoding are deterministic and local; scan decoded payloads without logging them.
            try:
                import cv2
                import numpy as np

                qr_detector = cv2.QRCodeDetector()
                barcode_detector = cv2.barcode_BarcodeDetector()
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    for index, frame in enumerate(ImageSequence.Iterator(image)):
                        rgb = np.asarray(frame.convert("RGB"))
                        decoded, _, _ = qr_detector.detectAndDecode(rgb)
                        if decoded:
                            extracted.append((f"qr:{index}", decoded))
                        barcode_values = normalized_barcode_values(barcode_detector.detectAndDecode(rgb))
                        for value_index, value in enumerate(barcode_values):
                            extracted.append((f"barcode:{index}:{value_index}", value))
                layers.update({"qr", "barcode"})
            except Exception:
                failures.append(("tool_failed", "image-code-parser-unavailable"))
    except Exception:
        result = ([], set(), [("unreadable", "invalid-image")])
        IMAGE_EXTRACTION_CACHE[digest] = result
        return result
    # OCR is a required image-pixel layer. A bounded repository budget prevents unbounded gates.
    if not allow_ocr:
        failures.append(("unreadable", "image-ocr-budget-exceeded"))
        return extracted, layers, failures
    try:
        for frame_index, text_index, text in bounded_ocr(data, multi_frame=True):
            extracted.append((f"ocr:{frame_index}:{text_index}", text))
        layers.add("ocr")
    except TimeoutError:
        failures.append(("tool_failed", "image-ocr-unit-timeout"))
    except Exception:
        failures.append(("tool_failed", "image-ocr-parser-unavailable"))
    result = (extracted, layers, failures)
    IMAGE_EXTRACTION_CACHE[digest] = result
    return result


def scan_image_content(state: ScanState, data: bytes, *, surface: str, object_id: str, display_path: str) -> None:
    if state.binary_is_approved(object_id, data):
        return
    digest = sha256_bytes(data)
    task_key = ocr_task_key("image", surface, object_id)
    if replay_ocr_result(state, task_key, digest):
        return
    finding_start = len(state.findings)
    coverage_start = len(state.coverage)
    cached = sha256_bytes(data) in IMAGE_EXTRACTION_CACHE
    if not cached and state.image_ocr_started_at is None:
        state.image_ocr_started_at = time.monotonic()
    within_budget = bool(
        state.image_ocr_started_at is not None
        and time.monotonic() - state.image_ocr_started_at <= state.image_ocr_budget_seconds
    )
    extracted, layers, failures = extract_image_layers(
        data,
        allow_ocr=cached or within_budget,
    )
    for label, value in extracted:
        scan_text(state, value, surface=surface, object_id=f"{object_id}:{label}", display_path=f"{display_path}!{label}")
    for status, reason in failures:
        state.add_coverage(surface, status, f"{reason}:{object_id}")
    if {"metadata", "qr", "barcode", "ocr"}.issubset(layers):
        state.add_coverage(surface, "checked", f"image-layers:{object_id}", 1)
        save_ocr_result(state, task_key, digest, finding_start, coverage_start)


def scan_pdf_content(state: ScanState, data: bytes, *, surface: str, object_id: str, display_path: str) -> None:
    if state.binary_is_approved(object_id, data):
        return
    try:
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            state.add_coverage(surface, "unreadable", f"encrypted-pdf:{object_id}")
            return
        if reader.metadata:
            scan_text(state, json.dumps(dict(reader.metadata), ensure_ascii=False, default=str), surface=surface, object_id=f"{object_id}:metadata", display_path=f"{display_path}!metadata")
        for index, page in enumerate(reader.pages):
            try:
                text = page.extract_text() or ""
                if text:
                    scan_text(state, text, surface=surface, object_id=f"{object_id}:page:{index + 1}", display_path=f"{display_path}!page:{index + 1}")
            except Exception:
                state.add_coverage(surface, "unreadable", f"pdf-page-unreadable:{object_id}:{index + 1}")
        try:
            import fitz
            ocr_page_count = 0
            digest = sha256_bytes(data)
            document = fitz.open(stream=data, filetype="pdf")
            total_page_count = len(document)
            with document:
                for index, page in enumerate(document):
                    page_number = index + 1
                    task_key = ocr_task_key("pdf-page", surface, object_id, str(page_number))
                    if replay_ocr_result(state, task_key, digest):
                        ocr_page_count += 1
                        continue
                    if state.image_ocr_started_at is None:
                        state.image_ocr_started_at = time.monotonic()
                    if time.monotonic() - state.image_ocr_started_at > state.image_ocr_budget_seconds:
                        state.add_coverage(surface, "unreadable", f"pdf-page-image-ocr-budget-exceeded:{object_id}")
                        break
                    finding_start = len(state.findings)
                    coverage_start = len(state.coverage)
                    pixmap = page.get_pixmap(matrix=fitz.Matrix(1.5, 1.5), alpha=False)
                    page_image = pixmap.tobytes("png")
                    extracted = bounded_ocr(page_image, multi_frame=False)
                    ocr_page_count += 1
                    for _frame_index, text_index, text in extracted:
                        scan_text(state, text, surface=surface, object_id=f"{object_id}:page-image:{page_number}:{text_index}", display_path=f"{display_path}!page-image:{page_number}:{text_index}")
                    save_ocr_result(state, task_key, digest, finding_start, coverage_start)
            if ocr_page_count == total_page_count:
                state.add_coverage(surface, "checked", f"pdf-page-image-ocr:{object_id}", ocr_page_count)
        except TimeoutError:
            state.add_coverage(surface, "tool_failed", f"pdf-page-image-ocr-unit-timeout:{object_id}")
        except Exception:
            state.add_coverage(surface, "tool_failed", f"pdf-page-image-ocr-unavailable:{object_id}")
        attachments = getattr(reader, "attachments", {}) or {}
        for name, values in attachments.items():
            for index, value in enumerate(values if isinstance(values, list) else [values]):
                scan_bytes(state, value, surface=surface, object_id=f"{object_id}!attachment:{name}:{index}", display_path=f"{display_path}!{name}", depth=1)
        state.add_coverage(surface, "checked", f"pdf-structure:{object_id}", len(reader.pages))
    except Exception:
        state.add_coverage(surface, "unreadable", f"invalid-or-unsupported-pdf:{object_id}")


def scan_command_metadata(state: ScanState, data: bytes, *, surface: str, object_id: str, display_path: str, command: list[str], layer: str) -> None:
    if state.binary_is_approved(object_id, data):
        return
    with tempfile.TemporaryDirectory(prefix="safe-publish-binary-") as temporary:
        target = Path(temporary) / Path(display_path).name
        target.write_bytes(data)
        result = run([*command, str(target)], text=False)
        if result.returncode != 0:
            state.add_coverage(surface, "tool_failed", f"{layer}-parser-unavailable:{object_id}")
            return
        output = decode_text(result.stdout)
        if output:
            scan_text(state, output, surface=surface, object_id=f"{object_id}:{layer}", display_path=f"{display_path}!{layer}")
        state.add_coverage(surface, "checked", f"{layer}:{object_id}", 1)


def numpy_dtype_depth(dtype: Any, depth: int = 0) -> int:
    """Return the maximum nested structured dtype depth with a hard recursion bound."""
    if depth > MAX_ARCHIVE_DEPTH:
        raise ValueError("NumPy dtype nesting exceeds the supported depth")
    fields = getattr(dtype, "fields", None) or {}
    if not fields:
        return depth
    return max(numpy_dtype_depth(field[0], depth + 1) for field in fields.values())


def scan_numpy_array(
    state: ScanState,
    value: Any,
    *,
    surface: str,
    object_id: str,
    display_path: str,
) -> bool:
    """Inspect one NumPy array without enabling pickle or emitting raw values."""
    try:
        import numpy as np

        array_value = np.asarray(value)
        numpy_dtype_depth(array_value.dtype)
        if array_value.dtype.hasobject:
            state.add_coverage(surface, "unreadable", f"numpy-object-dtype-forbidden:{object_id}")
            return False
        if int(array_value.size) > MAX_ARRAY_ELEMENTS or int(array_value.nbytes) > MAX_ARRAY_BYTES:
            state.add_coverage(surface, "unreadable", f"numpy-array-limit:{object_id}")
            return False
        metadata = json.dumps(
            {"dtype": str(array_value.dtype), "shape": [int(item) for item in array_value.shape]},
            ensure_ascii=False,
            sort_keys=True,
        )
        scan_text(
            state,
            metadata,
            surface=surface,
            object_id=f"{object_id}:numpy-metadata",
            display_path=f"{display_path}!numpy-metadata",
        )
        text_parts: list[str] = []
        text_bytes = 0
        candidates: list[Any] = []
        if array_value.dtype.fields:
            candidates.extend(array_value[name] for name in sorted(array_value.dtype.fields))
        else:
            candidates.append(array_value)
        for candidate in candidates:
            candidate_array = np.asarray(candidate)
            if candidate_array.dtype.kind not in {"S", "U"}:
                continue
            for item in candidate_array.reshape(-1):
                text = item.decode("utf-8", errors="replace") if isinstance(item, bytes) else str(item)
                encoded_length = len(text.encode("utf-8"))
                if text_bytes + encoded_length > MAX_ARRAY_TEXT_BYTES:
                    state.add_coverage(surface, "unreadable", f"numpy-text-limit:{object_id}")
                    return False
                text_parts.append(text)
                text_bytes += encoded_length
        if text_parts:
            scan_text(
                state,
                "\n".join(text_parts),
                surface=surface,
                object_id=f"{object_id}:numpy-text",
                display_path=f"{display_path}!numpy-text",
            )
        state.add_coverage(surface, "checked", f"numpy-array:{object_id}", 1)
        return True
    except (MemoryError, OSError, TypeError, ValueError):
        state.add_coverage(surface, "unreadable", f"invalid-or-unsupported-numpy-array:{object_id}")
        return False


def scan_numpy_content(
    state: ScanState,
    data: bytes,
    *,
    surface: str,
    object_id: str,
    display_path: str,
) -> None:
    """Inspect NPY and NPZ content with bounded expansion and pickle disabled."""
    if state.binary_is_approved(object_id, data):
        return
    try:
        import numpy as np

        suffix = Path(display_path.split("!")[-1]).suffix.lower()
        if suffix == ".npz":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = [item for item in archive.infolist() if not item.is_dir()]
                if len(infos) > MAX_ARRAY_MEMBERS:
                    state.add_coverage(surface, "tool_failed", f"numpy-member-limit:{object_id}")
                    return
                expanded = sum(int(item.file_size) for item in infos)
                if expanded > MAX_ARCHIVE_EXPANDED_BYTES or any(item.file_size > MAX_ARRAY_BYTES for item in infos):
                    state.add_coverage(surface, "tool_failed", f"numpy-expansion-limit:{object_id}")
                    return
                if any(item.flag_bits & 0x1 for item in infos):
                    state.add_coverage(surface, "unreadable", f"encrypted-numpy-archive:{object_id}")
                    return
            with np.load(io.BytesIO(data), allow_pickle=False) as archive_data:
                names = sorted(archive_data.files)
                if len(names) > MAX_ARRAY_MEMBERS:
                    state.add_coverage(surface, "tool_failed", f"numpy-member-limit:{object_id}")
                    return
                for name in names:
                    try:
                        value = archive_data[name]
                    except (MemoryError, OSError, TypeError, ValueError):
                        state.add_coverage(surface, "unreadable", f"numpy-pickle-forbidden-or-invalid:{object_id}!{name}")
                        continue
                    scan_numpy_array(
                        state,
                        value,
                        surface=surface,
                        object_id=f"{object_id}!{name}",
                        display_path=f"{display_path}!{name}",
                    )
            return
        value = np.load(io.BytesIO(data), allow_pickle=False)
        scan_numpy_array(state, value, surface=surface, object_id=object_id, display_path=display_path)
    except ImportError:
        state.add_coverage(surface, "tool_failed", f"numpy-parser-unavailable:{object_id}")
    except (MemoryError, OSError, TypeError, ValueError, zipfile.BadZipFile):
        state.add_coverage(surface, "unreadable", f"numpy-pickle-forbidden-or-invalid:{object_id}")


def scan_opaque_binary(state: ScanState, data: bytes, *, surface: str, object_id: str, display_path: str, layer: str) -> None:
    if state.binary_is_approved(object_id, data):
        return
    try:
        import magic

        description = str(magic.from_buffer(data))
        if description:
            scan_text(state, description, surface=surface, object_id=f"{object_id}:format", display_path=f"{display_path}!format")
        state.add_coverage(surface, "checked", f"binary-format:{object_id}", 1)
    except Exception:
        state.add_coverage(surface, "tool_failed", f"binary-format-parser-unavailable:{object_id}")
    scan_command_metadata(state, data, surface=surface, object_id=object_id, display_path=display_path, command=["strings", "-a", "-n", "6"], layer=layer)


def scan_media_content(state: ScanState, data: bytes, *, surface: str, object_id: str, display_path: str) -> None:
    if state.binary_is_approved(object_id, data):
        return
    with tempfile.TemporaryDirectory(prefix="safe-publish-media-") as temporary:
        temporary_path = Path(temporary)
        target = temporary_path / (Path(display_path).name or "media.bin")
        target.write_bytes(data)
        probe = run(["ffprobe", "-v", "quiet", "-show_format", "-show_streams", "-of", "json", str(target)])
        if probe.returncode != 0:
            state.add_coverage(surface, "tool_failed", f"media-metadata-parser-unavailable:{object_id}")
            return
        try:
            metadata = json.loads(probe.stdout)
        except json.JSONDecodeError:
            state.add_coverage(surface, "tool_failed", f"media-metadata-response-invalid:{object_id}")
            return
        scan_text(state, json.dumps(metadata, ensure_ascii=False), surface=surface, object_id=f"{object_id}:media-metadata", display_path=f"{display_path}!media-metadata")
        state.add_coverage(surface, "checked", f"media-metadata:{object_id}", 1)

        streams = metadata.get("streams") or []
        subtitle_streams = [item for item in streams if item.get("codec_type") == "subtitle"]
        if not subtitle_streams:
            state.add_coverage("media-subtitles", "not_present")
        for stream in subtitle_streams:
            index = stream.get("index")
            extracted = run(["ffmpeg", "-v", "error", "-i", str(target), "-map", f"0:{index}", "-f", "webvtt", "pipe:1"], text=False)
            if extracted.returncode != 0:
                state.add_coverage("media-subtitles", "unreadable", f"subtitle-extraction-failed:{object_id}:{index}")
                continue
            scan_bytes(state, extracted.stdout, surface="media-subtitles", object_id=f"{object_id}:subtitle:{index}", display_path=f"{display_path}!subtitle-{index}.vtt")
            state.add_coverage("media-subtitles", "checked", object_count=1)

        cover_streams = [item for item in streams if item.get("codec_type") == "video" and (item.get("disposition") or {}).get("attached_pic") == 1]
        if not cover_streams:
            state.add_coverage("media-cover-art", "not_present")
        for stream in cover_streams:
            index = stream.get("index")
            extracted = run(["ffmpeg", "-v", "error", "-i", str(target), "-map", f"0:{index}", "-frames:v", "1", "-f", "image2pipe", "-vcodec", "png", "pipe:1"], text=False)
            if extracted.returncode != 0:
                state.add_coverage("media-cover-art", "unreadable", f"cover-extraction-failed:{object_id}:{index}")
                continue
            scan_bytes(state, extracted.stdout, surface="media-cover-art", object_id=f"{object_id}:cover:{index}", display_path=f"{display_path}!cover-{index}.png")
            state.add_coverage("media-cover-art", "checked", object_count=1)

        attachment_streams = [item for item in streams if item.get("codec_type") == "attachment"]
        if not attachment_streams:
            state.add_coverage("media-attachments", "not_present")
        else:
            dumped = run(["ffmpeg", "-v", "error", "-dump_attachment:t", "", "-i", str(target), "-f", "null", "-"], temporary_path)
            attachments = [path for path in temporary_path.iterdir() if path != target]
            if dumped.returncode != 0 or len(attachments) < len(attachment_streams):
                state.add_coverage("media-attachments", "unreadable", f"attachment-extraction-failed:{object_id}")
            for index, attachment in enumerate(attachments):
                scan_bytes(state, attachment.read_bytes(), surface="media-attachments", object_id=f"{object_id}:attachment:{index}", display_path=f"{display_path}!{attachment.name}")
            if attachments:
                state.add_coverage("media-attachments", "checked", object_count=len(attachments))


def scan_bytes(
    state: ScanState,
    data: bytes,
    *,
    surface: str,
    object_id: str,
    display_path: str,
    depth: int = 0,
) -> None:
    state.register_object(object_id, data)
    if len(data) > DEFAULT_MAX_FILE_BYTES:
        state.add_coverage(surface, "unreadable", f"oversized-object:{object_id}")
        return
    suffix = Path(display_path.split("!")[-1]).suffix.lower()
    mime = detected_mime(data, suffix)
    # Treat Git LFS pointers as text even when their tracked filename uses an opaque suffix.
    pointer_text = decode_text(data)
    if pointer_text is not None and pointer_text.startswith("version https://git-lfs.github.com/spec/v1\n"):
        scan_text(state, pointer_text, surface=surface, object_id=object_id, display_path=display_path)
        return
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
    if pointer_text is not None and len(data) > DEFAULT_MAX_INLINE_TEXT_BYTES:
        state.add_coverage(surface, "unreadable", f"oversized-text-object:{object_id}")
        return
    if depth > MAX_ARCHIVE_DEPTH:
        state.add_coverage(surface, "tool_failed", f"archive-depth-limit:{object_id}")
        return
    if suffix in NUMPY_SUFFIXES:
        scan_numpy_content(state, data, surface=surface, object_id=object_id, display_path=display_path)
        return
    if suffix in OFFICE_SUFFIXES or (mime == "application/zip" and suffix in OFFICE_SUFFIXES):
        scan_zip(state, data, surface=surface, object_id=object_id, display_path=display_path, depth=depth, office=True)
        return
    if suffix == ".zip" or (mime == "application/zip" and suffix not in OFFICE_SUFFIXES):
        scan_zip(state, data, surface=surface, object_id=object_id, display_path=display_path, depth=depth)
        return
    if suffix in {".tar", ".tgz", ".gz", ".bz2", ".xz"}:
        scan_tar(state, data, surface=surface, object_id=object_id, display_path=display_path, depth=depth)
        return
    if suffix in {".7z", ".rar"}:
        if not state.binary_is_approved(object_id, data):
            state.add_coverage(surface, "unreadable", f"unsupported-archive:{object_id}")
        return
    if suffix == ".svg" or mime == "image/svg+xml":
        # SVG is XML text, so scan its source instead of requiring binary approval.
        svg_text = decode_text(data)
        try:
            root = ET.fromstring(svg_text) if svg_text is not None else None
        except ET.ParseError:
            root = None
        if root is None or root.tag.rsplit("}", 1)[-1].lower() != "svg":
            state.add_coverage(surface, "unreadable", f"invalid-svg:{object_id}")
            if svg_text is not None:
                scan_text(state, svg_text, surface=surface, object_id=object_id, display_path=display_path)
            return
        scan_text(state, svg_text, surface=surface, object_id=object_id, display_path=display_path)
        # Embedded raster images remain binary artifacts and need the same review as standalone files.
        for index, match in enumerate(SVG_DATA_URI_PATTERN.finditer(svg_text), start=1):
            mime_type = match.group(1).lower()
            encoded = re.sub(r"\s+", "", match.group(2))
            try:
                embedded = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                state.add_coverage(surface, "unreadable", f"invalid-svg-data-uri:{object_id}!embedded-{index}")
                continue
            embedded_suffix = SVG_MIME_SUFFIXES.get(mime_type, ".bin")
            scan_bytes(
                state,
                embedded,
                surface=surface,
                object_id=f"{object_id}!embedded-{index}{embedded_suffix}",
                display_path=f"{display_path}!embedded-{index}{embedded_suffix}",
                depth=depth + 1,
            )
        return
    if suffix in IMAGE_SUFFIXES or mime.startswith("image/"):
        scan_image_content(state, data, surface=surface, object_id=object_id, display_path=display_path)
        return
    if suffix == ".pdf" or mime == "application/pdf":
        scan_pdf_content(state, data, surface=surface, object_id=object_id, display_path=display_path)
        return
    if suffix in MEDIA_SUFFIXES or mime == "media/container":
        scan_media_content(state, data, surface=surface, object_id=object_id, display_path=display_path)
        return
    if suffix in OPAQUE_SUFFIXES or mime in {"application/x-dosexec", "application/x-elf"}:
        scan_opaque_binary(state, data, surface=surface, object_id=object_id, display_path=display_path, layer="binary-strings")
        return
    text = decode_text(data)
    if text is None:
        scan_opaque_binary(state, data, surface=surface, object_id=object_id, display_path=display_path, layer="opaque-binary-strings")
        return
    scan_text(state, text, surface=surface, object_id=object_id, display_path=display_path)


def complex_artifact(data: bytes, display_path: str) -> bool:
    suffix = Path(display_path.split("!")[-1]).suffix.lower()
    if suffix in OFFICE_SUFFIXES | IMAGE_SUFFIXES | MEDIA_SUFFIXES | ARCHIVE_SUFFIXES | DATABASE_SUFFIXES | OPAQUE_SUFFIXES | NUMPY_SUFFIXES | {".pdf", ".svg"}:
        return True
    mime = detected_mime(data, suffix)
    return mime != "application/octet-stream" or decode_text(data) is None


def artifact_may_require_ocr(data: bytes, display_path: str) -> bool:
    suffix = Path(display_path.split("!")[-1]).suffix.lower()
    if suffix in OFFICE_SUFFIXES | IMAGE_SUFFIXES | MEDIA_SUFFIXES | ARCHIVE_SUFFIXES | {".pdf", ".svg"}:
        return True
    return detected_mime(data, suffix) in {"application/pdf", "application/zip", "media/container", "image/svg+xml", "image/png", "image/jpeg", "image/gif"}


def artifact_worker_loop(connection: Any) -> None:
    """Scan complex objects in a reusable process so one parser cannot exceed the object budget."""
    global IN_ARTIFACT_WORKER, PRIVATE_ROOT_OVERRIDE
    IN_ARTIFACT_WORKER = True
    try:
        while True:
            request = connection.recv()
            if request is None:
                return
            repository, policy, collect_raw, data, surface, object_id, display_path, private_root_path, ocr_path, ocr_binding, ocr_budget_remaining = request
            store: OcrCheckpointStore | None = None
            try:
                PRIVATE_ROOT_OVERRIDE = Path(private_root_path).expanduser().resolve()
                if ocr_path and ocr_binding:
                    store = OcrCheckpointStore(Path(ocr_path), ocr_binding)
                worker_state = ScanState(repository, policy, collect_raw=collect_raw, ocr_store=store)
                if ocr_budget_remaining is not None:
                    worker_state.image_ocr_budget_seconds = max(0, int(ocr_budget_remaining))
                    if worker_state.image_ocr_budget_seconds == 0:
                        worker_state.image_ocr_started_at = time.monotonic() - 1
                scan_bytes(
                    worker_state,
                    data,
                    surface=surface,
                    object_id=object_id,
                    display_path=display_path,
                )
                connection.send((
                    "ok",
                    [item.public_dict() for item in worker_state.findings],
                    [item.as_dict() for item in worker_state.coverage],
                    worker_state.object_sha256,
                    worker_state.raw_candidates if collect_raw else [],
                ))
            except Exception:
                connection.send(("error", [], [], {}, []))
            finally:
                if store is not None:
                    store.close()
    except (EOFError, OSError):
        return
    finally:
        connection.close()


class ArtifactProcessRunner:
    """Reuse one isolated artifact scanner and replace it after a timeout or crash."""

    def __init__(self) -> None:
        self.process: Any | None = None
        self.connection: Any | None = None

    def _start(self) -> None:
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe(duplex=True)
        process = context.Process(target=artifact_worker_loop, args=(child,))
        process.daemon = True
        process.start()
        child.close()
        self.process = process
        self.connection = parent

    def _stop(self, *, graceful: bool) -> None:
        process, connection = self.process, self.connection
        self.process, self.connection = None, None
        if process is None:
            return
        if graceful and connection is not None and process.is_alive():
            try:
                connection.send(None)
            except (BrokenPipeError, EOFError, OSError):
                pass
        process.join(timeout=10 if graceful else 0)
        if process.is_alive():
            process.terminate()
            process.join(timeout=10)
        if process.is_alive():
            process.kill()
            process.join(timeout=10)
        if connection is not None:
            connection.close()

    def run(
        self,
        state: ScanState,
        data: bytes,
        *,
        surface: str,
        object_id: str,
        display_path: str,
        ocr_budget_remaining: int | None,
    ) -> None:
        try:
            timeout_seconds = max(1, int(os.environ.get("SAFE_PUBLISH_ARTIFACT_UNIT_TIMEOUT_SECONDS", DEFAULT_ARTIFACT_UNIT_TIMEOUT_SECONDS)))
        except ValueError:
            timeout_seconds = DEFAULT_ARTIFACT_UNIT_TIMEOUT_SECONDS
        if self.process is None or not self.process.is_alive() or self.connection is None:
            self._stop(graceful=False)
            self._start()
        assert self.connection is not None
        ocr_path = str(state.ocr_store.path) if state.ocr_store is not None else None
        ocr_binding = state.ocr_store.binding if state.ocr_store is not None else None
        try:
            self.connection.send((
                state.repository,
                state.policy,
                state.collect_raw,
                data,
                surface,
                object_id,
                display_path,
                str(private_root()),
                ocr_path,
                ocr_binding,
                ocr_budget_remaining,
            ))
            if not self.connection.poll(timeout_seconds):
                self._stop(graceful=False)
                state.add_coverage(surface, "tool_failed", f"artifact-unit-timeout:{object_id}")
                return
            status, findings, coverage, object_sha256, raw_candidates = self.connection.recv()
        except (BrokenPipeError, EOFError, OSError):
            self._stop(graceful=False)
            state.add_coverage(surface, "tool_failed", f"artifact-worker-failed:{object_id}")
            return
        if status != "ok":
            state.add_coverage(surface, "tool_failed", f"artifact-worker-failed:{object_id}")
            return
        temporary_state = ScanState(state.repository, state.policy, collect_raw=state.collect_raw)
        temporary_state.findings = [Finding(**item) for item in findings]
        temporary_state._finding_keys = {
            (item.object, item.location, item.rule_id, item.status) for item in temporary_state.findings
        }
        temporary_state.coverage = [Coverage(**item) for item in coverage]
        temporary_state.object_sha256 = {str(key): str(value) for key, value in object_sha256.items()}
        temporary_state.raw_candidates = [item for item in raw_candidates if isinstance(item, dict)]
        merge_scan_state(state, temporary_state)

    def close(self) -> None:
        self._stop(graceful=True)


ARTIFACT_PROCESS_RUNNER = ArtifactProcessRunner()
atexit.register(ARTIFACT_PROCESS_RUNNER.close)


def scan_bytes_bounded(
    state: ScanState,
    data: bytes,
    *,
    surface: str,
    object_id: str,
    display_path: str,
) -> None:
    if len(data) <= DEFAULT_MAX_FILE_BYTES and complex_artifact(data, display_path):
        ocr_budget_remaining: int | None = None
        if artifact_may_require_ocr(data, display_path):
            if state.image_ocr_started_at is None:
                state.image_ocr_started_at = time.monotonic()
            elapsed = time.monotonic() - state.image_ocr_started_at
            ocr_budget_remaining = max(0, int(state.image_ocr_budget_seconds - elapsed))
        ARTIFACT_PROCESS_RUNNER.run(
            state,
            data,
            surface=surface,
            object_id=object_id,
            display_path=display_path,
            ocr_budget_remaining=ocr_budget_remaining,
        )
        return
    scan_bytes(state, data, surface=surface, object_id=object_id, display_path=display_path)


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


def indexed_gitlinks(source: Path) -> set[str]:
    """Return submodule paths from the index without dereferencing their working directories."""
    staged = run(["git", "ls-files", "--stage", "-z"], source, text=False)
    if staged.returncode != 0:
        return set()
    gitlinks: set[str] = set()
    for entry in staged.stdout.split(b"\x00"):
        metadata, separator, raw_path = entry.partition(b"\t")
        if separator and metadata.startswith(b"160000 "):
            gitlinks.add(raw_path.decode("utf-8", errors="surrogateescape"))
    return gitlinks


def _scan_working_tree_slice(
    state: ScanState,
    source: Path,
    *,
    time_limit_seconds: int | None = None,
    checkpoint_path: Path | None = None,
    checkpoint_interval: int = DEFAULT_WORKTREE_CHECKPOINT_INTERVAL,
) -> None:
    started = time.monotonic()
    gitlinks = indexed_gitlinks(source)
    entries: list[tuple[str, Path, str, str]] = []
    for relative, path in iter_working_tree(source):
        try:
            if relative in gitlinks:
                kind, digest = "gitlink", ""
            elif path.is_symlink():
                kind, digest = "symlink", sha256_bytes(os.readlink(path).encode("utf-8", errors="surrogateescape"))
            else:
                kind, digest = "file", sha256_bytes(path.read_bytes())
            entries.append((relative, path, kind, digest))
        except (OSError, PermissionError):
            state.add_coverage("working-tree", "permission_denied", f"file-inventory-unreadable:{relative}")
            return
        if time_limit_seconds is not None and time.monotonic() - started >= time_limit_seconds:
            state.add_coverage("working-tree", "tool_failed", "working-tree-inventory-time-limit-exceeded")
            return
    inventory = json.dumps(
        [[relative, kind, digest] for relative, _path, kind, digest in entries],
        ensure_ascii=False,
        sort_keys=False,
        separators=(",", ":"),
    ).encode("utf-8")
    binding = {
        "repository": state.repository,
        "source_commit": git_head(source),
        "inventory_sha256": sha256_bytes(inventory),
        "file_count": len(entries),
        "scanner_sha256": state.scanner_sha256,
        "policy_fingerprint": policy_fingerprint(state.policy),
        "collect_raw": state.collect_raw,
    }
    resolved_checkpoint = (
        ensure_private_path(checkpoint_path or default_worktree_checkpoint_path(binding))
        if checkpoint_path is not None or time_limit_seconds is not None
        else None
    )
    work_state = ScanState(state.repository, state.policy, collect_raw=state.collect_raw, ocr_store=state.ocr_store)
    next_file_index = 0
    resumed = False
    complete = False
    if resolved_checkpoint is not None and resolved_checkpoint.exists():
        try:
            document = json.loads(resolved_checkpoint.read_text(encoding="utf-8"))
            if document.get("worktree_checkpoint_schema_version") != WORKTREE_CHECKPOINT_SCHEMA_VERSION or document.get("binding") != binding:
                raise ValueError("Working-tree checkpoint binding mismatch")
            finding_records = read_private_record_pages(resolved_checkpoint, document.get("finding_pages", {}))
            work_state.findings = [Finding(**item) for item in finding_records]
            work_state._finding_keys = {(item.object, item.location, item.rule_id, item.status) for item in work_state.findings}
            work_state.coverage = [Coverage(**item) for item in document.get("coverage", [])]
            work_state.object_sha256 = {str(key): str(value) for key, value in document.get("object_sha256", {}).items()}
            if work_state.collect_raw:
                work_state.raw_candidates = [item for item in document.get("raw_candidates", []) if isinstance(item, dict)]
            next_file_index = max(0, int(document.get("next_file_index", 0)))
            complete = bool(document.get("complete", False))
            if next_file_index > len(entries):
                raise ValueError("Working-tree checkpoint index is invalid")
            resumed = True
        except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError):
            state.add_coverage("working-tree", "tool_failed", "working-tree-checkpoint-invalid-or-mismatched")
            return

    def save_checkpoint(current_index: int, is_complete: bool) -> None:
        if resolved_checkpoint is None:
            return
        pages = write_private_record_pages(
            resolved_checkpoint,
            [item.public_dict() for item in work_state.findings],
            kind="worktree-findings",
        )
        write_json(
            resolved_checkpoint,
            {
                "worktree_checkpoint_schema_version": WORKTREE_CHECKPOINT_SCHEMA_VERSION,
                "binding": binding,
                "next_file_index": current_index,
                "complete": is_complete,
                "updated_at": utc_now(),
                "finding_pages": pages,
                "coverage": [item.as_dict() for item in work_state.coverage],
                "object_sha256": work_state.object_sha256,
                "raw_candidates": work_state.raw_candidates if work_state.collect_raw else [],
            },
            private=True,
        )
        state.worktree_progress = {
            "status": "complete" if is_complete else "in_progress",
            "processed_file_count": current_index,
            "total_file_count": len(entries),
            "resumed": resumed,
        }

    state.worktree_progress = {
        "status": "complete" if complete else "in_progress",
        "processed_file_count": next_file_index,
        "total_file_count": len(entries),
        "resumed": resumed,
    }
    if complete:
        merge_scan_state(state, work_state)
        return

    for index in range(next_file_index, len(entries)):
        if time_limit_seconds is not None and time.monotonic() - started >= time_limit_seconds:
            save_checkpoint(index, False)
            work_state.add_coverage("working-tree", "tool_failed", "working-tree-time-limit-exceeded", index)
            merge_scan_state(state, work_state)
            return
        relative, path, kind, _digest = entries[index]
        object_id = f"working-tree:{relative}"
        if any(fnmatch.fnmatch(relative, pattern) for pattern in work_state.policy["blocked_paths"]):
            rule = Rule("policy.blocked-path", "data", "block", re.compile(r"$^"))
            work_state.add_finding(surface="working-tree", object_id=object_id, location=relative, rule=rule, raw_value=None, legal=is_legal_path(relative))
        # The submodule scanner handles gitlinks and .gitmodules; reading the directory as a file is invalid.
        if kind == "gitlink":
            next_file_index = index + 1
            if checkpoint_interval > 0 and next_file_index % checkpoint_interval == 0:
                save_checkpoint(next_file_index, False)
            continue
        try:
            coverage_start = len(work_state.coverage)
            if kind == "symlink":
                target = os.readlink(path)
                scan_text(work_state, target, surface="working-tree", object_id=object_id, display_path=relative)
                resolved = path.resolve()
                try:
                    resolved.relative_to(source.resolve())
                except ValueError:
                    work_state.add_coverage("working-tree", "unreadable", f"external-symlink:{object_id}")
            else:
                scan_bytes_bounded(work_state, path.read_bytes(), surface="working-tree", object_id=object_id, display_path=relative)
            transient = [
                item for item in work_state.coverage[coverage_start:]
                if item.reason.startswith((
                    "image-ocr-budget-exceeded:",
                    "pdf-page-image-ocr-budget-exceeded:",
                    "image-ocr-unit-timeout:",
                    "pdf-page-image-ocr-unit-timeout:",
                    "artifact-unit-timeout:",
                    "artifact-worker-failed:",
                ))
            ]
            if transient:
                work_state.coverage = [*work_state.coverage[:coverage_start], *[item for item in work_state.coverage[coverage_start:] if item not in transient]]
                save_checkpoint(index, False)
                work_state.coverage.extend(transient)
                merge_scan_state(state, work_state)
                return
        except (OSError, PermissionError):
            work_state.add_coverage("working-tree", "permission_denied", f"file-unreadable:{object_id}")
        next_file_index = index + 1
        if checkpoint_interval > 0 and next_file_index % checkpoint_interval == 0:
            save_checkpoint(next_file_index, False)
    work_state.add_coverage("working-tree", "checked", object_count=len(entries))
    save_checkpoint(len(entries), True)
    merge_scan_state(state, work_state)


def worktree_worker_result_document(state: ScanState) -> dict[str, Any]:
    return {
        "findings": [item.public_dict() for item in state.findings],
        "coverage": [item.as_dict() for item in state.coverage],
        "object_sha256": state.object_sha256,
        "raw_candidates": state.raw_candidates if state.collect_raw else [],
        "worktree_progress": state.worktree_progress,
    }


def restore_worktree_worker_result(state: ScanState, document: dict[str, Any]) -> None:
    findings = [Finding(**item) for item in document.get("findings", [])]
    coverage = [Coverage(**item) for item in document.get("coverage", [])]
    state.replay_redacted_result(findings, coverage)
    state.object_sha256.update({str(key): str(value) for key, value in document.get("object_sha256", {}).items()})
    if state.collect_raw:
        for candidate in document.get("raw_candidates", []):
            if not isinstance(candidate, dict):
                continue
            key = (
                str(candidate.get("repository", "")),
                str(candidate.get("surface", "")),
                str(candidate.get("object", "")),
                str(candidate.get("rule_id", "")),
                str(candidate.get("raw_value", "")),
            )
            if key not in state._candidate_keys:
                state._candidate_keys.add(key)
                state.raw_candidates.append(candidate)
        state._raw_candidate_total = max(state._raw_candidate_total, len(state.raw_candidates))
    progress = document.get("worktree_progress")
    if isinstance(progress, dict):
        state.worktree_progress = progress


def command_scan_worktree_worker(args: argparse.Namespace) -> int:
    task_path = ensure_private_path(Path(args.task).expanduser().resolve())
    task = json.loads(task_path.read_text(encoding="utf-8"))
    result_path = ensure_private_path(Path(task["result"]).expanduser().resolve())
    source = Path(task["source"]).expanduser().resolve()
    policy = validate_policy(task["policy"])
    store: OcrCheckpointStore | None = None
    try:
        if task.get("ocr_path") and task.get("ocr_binding"):
            store = OcrCheckpointStore(Path(task["ocr_path"]), task["ocr_binding"])
        worker_state = ScanState(
            str(task["repository"]),
            policy,
            collect_raw=bool(task.get("collect_raw", False)),
            ocr_store=store,
        )
        _scan_working_tree_slice(
            worker_state,
            source,
            time_limit_seconds=int(task["slice_time_limit_seconds"]),
            checkpoint_path=Path(task["checkpoint"]) if task.get("checkpoint") else None,
            checkpoint_interval=max(1, int(task.get("checkpoint_interval", DEFAULT_WORKTREE_CHECKPOINT_INTERVAL))),
        )
        write_json(result_path, worktree_worker_result_document(worker_state), private=True)
    finally:
        if store is not None:
            store.close()
    return 0


def scan_working_tree(
    state: ScanState,
    source: Path,
    *,
    time_limit_seconds: int | None = None,
    checkpoint_path: Path | None = None,
    checkpoint_interval: int = DEFAULT_WORKTREE_CHECKPOINT_INTERVAL,
) -> None:
    if time_limit_seconds is None or time_limit_seconds <= 0:
        _scan_working_tree_slice(
            state,
            source,
            time_limit_seconds=time_limit_seconds,
            checkpoint_path=checkpoint_path,
            checkpoint_interval=checkpoint_interval,
        )
        return

    worker_root = ensure_private_path(private_root() / "worktree-workers")
    worker_root.mkdir(parents=True, exist_ok=True)
    restrict_private_path(worker_root, directory=True)
    token = sha256_bytes(f"{os.getpid()}:{time.time_ns()}:{source}".encode("utf-8", errors="surrogateescape"))
    task_path = worker_root / f"{token}.task.private.json"
    result_path = worker_root / f"{token}.result.private.json"
    write_json(
        task_path,
        {
            "repository": state.repository,
            "policy": state.policy,
            "collect_raw": state.collect_raw,
            "source": str(source),
            "checkpoint": str(checkpoint_path) if checkpoint_path is not None else None,
            "checkpoint_interval": max(1, min(checkpoint_interval, 5)),
            "slice_time_limit_seconds": max(0, time_limit_seconds - 1),
            "ocr_path": str(state.ocr_store.path) if state.ocr_store is not None else None,
            "ocr_binding": state.ocr_store.binding if state.ocr_store is not None else None,
            "result": str(result_path),
        },
        private=True,
    )
    try:
        try:
            worker = run(
                [sys.executable, str(Path(__file__).resolve()), "_scan-worktree-worker", "--task", str(task_path)],
                timeout_seconds=max(1, time_limit_seconds),
            )
        except subprocess.TimeoutExpired:
            state.add_coverage("working-tree", "tool_failed", "working-tree-hard-time-limit-exceeded")
            return
        if worker.returncode != 0 or not result_path.is_file():
            state.add_coverage("working-tree", "tool_failed", "working-tree-worker-failed")
            return
        try:
            restore_worktree_worker_result(state, json.loads(result_path.read_text(encoding="utf-8")))
        except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError):
            state.add_coverage("working-tree", "tool_failed", "working-tree-worker-result-invalid")
    finally:
        for temporary in (task_path, result_path):
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def git_head(source: Path) -> str | None:
    result = run(["git", "rev-parse", "HEAD"], source)
    return result.stdout.strip() if result.returncode == 0 else None


def merge_scan_state(target: ScanState, source: ScanState) -> None:
    for finding in source.findings:
        key = (finding.object, finding.location, finding.rule_id, finding.status)
        if key not in target._finding_keys:
            target._finding_keys.add(key)
            target.findings.append(finding)
    target.coverage.extend(source.coverage)
    target.object_sha256.update(source.object_sha256)
    for candidate in source.raw_candidates:
        key = (
            str(candidate.get("repository", "")),
            str(candidate.get("surface", "")),
            str(candidate.get("object", "")),
            str(candidate.get("rule_id", "")),
            str(candidate.get("raw_value", "")),
        )
        if key not in target._candidate_keys:
            target._candidate_keys.add(key)
            target.raw_candidates.append(candidate)
    target._raw_candidate_total = max(target._raw_candidate_total, len(target.raw_candidates))


def write_private_record_pages(
    base_path: Path,
    records: list[dict[str, Any]],
    *,
    kind: str,
    page_size: int = DEFAULT_FINDING_PAGE_SIZE,
) -> dict[str, Any]:
    resolved = ensure_private_path(base_path)
    pages: list[dict[str, Any]] = []
    for offset in range(0, len(records), page_size):
        page_records = records[offset:offset + page_size]
        payload = {
            "schema_version": SCHEMA_VERSION,
            "kind": kind,
            "page_index": len(pages) + 1,
            "records": page_records,
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = sha256_bytes(encoded)
        page_name = f".{resolved.stem}.{kind}-{len(pages) + 1:05d}-{digest[:16]}.private.json"
        page_path = resolved.with_name(page_name)
        write_json(page_path, payload, private=True)
        pages.append({"file": page_name, "sha256": digest, "record_count": len(page_records)})
    return {
        "kind": kind,
        "record_count": len(records),
        "page_size": page_size,
        "page_count": len(pages),
        "pages": pages,
    }


def write_paginated_private_report(path: Path, report: dict[str, Any]) -> dict[str, Any]:
    """Write a private report manifest whose findings are losslessly stored in verified pages."""
    resolved = ensure_private_path(path)
    records = list(report.get("findings", []))
    finding_pages = write_private_record_pages(
        resolved,
        records,
        kind="gate-findings",
    )
    manifest = {key: value for key, value in report.items() if key != "findings"}
    manifest["finding_pages"] = finding_pages
    write_json(resolved, manifest, private=True)
    return manifest


def read_private_record_pages(base_path: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    resolved = ensure_private_path(base_path)
    records: list[dict[str, Any]] = []
    for page in manifest.get("pages", []):
        page_path = ensure_private_path(resolved.with_name(str(page["file"])))
        encoded = page_path.read_bytes()
        if sha256_bytes(encoded.rstrip(b"\r\n")) != page["sha256"]:
            # write_json adds one newline; verify the canonical payload when the byte digest differs.
            document = json.loads(encoded.decode("utf-8"))
            canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if sha256_bytes(canonical) != page["sha256"]:
                raise ValueError("Private finding page digest mismatch")
        else:
            document = json.loads(encoded.decode("utf-8"))
        page_records = document.get("records", [])
        if not isinstance(page_records, list) or len(page_records) != int(page["record_count"]):
            raise ValueError("Private finding page is invalid")
        records.extend(item for item in page_records if isinstance(item, dict))
    if len(records) != int(manifest.get("record_count", -1)):
        raise ValueError("Private finding page count mismatch")
    return records


def history_checkpoint_binding(
    state: ScanState,
    source: Path,
    object_inventory: bytes,
    object_count: int,
) -> dict[str, Any]:
    return {
        "repository": state.repository,
        "source_commit": git_head(source),
        "object_inventory_sha256": sha256_bytes(object_inventory),
        "object_count": object_count,
        "scanner_sha256": state.scanner_sha256,
        "policy_fingerprint": policy_fingerprint(state.policy),
        "collect_raw": state.collect_raw,
    }


def ocr_checkpoint_binding(repository: str, source: Path, policy: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "ocr_checkpoint_schema_version": OCR_CHECKPOINT_SCHEMA_VERSION,
        "repository": repository,
        "source_commit": git_head(source),
        "scanner_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "policy_fingerprint": policy_fingerprint(policy),
    }


def default_ocr_checkpoint_path(binding: dict[str, Any]) -> Path:
    encoded = json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return private_root() / "ocr-checkpoints" / f"{sha256_bytes(encoded)}.private.sqlite"


def default_history_checkpoint_path(binding: dict[str, Any]) -> Path:
    encoded = json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return private_root() / "history-checkpoints" / f"{sha256_bytes(encoded)}.private.json"


def default_worktree_checkpoint_path(binding: dict[str, Any]) -> Path:
    encoded = json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return private_root() / "worktree-checkpoints" / f"{sha256_bytes(encoded)}.private.json"


def history_checkpoint_document(
    state: ScanState,
    binding: dict[str, Any],
    *,
    phase: str,
    next_object_index: int,
    blob_count: int,
    finding_pages: dict[str, Any],
) -> dict[str, Any]:
    return {
        "history_checkpoint_schema_version": HISTORY_CHECKPOINT_SCHEMA_VERSION,
        "binding": binding,
        "phase": phase,
        "next_object_index": next_object_index,
        "blob_count": blob_count,
        "updated_at": utc_now(),
        "finding_pages": finding_pages,
        "coverage": [item.as_dict() for item in state.coverage],
        "object_sha256": state.object_sha256,
        "raw_candidates": state.raw_candidates if state.collect_raw else [],
    }


def restore_history_checkpoint(state: ScanState, checkpoint_path: Path, document: dict[str, Any]) -> tuple[str, int, int]:
    finding_records = document.get("findings", [])
    if "finding_pages" in document:
        finding_records = read_private_record_pages(checkpoint_path, document["finding_pages"])
    for item in finding_records:
        finding = Finding(**item)
        key = (finding.object, finding.location, finding.rule_id, finding.status)
        if key not in state._finding_keys:
            state._finding_keys.add(key)
            state.findings.append(finding)
    state.coverage.extend(Coverage(**item) for item in document.get("coverage", []))
    state.object_sha256.update({str(key): str(value) for key, value in document.get("object_sha256", {}).items()})
    if state.collect_raw:
        state.raw_candidates.extend(item for item in document.get("raw_candidates", []) if isinstance(item, dict))
        state._candidate_keys.update(
            (
                str(item.get("repository", "")),
                str(item.get("surface", "")),
                str(item.get("object", "")),
                str(item.get("rule_id", "")),
                str(item.get("raw_value", "")),
            )
            for item in state.raw_candidates
        )
        state._raw_candidate_total = len(state.raw_candidates)
    return (
        str(document.get("phase", "objects")),
        max(0, int(document.get("next_object_index", 0))),
        max(0, int(document.get("blob_count", 0))),
    )


def _scan_git_history_slice(
    state: ScanState,
    source: Path,
    *,
    time_limit_seconds: int | None = None,
    checkpoint_path: Path | None = None,
    checkpoint_interval: int = DEFAULT_HISTORY_CHECKPOINT_INTERVAL,
) -> None:
    started = time.monotonic()
    inventory_timeout = (
        max(1, time_limit_seconds)
        if time_limit_seconds is not None and time_limit_seconds > 0
        else None
    )
    history_state = ScanState(
        state.repository,
        state.policy,
        collect_raw=state.collect_raw,
        ocr_store=state.ocr_store,
    )

    def time_exceeded() -> bool:
        return time_limit_seconds is not None and time.monotonic() - started >= time_limit_seconds

    try:
        shallow = run(
            ["git", "rev-parse", "--is-shallow-repository"],
            source,
            timeout_seconds=inventory_timeout,
        )
    except subprocess.TimeoutExpired:
        state.add_coverage("git-history", "tool_failed", "git-history-time-limit-exceeded")
        return
    if shallow.returncode != 0:
        state.add_coverage("git-history", "tool_failed", "git-repository-unavailable")
        return
    if shallow.stdout.strip().lower() == "true":
        state.add_coverage("git-history", "unreadable", "shallow-history")
        return
    try:
        objects = run(
            ["git", "rev-list", "--objects", "--all"],
            source,
            text=False,
            timeout_seconds=inventory_timeout,
        )
    except subprocess.TimeoutExpired:
        state.add_coverage("git-history", "tool_failed", "git-history-time-limit-exceeded")
        return
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
    binding = history_checkpoint_binding(state, source, objects.stdout, len(object_entries))
    resolved_checkpoint = (
        ensure_private_path(checkpoint_path or default_history_checkpoint_path(binding))
        if checkpoint_path is not None or time_limit_seconds is not None
        else None
    )
    phase, next_object_index, blob_count = "objects", 0, 0
    resumed = False
    if resolved_checkpoint is not None and resolved_checkpoint.exists():
        try:
            document = json.loads(resolved_checkpoint.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            state.add_coverage("git-history", "tool_failed", "git-history-checkpoint-invalid")
            return
        if (
            document.get("history_checkpoint_schema_version") != HISTORY_CHECKPOINT_SCHEMA_VERSION
            or document.get("binding") != binding
        ):
            state.add_coverage("git-history", "tool_failed", "git-history-checkpoint-binding-mismatch")
            return
        try:
            phase, next_object_index, blob_count = restore_history_checkpoint(history_state, resolved_checkpoint, document)
        except (TypeError, ValueError, KeyError):
            state.add_coverage("git-history", "tool_failed", "git-history-checkpoint-invalid")
            return
        if next_object_index > len(object_entries) or phase not in {"objects", "refs", "complete"}:
            state.add_coverage("git-history", "tool_failed", "git-history-checkpoint-invalid")
            return
        resumed = True
    state.history_progress = {
        "status": "complete" if phase == "complete" else "in_progress",
        "processed_object_count": next_object_index,
        "total_object_count": len(object_entries),
        "resumed": resumed,
    }
    if phase == "complete":
        merge_scan_state(state, history_state)
        return

    def save_checkpoint(current_phase: str, current_index: int) -> None:
        if resolved_checkpoint is None:
            return
        finding_pages = write_private_record_pages(
            resolved_checkpoint,
            [item.public_dict() for item in history_state.findings],
            kind="history-findings",
        )
        write_json(
            resolved_checkpoint,
            history_checkpoint_document(
                history_state,
                binding,
                phase=current_phase,
                next_object_index=current_index,
                blob_count=blob_count,
                finding_pages=finding_pages,
            ),
            private=True,
        )
        state.history_progress = {
            "status": "complete" if current_phase == "complete" else "in_progress",
            "processed_object_count": current_index,
            "total_object_count": len(object_entries),
            "resumed": resumed,
        }

    process: subprocess.Popen[bytes] | None = None
    try:
        if phase == "objects":
            process = subprocess.Popen(
                ["git", "cat-file", "--batch"],
                cwd=str(source),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert process.stdin is not None and process.stdout is not None
            for index in range(next_object_index, len(object_entries)):
                if time_exceeded():
                    save_checkpoint("objects", index)
                    history_state.add_coverage("git-history", "tool_failed", "git-history-time-limit-exceeded", blob_count)
                    merge_scan_state(state, history_state)
                    return
                oid, path = object_entries[index]
                process.stdin.write(f"{oid}\n".encode("ascii"))
                process.stdin.flush()
                header = process.stdout.readline().decode("ascii", errors="replace").strip()
                parts = header.split()
                if len(parts) < 3 or parts[1] == "missing":
                    history_state.add_coverage("git-history", "unreadable", f"git-object-unreadable:{oid}")
                else:
                    object_type, size_text = parts[1], parts[2]
                    try:
                        size = int(size_text)
                    except ValueError:
                        history_state.add_coverage("git-history", "tool_failed", f"git-object-header-invalid:{oid}")
                        size = 0
                    content = process.stdout.read(size)
                    process.stdout.read(1)
                    if object_type in {"commit", "tag"}:
                        scan_text(
                            history_state,
                            content.decode("utf-8", errors="replace"),
                            surface="git-metadata",
                            object_id=f"git-{object_type}:{oid}",
                            display_path=f"git-{object_type}:{oid[:12]}",
                        )
                    elif object_type == "blob":
                        blob_count += 1
                        display = path or f"blob-{oid[:12]}"
                        coverage_start = len(history_state.coverage)
                        scan_bytes_bounded(
                            history_state,
                            content,
                            surface="git-history",
                            object_id=f"git:{oid}:{display}",
                            display_path=display,
                        )
                        transient_ocr_gaps = [
                            item
                            for item in history_state.coverage[coverage_start:]
                            if item.reason.startswith((
                                "image-ocr-budget-exceeded:",
                                "pdf-page-image-ocr-budget-exceeded:",
                                "image-ocr-unit-timeout:",
                                "pdf-page-image-ocr-unit-timeout:",
                                "artifact-unit-timeout:",
                                "artifact-worker-failed:",
                            ))
                        ]
                        if transient_ocr_gaps:
                            history_state.coverage = [
                                *history_state.coverage[:coverage_start],
                                *[
                                    item
                                    for item in history_state.coverage[coverage_start:]
                                    if item not in transient_ocr_gaps
                                ],
                            ]
                            save_checkpoint("objects", index)
                            history_state.coverage.extend(transient_ocr_gaps)
                            merge_scan_state(state, history_state)
                            return
                next_object_index = index + 1
                if checkpoint_interval > 0 and next_object_index % checkpoint_interval == 0:
                    save_checkpoint("objects", next_object_index)
            process.stdin.close()
            process.wait(timeout=30)
            process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            process = None
            phase = "refs"
            save_checkpoint(phase, len(object_entries))
        if time_exceeded():
            history_state.add_coverage("git-history", "tool_failed", "git-history-time-limit-exceeded", blob_count)
            merge_scan_state(state, history_state)
            return
        history_state.coverage = [
            item for item in history_state.coverage if not item.reason.startswith("git-ref-enumeration-")
        ]
        remaining_seconds = None
        if time_limit_seconds is not None:
            remaining_seconds = max(1, int(time_limit_seconds - (time.monotonic() - started)))
        coverage_before_refs = len(history_state.coverage)
        scan_git_refs(history_state, source, timeout_seconds=remaining_seconds)
        ref_coverage = history_state.coverage[coverage_before_refs:]
        if any(item.status not in {"checked", "not_present"} for item in ref_coverage):
            save_checkpoint("refs", len(object_entries))
            merge_scan_state(state, history_state)
            return
        history_state.add_coverage("git-history", "checked", object_count=blob_count)
        save_checkpoint("complete", len(object_entries))
        merge_scan_state(state, history_state)
    except (OSError, subprocess.SubprocessError, AssertionError):
        if process is not None:
            process.kill()
        history_state.add_coverage("git-history", "tool_failed", "git-cat-file-failed")
        merge_scan_state(state, history_state)
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=30)
            except subprocess.SubprocessError:
                pass
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def history_worker_result_document(state: ScanState) -> dict[str, Any]:
    return {
        "findings": [item.public_dict() for item in state.findings],
        "coverage": [item.as_dict() for item in state.coverage],
        "object_sha256": state.object_sha256,
        "raw_candidates": state.raw_candidates if state.collect_raw else [],
        "history_progress": state.history_progress,
    }


def restore_history_worker_result(state: ScanState, document: dict[str, Any]) -> None:
    findings = [Finding(**item) for item in document.get("findings", [])]
    coverage = [Coverage(**item) for item in document.get("coverage", [])]
    state.replay_redacted_result(findings, coverage)
    state.object_sha256.update({str(key): str(value) for key, value in document.get("object_sha256", {}).items()})
    if state.collect_raw:
        for candidate in document.get("raw_candidates", []):
            if not isinstance(candidate, dict):
                continue
            key = (
                str(candidate.get("repository", "")),
                str(candidate.get("surface", "")),
                str(candidate.get("object", "")),
                str(candidate.get("rule_id", "")),
                str(candidate.get("raw_value", "")),
            )
            if key not in state._candidate_keys:
                state._candidate_keys.add(key)
                state.raw_candidates.append(candidate)
        state._raw_candidate_total = max(state._raw_candidate_total, len(state.raw_candidates))
    progress = document.get("history_progress")
    if isinstance(progress, dict):
        state.history_progress = progress


def command_scan_git_history_worker(args: argparse.Namespace) -> int:
    task_path = ensure_private_path(Path(args.task).expanduser().resolve())
    task = json.loads(task_path.read_text(encoding="utf-8"))
    result_path = ensure_private_path(Path(task["result"]).expanduser().resolve())
    source = Path(task["source"]).expanduser().resolve()
    policy = validate_policy(task["policy"])
    store: OcrCheckpointStore | None = None
    try:
        if task.get("ocr_path") and task.get("ocr_binding"):
            store = OcrCheckpointStore(Path(task["ocr_path"]), task["ocr_binding"])
        worker_state = ScanState(
            str(task["repository"]),
            policy,
            collect_raw=bool(task.get("collect_raw", False)),
            ocr_store=store,
        )
        _scan_git_history_slice(
            worker_state,
            source,
            time_limit_seconds=int(task["slice_time_limit_seconds"]),
            checkpoint_path=Path(task["checkpoint"]) if task.get("checkpoint") else None,
            checkpoint_interval=max(1, int(task.get("checkpoint_interval", DEFAULT_HISTORY_CHECKPOINT_INTERVAL))),
        )
        write_json(result_path, history_worker_result_document(worker_state), private=True)
    finally:
        if store is not None:
            store.close()
    return 0


def scan_git_history(
    state: ScanState,
    source: Path,
    *,
    time_limit_seconds: int | None = None,
    checkpoint_path: Path | None = None,
    checkpoint_interval: int = DEFAULT_HISTORY_CHECKPOINT_INTERVAL,
) -> None:
    if time_limit_seconds is None or time_limit_seconds <= 0:
        _scan_git_history_slice(
            state,
            source,
            time_limit_seconds=time_limit_seconds,
            checkpoint_path=checkpoint_path,
            checkpoint_interval=checkpoint_interval,
        )
        return

    worker_root = ensure_private_path(private_root() / "git-history-workers")
    worker_root.mkdir(parents=True, exist_ok=True)
    restrict_private_path(worker_root, directory=True)
    token = sha256_bytes(f"{os.getpid()}:{time.time_ns()}:{source}".encode("utf-8", errors="surrogateescape"))
    task_path = worker_root / f"{token}.task.private.json"
    result_path = worker_root / f"{token}.result.private.json"
    write_json(
        task_path,
        {
            "repository": state.repository,
            "policy": state.policy,
            "collect_raw": state.collect_raw,
            "source": str(source),
            "checkpoint": str(checkpoint_path) if checkpoint_path is not None else None,
            "checkpoint_interval": max(1, min(checkpoint_interval, 100)),
            "slice_time_limit_seconds": max(0, time_limit_seconds - 1),
            "ocr_path": str(state.ocr_store.path) if state.ocr_store is not None else None,
            "ocr_binding": state.ocr_store.binding if state.ocr_store is not None else None,
            "result": str(result_path),
        },
        private=True,
    )
    try:
        try:
            worker = run(
                [sys.executable, str(Path(__file__).resolve()), "_scan-git-history-worker", "--task", str(task_path)],
                timeout_seconds=max(1, time_limit_seconds),
            )
        except subprocess.TimeoutExpired:
            state.add_coverage("git-history", "tool_failed", "git-history-hard-time-limit-exceeded")
            return
        if worker.returncode != 0 or not result_path.is_file():
            state.add_coverage("git-history", "tool_failed", "git-history-worker-failed")
            return
        try:
            restore_history_worker_result(state, json.loads(result_path.read_text(encoding="utf-8")))
        except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError):
            state.add_coverage("git-history", "tool_failed", "git-history-worker-result-invalid")
    finally:
        for temporary in (task_path, result_path):
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def scan_git_refs(state: ScanState, source: Path, *, timeout_seconds: int | None = None) -> None:
    try:
        refs = run(
            ["git", "for-each-ref", "--format=%(refname)%00%(objectname)%00%(objecttype)%00%(taggername)%00%(taggeremail)%00%(contents)%00%1e"],
            source,
            text=False,
            timeout_seconds=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        state.add_coverage("git-metadata", "tool_failed", "git-ref-enumeration-time-limit-exceeded")
        return
    if refs.returncode != 0:
        state.add_coverage("git-metadata", "tool_failed", "git-ref-enumeration-failed")
        return
    count = 0
    for record in refs.stdout.split(b"\x1e\n"):
        fields = record.strip(b"\x00\r\n").split(b"\x00", 5)
        if len(fields) != 6:
            continue
        refname, oid, object_type, tagger_name, tagger_email, contents = fields
        ref_text = refname.decode("utf-8", errors="replace")
        if not ref_text:
            continue
        count += 1
        object_id = f"git-ref:{ref_text}"
        for label, value in (("name", refname), ("tagger-name", tagger_name), ("tagger-email", tagger_email), ("contents", contents)):
            decoded = value.decode("utf-8", errors="replace")
            if decoded:
                scan_text(state, decoded, surface="git-metadata", object_id=f"{object_id}:{label}", display_path=f"{ref_text}:{label}")
    state.add_coverage("git-metadata", "checked" if count else "not_present", object_count=count)


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


def stable_gitleaks_object_id(source: Path, commit: str, path: str) -> str | None:
    """Bind a Git finding to file content instead of transient candidate commit metadata."""
    normalized_path = path.replace("\\", "/")
    if re.fullmatch(r"[0-9a-f]{40,64}", commit):
        resolved = run(["git", "rev-parse", "--verify", f"{commit}:{normalized_path}"], source)
        blob_oid = resolved.stdout.strip().lower()
        if resolved.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", blob_oid):
            return f"gitleaks-blob:{blob_oid}:{normalized_path}"
    worktree_path = source / Path(normalized_path)
    try:
        if worktree_path.is_file():
            return f"gitleaks-worktree:{sha256_bytes(worktree_path.read_bytes())}:{normalized_path}"
    except OSError:
        pass
    return None


def run_gitleaks(state: ScanState, source: Path, binary: Path | None = None) -> None:
    try:
        executable = binary or ensure_gitleaks()
    except Exception:
        state.add_coverage("gitleaks", "tool_failed", "gitleaks-install-or-verification-failed")
        return
    executable_key = f"{executable.resolve()}:{sha256_bytes(executable.read_bytes())}"
    if executable_key not in VERIFIED_GITLEAKS:
        with tempfile.TemporaryDirectory(prefix="safe-publish-gitleaks-canary-") as canary_temporary:
            canary_root = Path(canary_temporary)
            marker = "gh" + "p_" + "7H4G2J9K5M8N3P6Q1R4S7T0V2W5X8Y6Z9B3C"
            (canary_root / "canary.txt").write_text("GITHUB_TOKEN=" + marker + "\n", encoding="utf-8")
            canary_report = canary_root / "report.json"
            try:
                canary = run([
                    str(executable), "dir", "--no-banner", "--no-color", "--redact=100",
                    "--report-format", "json", "--report-path", str(canary_report), str(canary_root),
                ], timeout_seconds=60)
            except subprocess.TimeoutExpired:
                state.add_coverage("gitleaks", "tool_failed", "gitleaks-canary-timeout")
                return
            try:
                canary_records = json.loads(canary_report.read_text(encoding="utf-8")) if canary_report.exists() else []
            except (OSError, json.JSONDecodeError):
                canary_records = []
            if canary.returncode not in {0, 1} or not canary_records:
                state.add_coverage("gitleaks", "tool_failed", "gitleaks-runtime-canary-not-detected")
                return
        VERIFIED_GITLEAKS.add(executable_key)
    with tempfile.TemporaryDirectory(prefix="safe-publish-gitleaks-") as temporary:
        report = Path(temporary) / "report.json"
        try:
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
                ],
                timeout_seconds=330,
            )
        except subprocess.TimeoutExpired:
            state.add_coverage("gitleaks", "tool_failed", "gitleaks-process-timeout")
            return
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
            object_id = stable_gitleaks_object_id(source, commit, path)
            if object_id is None:
                state.add_coverage("gitleaks", "unreadable", "gitleaks-object-binding-failed")
                object_id = f"gitleaks-unbound:{path}"
            state.add_finding(
                surface="gitleaks",
                object_id=object_id,
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


def coverage_risk_level(item: Coverage) -> str:
    if item.status in {"checked", "not_present"}:
        return "none"
    return "noncritical" if item.surface in NONCRITICAL_COVERAGE_SURFACES else "critical"


def consolidated_coverage(coverage: list[Coverage]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in sorted(coverage, key=lambda value: (value.surface, value.status, value.reason)):
        record = item.as_dict()
        record["risk_level"] = coverage_risk_level(item)
        result.append(record)
    return result


def coverage_issue_codes(coverage: list[Coverage]) -> list[str]:
    codes: set[str] = set()
    for item in coverage:
        reason = item.reason.split(":", 1)[0]
        if reason in {"git-history-time-limit-exceeded", "git-history-hard-time-limit-exceeded"}:
            codes.add("GIT_HISTORY_TIMEOUT")
        elif reason in {"git-history-worker-failed", "scanner-crashed"}:
            codes.add("SCANNER_CRASHED")
        elif reason == "gate-report-missing":
            codes.add("GATE_REPORT_MISSING")
    return sorted(codes)


def decision_for(state: ScanState, *, force_incomplete: bool = False) -> str:
    if force_incomplete or any(item.status not in {"checked", "not_present"} for item in state.coverage):
        return "incomplete"
    unresolved = [item for item in state.findings if item.status not in {"approved", "excepted"}]
    if any(item.status == "block" for item in unresolved):
        return "block"
    if any(item.status == "review" for item in unresolved):
        return "review"
    return "pass"


def finding_risk_level(finding: Finding) -> str:
    if finding.status in {"approved", "excepted"}:
        return "none"
    if finding.legal_protected or finding.rule_id not in NONCRITICAL_FINDING_RULES:
        return "critical"
    return "noncritical"


def risk_acceptance_status(state: ScanState, finding: Finding) -> str:
    if finding_risk_level(finding) != "noncritical":
        return "not-eligible"
    matches = [
        item
        for item in state.policy["risk_acceptances"]
        if item["repository"] == state.repository and item["rule_id"] == finding.rule_id and item["object"] == finding.object
    ]
    if not matches:
        return "missing"
    now = dt.datetime.now(dt.timezone.utc)
    observed_digest = state.object_sha256.get(finding.object)
    observed_statuses: set[str] = set()
    for acceptance in matches:
        expires = dt.datetime.fromisoformat(acceptance["expires_at"].replace("Z", "+00:00"))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=dt.timezone.utc)
        if expires <= now:
            observed_statuses.add("expired")
            continue
        if acceptance["scanner_sha256"] != state.scanner_sha256:
            observed_statuses.add("scanner-changed")
            continue
        if observed_digest is None or acceptance["object_sha256"] != observed_digest:
            observed_statuses.add("object-changed")
            continue
        return "active"
    for status in ("expired", "scanner-changed", "object-changed"):
        if status in observed_statuses:
            return status
    return "missing"


def publication_decision_for(
    state: ScanState,
    *,
    release_profile: str = "permissive-noncritical",
    force_incomplete: bool = False,
) -> str:
    if release_profile not in RELEASE_PROFILES:
        raise ValueError("Release profile is unknown")
    audit_decision = decision_for(state, force_incomplete=force_incomplete)
    if release_profile == "strict":
        return "allow" if audit_decision == "pass" else "deny"
    if force_incomplete:
        return "deny"
    if any(coverage_risk_level(item) == "critical" for item in state.coverage):
        return "deny"
    unresolved = [item for item in state.findings if item.status not in {"approved", "excepted"}]
    for finding in unresolved:
        if finding_risk_level(finding) == "critical":
            return "deny"
    return "allow" if audit_decision == "pass" else "allow_with_risk"


def sorted_findings(state: ScanState) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in sorted(
        state.findings,
        key=lambda value: (value.repository, value.surface, value.object, value.location, value.rule_id, value.status),
    ):
        record = item.public_dict()
        record["risk_level"] = finding_risk_level(item)
        if record["risk_level"] == "noncritical":
            record["risk_acceptance"] = risk_acceptance_status(state, item)
        result.append(record)
    return result


def gate_result_explanation(
    decision: str,
    publication_decision: str,
    summary: dict[str, int],
) -> dict[str, str]:
    if summary["critical_finding_count"]:
        match_reason = "At least one unresolved finding matched a fixed critical rule"
    elif summary["critical_coverage_gap_count"]:
        match_reason = "At least one required publication surface was not completely inspected"
    elif summary["noncritical_finding_count"] or summary["noncritical_coverage_gap_count"]:
        match_reason = "Only fixed-matrix noncritical findings or auxiliary-surface gaps remain"
    else:
        match_reason = "Every declared publication surface was checked and no unresolved finding remains"
    if publication_decision == "deny":
        publication_effect = "The exact GitHub write must stop"
        next_step = "Repair the critical finding or restore the missing required coverage, then rerun the gate on the identical source"
    elif publication_decision == "allow_with_risk":
        publication_effect = "The exact GitHub write may continue after explicit authorization while the noncritical risk remains reported"
        next_step = "Retain the private report and review the noncritical items without blocking this publication"
    else:
        publication_effect = "The exact GitHub write may continue after explicit authorization"
        next_step = "Verify the remote commit and required checks after the write"
    return {
        "count_source": "finding counts come from normalized scanner records; coverage-gap counts come from declared surfaces whose status is neither checked nor not_present",
        "match_reason": match_reason,
        "publication_effect": publication_effect,
        "next_step": next_step,
        "strict_audit_context": f"The strict audit decision is {decision}; it remains separate from the publication decision",
    }


def gate_report(
    state: ScanState,
    source: Path,
    policy: dict[str, Any] | None,
    *,
    release_profile: str = "permissive-noncritical",
    force_incomplete: bool = False,
) -> dict[str, Any]:
    decision = decision_for(state, force_incomplete=force_incomplete)
    publication_decision = publication_decision_for(
        state,
        release_profile=release_profile,
        force_incomplete=force_incomplete,
    )
    findings = sorted_findings(state)
    coverage = consolidated_coverage(state.coverage)
    summary = {
        "finding_count": len(state.findings),
        "block_count": sum(item.status == "block" for item in state.findings),
        "review_count": sum(item.status == "review" for item in state.findings),
        "approved_count": sum(item.status in {"approved", "excepted"} for item in state.findings),
        "coverage_gap_count": sum(item.status not in {"checked", "not_present"} for item in state.coverage),
        "critical_finding_count": sum(item["risk_level"] == "critical" for item in findings),
        "noncritical_finding_count": sum(item["risk_level"] == "noncritical" for item in findings),
        "accepted_risk_count": sum(item.get("risk_acceptance") == "active" for item in findings),
        "critical_coverage_gap_count": sum(item["risk_level"] == "critical" for item in coverage),
        "noncritical_coverage_gap_count": sum(item["risk_level"] == "noncritical" for item in coverage),
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "mode": "exact-publication-gate",
        "decision": decision,
        "publication_decision": publication_decision,
        "release_profile": release_profile,
        "repository": state.repository,
        "source_commit": git_head(source),
        "scanner_versions": {
            "safe_publish": "3",
            "safe_publish_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "image_ocr_budget_seconds": state.image_ocr_budget_seconds,
            "gitleaks": GITLEAKS_VERSION,
            "python": platform.python_version(),
        },
        "policy_fingerprint": policy_fingerprint(policy),
        "history_progress": (
            {key: value for key, value in state.history_progress.items() if key != "resumed"}
            if state.history_progress is not None
            else None
        ),
        "worktree_progress": (
            {key: value for key, value in state.worktree_progress.items() if key != "resumed"}
            if state.worktree_progress is not None
            else None
        ),
        "coverage": coverage,
        "issue_codes": coverage_issue_codes(state.coverage),
        "findings": findings,
        "summary": summary,
        "result_explanation": gate_result_explanation(decision, publication_decision, summary),
    }
    stable = {key: value for key, value in report.items() if key not in {"generated_at", "report_fingerprint"}}
    report["report_fingerprint"] = sha256_bytes(json.dumps(stable, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return report


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
    ocr_store: OcrCheckpointStore | None = None
    ocr_binding = ocr_checkpoint_binding(repository, source, policy)
    try:
        requested_ocr_checkpoint = getattr(args, "ocr_checkpoint", None)
        ocr_path = (
            Path(requested_ocr_checkpoint).expanduser().resolve()
            if requested_ocr_checkpoint
            else default_ocr_checkpoint_path(ocr_binding)
        )
        ocr_store = OcrCheckpointStore(ocr_path, ocr_binding)
    except (OSError, RuntimeError, ValueError):
        ocr_store = None
    state = ScanState(repository, policy, ocr_store=ocr_store)
    if ocr_store is None:
        state.add_coverage("ocr-checkpoint", "tool_failed", "ocr-checkpoint-unavailable-or-invalid")
    if policy_error:
        state.add_coverage("private-policy", "unreadable", "private-policy-unavailable-or-invalid")
    elif args.generic_only:
        state.add_coverage("private-policy", "unreadable", "generic-only-cannot-pass-publication")
    else:
        state.add_coverage("private-policy", "checked", object_count=len(policy["identifiers"]) if policy else 0)
    try:
        if not source.is_dir():
            state.add_coverage("working-tree", "unreadable", "source-directory-unavailable")
        else:
            scan_working_tree(
                state,
                source,
                time_limit_seconds=getattr(args, "worktree_time_limit_seconds", DEFAULT_GATE_WORKTREE_BUDGET_SECONDS),
                checkpoint_path=(
                    Path(args.worktree_checkpoint).expanduser().resolve()
                    if getattr(args, "worktree_checkpoint", None)
                    else None
                ),
                checkpoint_interval=getattr(args, "worktree_checkpoint_interval", DEFAULT_WORKTREE_CHECKPOINT_INTERVAL),
            )
            worktree_incomplete = any(
                item.surface == "working-tree" and item.status not in {"checked", "not_present"}
                for item in state.coverage
            )
            if not worktree_incomplete:
                scan_git_history(
                    state,
                    source,
                    time_limit_seconds=getattr(args, "git_history_time_limit_seconds", DEFAULT_GATE_HISTORY_BUDGET_SECONDS),
                    checkpoint_path=(
                        Path(args.git_history_checkpoint).expanduser().resolve()
                        if getattr(args, "git_history_checkpoint", None)
                        else None
                    ),
                    checkpoint_interval=getattr(args, "git_history_checkpoint_interval", DEFAULT_HISTORY_CHECKPOINT_INTERVAL),
                )
                scan_submodules(state, source)
                scan_lfs(state, source)
                run_gitleaks(state, source, Path(args.gitleaks_path).resolve() if args.gitleaks_path else None)
        scan_release_paths(state, [Path(item).expanduser().resolve() for item in args.release_asset])
    finally:
        if ocr_store is not None:
            ocr_store.close()
    report = gate_report(
        state,
        source,
        policy,
        release_profile=args.release_profile,
        force_incomplete=force_incomplete,
    )
    write_paginated_private_report(Path(args.report), report)
    if args.public_summary:
        write_json(
            Path(args.public_summary),
            {
                "schema_version": SCHEMA_VERSION,
                "mode": report["mode"],
                "decision": report["decision"],
                "publication_decision": report["publication_decision"],
                "release_profile": report["release_profile"],
                "source_commit": report["source_commit"],
                "scanner_sha256": report["scanner_versions"]["safe_publish_sha256"],
                "policy_fingerprint": report["policy_fingerprint"],
                "report_fingerprint": report["report_fingerprint"],
                "history_progress": report["history_progress"],
                "worktree_progress": report["worktree_progress"],
                "issue_codes": report["issue_codes"],
                "summary": report["summary"],
                "result_explanation": report["result_explanation"],
            },
        )
    print(
        json.dumps(
            {
                "decision": report["decision"],
                "publication_decision": report["publication_decision"],
                "release_profile": report["release_profile"],
                **report["summary"],
                "result_explanation": report["result_explanation"],
            },
            sort_keys=True,
        )
    )
    return 0 if report["publication_decision"] in {"allow", "allow_with_risk"} else 3


def probe_command(command: list[str]) -> tuple[bool, str | None]:
    """Check one executable without exposing its installation path."""
    if shutil.which(command[0]) is None:
        return False, None
    try:
        result = run(command, timeout_seconds=30)
    except (OSError, subprocess.SubprocessError):
        return False, None
    if result.returncode != 0:
        return False, None
    first_line = (result.stdout or result.stderr).strip().splitlines()
    version = first_line[0][:160] if first_line else "available"
    return True, version


def probe_python_component(name: str) -> tuple[bool, str | None]:
    """Import one parser in-process and return only a non-sensitive version string."""
    try:
        module = importlib.import_module(name)
        return True, str(getattr(module, "__version__", "available"))[:80]
    except Exception:
        return False, None


def cached_gitleaks_probe() -> tuple[bool, str | None]:
    """Probe PATH or the verified-version cache without downloading anything."""
    path_probe = probe_command(["gitleaks", "version"])
    if path_probe[0]:
        return path_probe
    try:
        _asset_name, executable_name = gitleaks_asset_name()
    except RuntimeError:
        return False, None
    cached = get_codex_home() / "cache" / "github-safe-publish" / f"gitleaks-{GITLEAKS_VERSION}" / executable_name
    if not cached.is_file():
        return False, None
    return probe_command([str(cached), "version"])


def doctor_requirements(source: Path | None) -> set[str]:
    """Map tracked object types to the parser layers required for a complete gate."""
    required = {"git", "git-lfs", "gitleaks"}
    if source is None or not source.is_dir():
        return required
    for relative, path in iter_working_tree(source):
        if not path.is_file():
            continue
        suffix = Path(relative).suffix.lower()
        if suffix in IMAGE_SUFFIXES:
            required.update({"pillow", "opencv", "image-ocr"})
        elif suffix in NUMPY_SUFFIXES:
            required.add("numpy")
        elif suffix == ".pdf":
            required.update({"pdf", "image-ocr"})
        elif suffix in MEDIA_SUFFIXES:
            required.add("media")
        elif suffix in OPAQUE_SUFFIXES:
            required.update({"libmagic", "strings"})
    return required


def doctor_report(source: Path | None = None, *, require_all: bool = False) -> dict[str, Any]:
    """Return a deterministic capability report for the current runtime."""
    probes: dict[str, tuple[bool, str | None]] = {
        "git": probe_command(["git", "--version"]),
        "git-lfs": probe_command(["git", "lfs", "version"]),
        "gitleaks": cached_gitleaks_probe(),
        "strings": probe_command(["strings", "--version"]),
        "media": probe_command(["ffprobe", "-version"]),
        "pillow": probe_python_component("PIL"),
        "numpy": probe_python_component("numpy"),
        "pdf": probe_python_component("pypdf"),
        "image-ocr": probe_python_component("rapidocr_onnxruntime"),
    }
    opencv_ok, opencv_version = probe_python_component("cv2")
    if opencv_ok:
        try:
            import cv2
            import numpy as np

            detector = cv2.barcode_BarcodeDetector()
            normalized_barcode_values(detector.detectAndDecode(np.zeros((32, 32, 3), dtype=np.uint8)))
        except Exception:
            opencv_ok = False
    probes["opencv"] = (opencv_ok, opencv_version)
    magic_ok, magic_version = probe_python_component("magic")
    if magic_ok:
        try:
            import magic

            magic.from_buffer(b"synthetic")
        except Exception:
            magic_ok = False
    probes["libmagic"] = (magic_ok, magic_version)
    required = set(probes) if require_all else doctor_requirements(source)
    components = {
        name: {"status": "available" if available else "unavailable", "required": name in required, "version": version}
        for name, (available, version) in sorted(probes.items())
    }
    missing = sorted(name for name in required if not probes.get(name, (False, None))[0])
    stable = {"schema_version": SCHEMA_VERSION, "components": components, "required": sorted(required), "missing_required": missing}
    return {**stable, "decision": "pass" if not missing else "incomplete", "fingerprint": sha256_bytes(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode("utf-8"))}


def command_doctor(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve() if args.source else None
    report = doctor_report(source, require_all=bool(args.all))
    if args.output:
        write_json(Path(args.output), report)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["decision"] == "pass" else 4


def copy_worktree_candidate(source: Path, base_commit: str, destination: Path) -> tuple[str, str, str]:
    """Create an isolated candidate that includes tracked edits, deletions, and untracked files."""
    cloned = run(["git", "clone", "--no-hardlinks", str(source), str(destination)])
    if cloned.returncode != 0:
        raise RuntimeError("Unable to clone the publication candidate")
    checked_out = run(["git", "checkout", "--detach", base_commit], destination)
    if checked_out.returncode != 0:
        raise RuntimeError("Unable to check out the requested base commit")
    source_remote = run(["git", "remote", "get-url", "origin"], source)
    if source_remote.returncode != 0 or not source_remote.stdout.strip():
        raise RuntimeError("Source GitHub remote is unavailable")
    remote_updated = run(["git", "remote", "set-url", "origin", source_remote.stdout.strip()], destination)
    if remote_updated.returncode != 0:
        raise RuntimeError("Unable to preserve the source GitHub remote")
    base_files = run(["git", "ls-tree", "-r", "--name-only", "-z", base_commit], source, text=False)
    if base_files.returncode != 0:
        raise RuntimeError("Unable to enumerate base files")
    for raw in base_files.stdout.split(b"\x00"):
        if not raw:
            continue
        relative = raw.decode("utf-8", errors="surrogateescape")
        source_path = source / relative
        target = destination / relative
        if not source_path.exists() and not source_path.is_symlink() and (target.exists() or target.is_symlink()):
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
    for relative, source_path in iter_working_tree(source):
        if source_path.is_dir():
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source_path.is_symlink():
            if target.exists() or target.is_symlink():
                target.unlink()
            target.symlink_to(os.readlink(source_path))
        else:
            shutil.copy2(source_path, target)
    staged = run(["git", "add", "-A"], destination)
    if staged.returncode != 0:
        raise RuntimeError("Unable to stage the isolated candidate")
    tree = run(["git", "write-tree"], destination)
    index = run(["git", "ls-files", "-s", "-z"], destination, text=False)
    patch = run(["git", "diff", "--cached", "--binary", base_commit], destination, text=False)
    if tree.returncode != 0 or index.returncode != 0 or patch.returncode != 0:
        raise RuntimeError("Unable to fingerprint the isolated candidate")
    return tree.stdout.strip(), sha256_bytes(index.stdout), sha256_bytes(patch.stdout)


def run_validation_command(command: str, cwd: Path, timeout_seconds: int) -> dict[str, Any]:
    """Run a caller-approved validation while retaining only status and duration."""
    started = time.monotonic()
    if os.name == "nt":
        powershell_script = (
            "$global:LASTEXITCODE = 0; "
            "$script:validationSucceeded = $true; "
            "$script:validationExitCode = 0; "
            f"& {{ {command}; "
            "$script:validationSucceeded = $?; "
            "$script:validationExitCode = $LASTEXITCODE }; "
            "if (-not $validationSucceeded) { "
            "if ($validationExitCode -is [int] -and $validationExitCode -ne 0) { exit $validationExitCode }; "
            "exit 1 }; "
            "if ($validationExitCode -is [int]) { exit $validationExitCode }; "
            "exit 0"
        )
        encoded = base64.b64encode(powershell_script.encode("utf-16-le")).decode("ascii")
        shell_command = ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
    else:
        shell_command = ["bash", "-lc", command]
    try:
        result = run(shell_command, cwd, timeout_seconds=timeout_seconds)
        status = "pass" if result.returncode == 0 else "fail"
        exit_code: int | None = int(result.returncode)
    except subprocess.TimeoutExpired:
        status = "timeout"
        exit_code = None
    return {"status": status, "exit_code": exit_code, "duration_seconds": round(time.monotonic() - started, 3)}


def remote_default_branch(repository: str) -> str:
    result = run(["gh", "repo", "view", repository, "--json", "defaultBranchRef", "--jq", ".defaultBranchRef.name"])
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("GitHub default branch is unavailable")
    return result.stdout.strip()


def remote_branch_commit(repository: str, branch: str) -> str:
    result = run(["gh", "api", f"repos/{repository}/commits/{branch}", "--jq", ".sha"])
    if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", result.stdout.strip()):
        raise RuntimeError("GitHub branch commit is unavailable")
    return result.stdout.strip()


def repository_has_required_governance(repository: str, branch: str) -> bool:
    protection = run(["gh", "api", f"repos/{repository}/branches/{branch}/protection"])
    if protection.returncode == 0:
        try:
            document = json.loads(protection.stdout)
            contexts = ((document.get("required_status_checks") or {}).get("contexts") or [])
            checks = ((document.get("required_status_checks") or {}).get("checks") or [])
            if contexts or checks:
                return True
        except json.JSONDecodeError:
            pass
    rulesets = run(["gh", "api", f"repos/{repository}/rulesets?includes_parents=true"])
    if rulesets.returncode != 0:
        return False
    try:
        return any(
            item.get("enforcement") == "active"
            and any(rule.get("type") == "required_status_checks" for rule in item.get("rules", []))
            for item in json.loads(rulesets.stdout)
        )
    except (json.JSONDecodeError, TypeError):
        return False


def update_managed_public_summary(path: str | None, values: dict[str, Any]) -> None:
    """Add orchestration state to a redacted public summary without private locations."""
    if not path:
        return
    target = Path(path)
    document: dict[str, Any] = {}
    if target.is_file():
        try:
            loaded = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                document.update(loaded)
        except (OSError, json.JSONDecodeError):
            document = {}
    document.update(values)
    write_json(target, document)


def write_managed_gate_failure(
    *,
    issue_reason: str,
    repository: str,
    candidate: Path,
    policy: dict[str, Any],
    release_profile: str,
    report_path: Path,
    public_summary_path: str | None,
) -> dict[str, Any]:
    failure_state = ScanState(repository, policy)
    failure_state.add_coverage("exact-gate", "tool_failed", issue_reason)
    report = gate_report(
        failure_state,
        candidate,
        policy,
        release_profile=release_profile,
        force_incomplete=True,
    )
    write_paginated_private_report(report_path, report)
    if public_summary_path:
        write_json(
            Path(public_summary_path),
            {
                "schema_version": SCHEMA_VERSION,
                "mode": report["mode"],
                "decision": report["decision"],
                "publication_decision": report["publication_decision"],
                "release_profile": report["release_profile"],
                "source_commit": report["source_commit"],
                "scanner_sha256": report["scanner_versions"]["safe_publish_sha256"],
                "policy_fingerprint": report["policy_fingerprint"],
                "report_fingerprint": report["report_fingerprint"],
                "issue_codes": report["issue_codes"],
                "summary": report["summary"],
                "result_explanation": report["result_explanation"],
                "managed_state": "incomplete",
            },
        )
    return report


def command_managed_publish(args: argparse.Namespace) -> int:
    """Gate one exact worktree candidate and optionally publish it through a PR."""
    source = Path(args.source).expanduser().resolve()
    output_dir = ensure_private_path(Path(args.private_output_dir))
    output_dir.mkdir(parents=True, exist_ok=True)
    restrict_private_path(output_dir, directory=True)
    checkpoint_path = ensure_private_path(Path(args.checkpoint) if args.checkpoint else output_dir / "checkpoint.private.json")
    report_path = ensure_private_path(output_dir / "gate.private.json")
    base_commit = run(["git", "rev-parse", "--verify", f"{args.base_commit}^{{commit}}"], source).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", base_commit) or git_head(source) != base_commit:
        raise ValueError("Base commit must equal the current source HEAD")
    policy = load_policy(Path(args.policy), source)
    gitleaks_binary = Path(args.gitleaks_path).expanduser().resolve() if args.gitleaks_path else ensure_gitleaks()
    default_branch = args.base_branch or remote_default_branch(args.repository)
    if remote_branch_commit(args.repository, default_branch) != base_commit:
        raise RuntimeError("Remote base changed before publication")
    runtime = doctor_report(source)
    candidate = output_dir / "candidate"
    if candidate.exists() and not args.resume:
        raise ValueError("Candidate already exists; use --resume or a new private output directory")
    if not candidate.exists():
        tree_oid, tree_sha256, patch_sha256 = copy_worktree_candidate(source, base_commit, candidate)
    else:
        staged = run(["git", "add", "-A"], candidate)
        tree = run(["git", "write-tree"], candidate)
        index = run(["git", "ls-files", "-s", "-z"], candidate, text=False)
        patch = run(["git", "diff", "--cached", "--binary", base_commit], candidate, text=False)
        if staged.returncode != 0 or tree.returncode != 0 or index.returncode != 0 or patch.returncode != 0:
            raise RuntimeError("Unable to resume the isolated candidate")
        tree_oid, tree_sha256, patch_sha256 = tree.stdout.strip(), sha256_bytes(index.stdout), sha256_bytes(patch.stdout)
    validations = [run_validation_command(command, candidate, args.validation_timeout_seconds) for command in args.validation_command]
    if args.readme_auditor:
        auditor = Path(args.readme_auditor).expanduser().resolve()
        validations.append(run_validation_command(f'python -X utf8 "{auditor}" "{candidate}" --scan-repository', candidate, args.validation_timeout_seconds))
    validation_passed = all(item["status"] == "pass" for item in validations)
    if runtime["decision"] != "pass" or not validation_passed:
        checkpoint = {
            "schema_version": SCHEMA_VERSION,
            "state": "incomplete",
            "base_commit": base_commit,
            "candidate_tree_oid": tree_oid,
            "candidate_tree_sha256": tree_sha256,
            "patch_sha256": patch_sha256,
            "scanner_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "policy_fingerprint": policy_fingerprint(policy),
            "runtime_fingerprint": runtime["fingerprint"],
            "validation": validations,
        }
        write_json(checkpoint_path, checkpoint, private=True)
        if args.public_summary:
            write_json(Path(args.public_summary), {key: checkpoint[key] for key in ("schema_version", "state", "base_commit", "candidate_tree_sha256", "patch_sha256", "scanner_sha256", "policy_fingerprint", "runtime_fingerprint")})
        print(json.dumps({"publication_decision": "deny", "state": "incomplete"}, sort_keys=True))
        return 4
    candidate_head = git_head(candidate)
    if candidate_head == base_commit:
        base_timestamp = run(["git", "show", "-s", "--format=%cI", base_commit], candidate).stdout.strip()
        if not base_timestamp:
            raise RuntimeError("Base commit timestamp is unavailable")
        committed = run(
            [
                "git", "-c", "user.name=GitHub Managed Publish", "-c", "user.email=managed-publish@example.invalid",
                "commit", "-m", args.commit_message,
            ],
            candidate,
            env={"GIT_AUTHOR_DATE": base_timestamp, "GIT_COMMITTER_DATE": base_timestamp},
        )
        if committed.returncode != 0:
            raise RuntimeError("Publication candidate has no committable changes")
    elif not args.resume:
        raise RuntimeError("Unexpected commit exists in the isolated candidate")
    gate_args = argparse.Namespace(
        source=str(candidate), repository=args.repository, policy=args.policy, policy_b64_env=None,
        generic_only=False, release_asset=args.release_asset, gitleaks_path=str(gitleaks_binary),
        release_profile=args.release_profile, report=str(report_path), public_summary=args.public_summary,
        git_history_checkpoint=str(output_dir / "git-history-checkpoint.private.json"),
        worktree_checkpoint=str(output_dir / "worktree-checkpoint.private.json"),
        ocr_checkpoint=str(output_dir / "ocr-checkpoint.private.sqlite"),
        worktree_time_limit_seconds=getattr(args, "worktree_time_limit_seconds", DEFAULT_GATE_WORKTREE_BUDGET_SECONDS),
        worktree_checkpoint_interval=getattr(args, "worktree_checkpoint_interval", DEFAULT_WORKTREE_CHECKPOINT_INTERVAL),
        git_history_time_limit_seconds=getattr(args, "git_history_time_limit_seconds", DEFAULT_GATE_HISTORY_BUDGET_SECONDS),
        git_history_checkpoint_interval=getattr(args, "git_history_checkpoint_interval", DEFAULT_HISTORY_CHECKPOINT_INTERVAL),
    )
    placeholder = write_managed_gate_failure(
        issue_reason="gate-report-missing",
        repository=args.repository,
        candidate=candidate,
        policy=policy,
        release_profile=args.release_profile,
        report_path=report_path,
        public_summary_path=args.public_summary,
    )
    try:
        gate_exit = command_gate(gate_args)
    except Exception:
        gate_document = write_managed_gate_failure(
            issue_reason="scanner-crashed",
            repository=args.repository,
            candidate=candidate,
            policy=policy,
            release_profile=args.release_profile,
            report_path=report_path,
            public_summary_path=args.public_summary,
        )
        checkpoint = {
            "schema_version": SCHEMA_VERSION,
            "state": "incomplete",
            "base_commit": base_commit,
            "candidate_tree_oid": tree_oid,
            "candidate_tree_sha256": tree_sha256,
            "patch_sha256": patch_sha256,
            "scanner_sha256": gate_document["scanner_versions"]["safe_publish_sha256"],
            "policy_fingerprint": gate_document["policy_fingerprint"],
            "report_fingerprint": gate_document["report_fingerprint"],
            "publication_decision": "deny",
            "issue_codes": gate_document["issue_codes"],
            "validation": validations,
        }
        write_json(checkpoint_path, checkpoint, private=True)
        print(json.dumps({"publication_decision": "deny", "state": "incomplete", "issue_codes": checkpoint["issue_codes"]}, sort_keys=True))
        return 4
    try:
        gate_document = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        gate_document = placeholder
    if gate_document.get("report_fingerprint") == placeholder["report_fingerprint"]:
        checkpoint = {
            "schema_version": SCHEMA_VERSION,
            "state": "incomplete",
            "base_commit": base_commit,
            "candidate_tree_oid": tree_oid,
            "candidate_tree_sha256": tree_sha256,
            "patch_sha256": patch_sha256,
            "scanner_sha256": placeholder["scanner_versions"]["safe_publish_sha256"],
            "policy_fingerprint": placeholder["policy_fingerprint"],
            "report_fingerprint": placeholder["report_fingerprint"],
            "publication_decision": "deny",
            "issue_codes": placeholder["issue_codes"],
            "validation": validations,
        }
        write_json(checkpoint_path, checkpoint, private=True)
        print(json.dumps({"publication_decision": "deny", "state": "incomplete", "issue_codes": checkpoint["issue_codes"]}, sort_keys=True))
        return 4
    publication_decision = gate_document["publication_decision"]
    checkpoint = {
        "schema_version": SCHEMA_VERSION,
        "state": "gated",
        "base_commit": base_commit,
        "candidate_commit": git_head(candidate),
        "candidate_tree_oid": tree_oid,
        "candidate_tree_sha256": tree_sha256,
        "patch_sha256": patch_sha256,
        "scanner_sha256": gate_document["scanner_versions"]["safe_publish_sha256"],
        "policy_fingerprint": gate_document["policy_fingerprint"],
        "report_fingerprint": gate_document["report_fingerprint"],
        "publication_decision": publication_decision,
        "validation": validations,
    }
    write_json(checkpoint_path, checkpoint, private=True)
    update_managed_public_summary(
        args.public_summary,
        {
            "managed_state": checkpoint["state"],
            "candidate_tree_sha256": tree_sha256,
            "patch_sha256": patch_sha256,
        },
    )
    if gate_exit != 0 or publication_decision not in {"allow", "allow_with_risk"} or args.intent == "audit":
        print(json.dumps({"publication_decision": publication_decision, "state": "gated"}, sort_keys=True))
        return gate_exit
    if remote_branch_commit(args.repository, default_branch) != base_commit:
        raise RuntimeError("Remote base changed after the gate")
    branch = args.branch or f"codex/managed-publish-{tree_sha256[:12]}"
    pushed = run(["git", "push", "origin", f"HEAD:refs/heads/{branch}"], candidate)
    if pushed.returncode != 0:
        raise RuntimeError("Candidate branch push failed")
    remote_candidate = remote_branch_commit(args.repository, branch)
    remote_tree = run(["gh", "api", f"repos/{args.repository}/git/commits/{remote_candidate}", "--jq", ".tree.sha"])
    if remote_tree.returncode != 0 or remote_tree.stdout.strip() != tree_oid:
        raise RuntimeError("Remote candidate tree differs from the gated tree")
    existing = run(["gh", "pr", "list", "--repo", args.repository, "--head", branch, "--state", "open", "--json", "number", "--jq", ".[0].number"])
    if existing.returncode == 0 and existing.stdout.strip().isdigit():
        pr_number = existing.stdout.strip()
    else:
        created = run(["gh", "pr", "create", "--repo", args.repository, "--base", default_branch, "--head", branch, "--title", args.pr_title, "--body", args.pr_body])
        if created.returncode != 0:
            raise RuntimeError("Pull request creation failed")
        lookup = run(["gh", "pr", "list", "--repo", args.repository, "--head", branch, "--state", "open", "--json", "number", "--jq", ".[0].number"])
        if lookup.returncode != 0 or not lookup.stdout.strip().isdigit():
            raise RuntimeError("Created pull request is unavailable")
        pr_number = lookup.stdout.strip()
    checkpoint.update({"state": "pr-created", "branch": branch, "pull_request": int(pr_number)})
    if args.intent != "auto-merge" or publication_decision != "allow":
        write_json(checkpoint_path, checkpoint, private=True)
        update_managed_public_summary(args.public_summary, {"managed_state": "pr-created"})
        print(json.dumps({"publication_decision": publication_decision, "state": "pr-created"}, sort_keys=True))
        return 0
    if not repository_has_required_governance(args.repository, default_branch):
        checkpoint.update({"state": "review-required", "governance_issue": "BRANCH_PROTECTION_MISSING"})
        write_json(checkpoint_path, checkpoint, private=True)
        update_managed_public_summary(args.public_summary, {"managed_state": "review-required", "issue_codes": ["BRANCH_PROTECTION_MISSING"]})
        print(json.dumps({"publication_decision": publication_decision, "state": "review-required", "issue_code": "BRANCH_PROTECTION_MISSING"}, sort_keys=True))
        return 0
    try:
        checks = run(["gh", "pr", "checks", pr_number, "--repo", args.repository, "--required", "--watch", "--interval", "10"], timeout_seconds=args.checks_timeout_seconds)
    except subprocess.TimeoutExpired:
        checks = subprocess.CompletedProcess([], 1, "", "")
    if checks.returncode != 0 or remote_branch_commit(args.repository, default_branch) != base_commit:
        checkpoint["state"] = "review-required"
        write_json(checkpoint_path, checkpoint, private=True)
        update_managed_public_summary(args.public_summary, {"managed_state": "review-required"})
        print(json.dumps({"publication_decision": publication_decision, "state": "review-required"}, sort_keys=True))
        return 0
    merged = run(["gh", "pr", "merge", pr_number, "--repo", args.repository, "--squash", "--delete-branch"])
    if merged.returncode != 0:
        raise RuntimeError("Pull request merge failed")
    checkpoint["state"] = "merged"
    write_json(checkpoint_path, checkpoint, private=True)
    update_managed_public_summary(args.public_summary, {"managed_state": "merged"})
    print(json.dumps({"publication_decision": publication_decision, "state": "merged"}, sort_keys=True))
    return 0


def command_policy_candidates(args: argparse.Namespace) -> int:
    source = Path(args.source).expanduser().resolve()
    output = ensure_private_path(Path(args.output))
    state = ScanState(args.repository or source.name, empty_policy(), collect_raw=True)
    scan_working_tree(state, source)
    # Candidate discovery covers deleted and renamed history plus non-working-tree Git surfaces.
    scan_git_history(state, source)
    scan_submodules(state, source)
    scan_lfs(state, source)
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
    gitlinks = indexed_gitlinks(destination)
    for relative, path in iter_working_tree(destination):
        if is_legal_path(relative) or path.is_symlink() or relative in gitlinks:
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


def restore_clean_root_gitlinks(source: Path, commit: str, destination: Path) -> int:
    """Recreate submodule index entries omitted by git archive in a clean publication root."""
    tree = run(["git", "ls-tree", "-r", "-z", commit], source, text=False)
    if tree.returncode != 0:
        raise RuntimeError("Unable to enumerate source tree modes")
    restored = 0
    for entry in tree.stdout.split(b"\x00"):
        metadata, separator, raw_path = entry.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3 or fields[0] != b"160000":
            continue
        oid = fields[2].decode("ascii", errors="strict")
        path = raw_path.decode("utf-8", errors="surrogateescape")
        updated = run(["git", "update-index", "--add", "--cacheinfo", f"160000,{oid},{path}"], destination)
        if updated.returncode != 0:
            raise RuntimeError("Unable to preserve a source submodule pointer")
        restored += 1
    return restored


def prepare_failure_report(
    *,
    source: Path,
    destination: Path,
    report_path: Path,
    commit: str | None,
    mode: str,
    policy: dict[str, Any] | None,
    coverage: list[Coverage],
    error_class: str,
) -> None:
    """Write a redacted machine report when preparation cannot establish complete coverage."""
    document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "decision": "incomplete",
        "source_commit": commit,
        "mode": mode,
        "destination": str(destination),
        "policy_fingerprint": policy_fingerprint(policy),
        "coverage": consolidated_coverage(coverage),
        "error": error_class,
    }
    write_json(report_path, document, private=True)


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
    report_path = Path(args.report)
    policy: dict[str, Any] | None = None
    exact_commit: str | None = None
    preparation_coverage: list[Coverage] = []
    try:
        policy = load_policy(Path(args.policy), source)
        commit_check = run(["git", "rev-parse", "--verify", f"{args.commit}^{{commit}}"], source)
        if commit_check.returncode != 0:
            raise ValueError("Source commit is unavailable")
        exact_commit = commit_check.stdout.strip()

        # A publication copy cannot be complete when a referenced LFS entity is absent.
        lfs_state = ScanState(source.name, empty_policy())
        scan_lfs(lfs_state, source)
        preparation_coverage.extend(lfs_state.coverage)
        if any(item.status not in {"checked", "not_present"} for item in lfs_state.coverage):
            raise RuntimeError("Required LFS entities are unavailable")

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
            restore_clean_root_gitlinks(source, exact_commit, destination)
        replacement_report = apply_replacements(destination, policy)
    except (OSError, RuntimeError, ValueError) as exc:
        # Remove only the disposable destination created by this command after its path was validated above.
        if destination.exists():
            shutil.rmtree(destination)
        if not preparation_coverage:
            preparation_coverage.append(Coverage("prepare", "tool_failed", "preparation-failed"))
        prepare_failure_report(
            source=source,
            destination=destination,
            report_path=report_path,
            commit=exact_commit,
            mode=args.mode,
            policy=policy,
            coverage=preparation_coverage,
            error_class=exc.__class__.__name__,
        )
        print(json.dumps({"decision": "incomplete", "error": exc.__class__.__name__}, sort_keys=True), file=sys.stderr)
        return 4
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "source_commit": exact_commit,
        "mode": args.mode,
        "destination": str(destination),
        "policy_fingerprint": policy_fingerprint(policy),
        **replacement_report,
    }
    write_json(report_path, report, private=True)
    print(json.dumps({"source_commit": exact_commit, "mode": args.mode, "changed_file_count": replacement_report["changed_file_count"]}, sort_keys=True))
    return 0


def gh_json(endpoint: str) -> tuple[Any | None, str | None]:
    try:
        result = run(["gh", "api", "--paginate", endpoint], timeout_seconds=DEFAULT_REMOTE_REQUEST_TIMEOUT_SECONDS)
    except (OSError, subprocess.SubprocessError):
        return None, "tool_failed"
    if result.returncode != 0:
        lowered = result.stderr.lower()
        if "403" in lowered or "resource not accessible" in lowered:
            reason = "permission_denied"
        elif "404" in lowered or "not found" in lowered:
            reason = "not_present"
        else:
            reason = "tool_failed"
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


def api_items(endpoint: str, field: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
    values, error = gh_json(endpoint)
    if error:
        return [], error
    records: list[dict[str, Any]] = []
    for value in values or []:
        if field and isinstance(value, dict):
            nested = value.get(field) or []
            records.extend(item for item in nested if isinstance(item, dict))
        elif isinstance(value, dict):
            records.append(value)
    return records, None


def gh_download(endpoint: str, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> tuple[bytes | None, str | None]:
    try:
        result = run(
            ["gh", "api", endpoint, "-H", "Accept: application/octet-stream"],
            text=False,
            timeout_seconds=DEFAULT_REMOTE_REQUEST_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            lowered = result.stderr.decode("utf-8", errors="ignore").lower()
            if "403" in lowered or "resource not accessible" in lowered:
                return None, "permission_denied"
            if "404" in lowered or "not found" in lowered or "410" in lowered:
                return None, "not_present"
            return None, "tool_failed"
        if len(result.stdout) > max_bytes:
            return None, "unreadable"
        return result.stdout, None
    except (OSError, subprocess.SubprocessError):
        return None, "tool_failed"


def fetch_public_url(url: str, *, max_bytes: int = DEFAULT_MAX_FILE_BYTES) -> tuple[bytes | None, str | None, str]:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "github-safe-publish/2"})
        with urllib.request.urlopen(request, timeout=30) as response:
            content_type = response.headers.get_content_type()
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    return None, "unreadable", content_type
                chunks.append(chunk)
            return b"".join(chunks), None, content_type
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403}:
            return None, "permission_denied", ""
        if exc.code in {404, 410}:
            return None, "unreadable", ""
        return None, "tool_failed", ""
    except (OSError, urllib.error.URLError, ValueError):
        return None, "tool_failed", ""


def audit_rendered_pages(state: ScanState, root_url: str) -> None:
    parsed_root = urllib.parse.urlparse(root_url)
    if parsed_root.scheme not in {"http", "https"} or not parsed_root.netloc:
        state.add_coverage("github-pages-rendered", "unreadable", "invalid-pages-url")
        return
    queue = [root_url]
    seen: set[str] = set()
    checked = 0
    while queue and len(seen) < 100:
        current = queue.pop(0)
        normalized = urllib.parse.urldefrag(current).url
        if normalized in seen:
            continue
        seen.add(normalized)
        data, error, content_type = fetch_public_url(normalized)
        if error or data is None:
            state.add_coverage("github-pages-rendered", error or "tool_failed", "pages-resource-download-failed")
            continue
        path = urllib.parse.urlparse(normalized).path or "/"
        display_path = path if Path(path).suffix else f"{path.rstrip('/')}/index.html"
        scan_bytes(state, data, surface="github-pages-rendered", object_id=f"pages:{normalized}", display_path=display_path)
        checked += 1
        if content_type in {"text/html", "application/xhtml+xml"}:
            parser = SameOriginLinkParser()
            try:
                parser.feed(data.decode("utf-8", errors="replace"))
            except Exception:
                state.add_coverage("github-pages-rendered", "unreadable", "pages-html-parse-failed")
                continue
            for link in parser.links:
                candidate = urllib.parse.urljoin(normalized, link)
                parsed = urllib.parse.urlparse(candidate)
                if parsed.scheme in {"http", "https"} and parsed.netloc == parsed_root.netloc:
                    queue.append(candidate)
    if queue:
        state.add_coverage("github-pages-rendered", "unreadable", "pages-resource-limit")
    state.add_coverage("github-pages-rendered", "checked" if checked else "unreadable", object_count=checked)


def scan_remote_records(state: ScanState, records: list[dict[str, Any]], *, surface: str, prefix: str, fields: Iterable[str]) -> None:
    count = 0
    for index, record in enumerate(records):
        stable = record.get("id") or record.get("node_id") or record.get("number") or index
        for field in fields:
            value: Any = record
            for part in field.split("."):
                value = value.get(part) if isinstance(value, dict) else None
            if isinstance(value, str) and value:
                count += 1
                scan_text(state, value, surface=surface, object_id=f"{prefix}:{stable}:{field}", display_path=f"{prefix}:{stable}:{field}")
            elif isinstance(value, list):
                for list_index, item in enumerate(value):
                    if isinstance(item, str):
                        count += 1
                        scan_text(state, item, surface=surface, object_id=f"{prefix}:{stable}:{field}:{list_index}", display_path=f"{prefix}:{stable}:{field}:{list_index}")
                    elif isinstance(item, dict):
                        text_value = item.get("name") or item.get("description")
                        if isinstance(text_value, str) and text_value:
                            count += 1
                            scan_text(state, text_value, surface=surface, object_id=f"{prefix}:{stable}:{field}:{list_index}", display_path=f"{prefix}:{stable}:{field}:{list_index}")
    state.add_coverage(surface, "checked" if records else "not_present", object_count=count)


def audit_repository_associated_surfaces(
    state: ScanState,
    owner: str,
    repository: str,
    repo_metadata: dict[str, Any],
    *,
    time_limit_seconds: int = DEFAULT_ASSOCIATED_SURFACE_BUDGET_SECONDS,
) -> None:
    deadline = time.monotonic() + max(1, time_limit_seconds)

    def stop_when_budget_expires() -> bool:
        if time.monotonic() < deadline:
            return False
        observed = {item.surface for item in state.coverage}
        for surface in sorted(REPOSITORY_ASSOCIATED_SURFACES - observed):
            state.add_coverage(surface, "tool_failed", "repository-associated-time-limit-exceeded")
        return True

    base = f"repos/{owner}/{repository}"
    endpoints = (
        ("issues", f"{base}/issues?state=all&per_page=100", None, ("title", "body", "labels", "milestone.title", "milestone.description")),
        ("issue-comments", f"{base}/issues/comments?per_page=100", None, ("body",)),
        ("pull-requests", f"{base}/pulls?state=all&per_page=100", None, ("title", "body", "head.label", "base.label")),
        ("pull-comments", f"{base}/pulls/comments?per_page=100", None, ("body", "path")),
        ("labels", f"{base}/labels?per_page=100", None, ("name", "description")),
        ("milestones", f"{base}/milestones?state=all&per_page=100", None, ("title", "description")),
        ("deployments", f"{base}/deployments?per_page=100", None, ("environment", "description", "original_environment")),
        ("environments", f"{base}/environments?per_page=100", "environments", ("name",)),
        ("actions-variables", f"{base}/actions/variables?per_page=100", "variables", ("name", "value")),
        ("actions-artifacts", f"{base}/actions/artifacts?per_page=100", "artifacts", ("name", "workflow_run.head_branch")),
    )
    for surface, endpoint, field, fields in endpoints:
        if stop_when_budget_expires():
            return
        records, error = api_items(endpoint, field)
        if error:
            state.add_coverage(surface, error, f"{surface}-enumeration-failed")
        else:
            scan_remote_records(state, records, surface=surface, prefix=surface, fields=fields)

    if stop_when_budget_expires():
        return
    deployments, deployments_error = api_items(f"{base}/deployments?per_page=100")
    if deployments_error:
        state.add_coverage("deployment-statuses", deployments_error, "deployment-status-enumeration-failed")
    elif not deployments:
        state.add_coverage("deployment-statuses", "not_present")
    else:
        status_count = 0
        for deployment in deployments:
            if stop_when_budget_expires():
                return
            deployment_id = deployment.get("id")
            statuses, error = api_items(f"{base}/deployments/{deployment_id}/statuses?per_page=100")
            if error:
                state.add_coverage("deployment-statuses", error, "deployment-status-page-failed")
                continue
            status_count += len(statuses)
            scan_remote_records(state, statuses, surface="deployment-statuses", prefix=f"deployment:{deployment_id}:status", fields=("description", "environment_url", "log_url"))
        state.add_coverage("deployment-statuses", "checked", object_count=status_count)

    if stop_when_budget_expires():
        return
    artifacts, artifacts_error = api_items(f"{base}/actions/artifacts?per_page=100", "artifacts")
    if artifacts_error:
        state.add_coverage("actions-artifact-content", artifacts_error, "artifact-enumeration-failed")
    elif not artifacts:
        state.add_coverage("actions-artifact-content", "not_present")
    else:
        checked_artifacts = 0
        for artifact in artifacts:
            if stop_when_budget_expires():
                return
            artifact_id = artifact.get("id")
            size = int(artifact.get("size_in_bytes") or 0)
            if size > DEFAULT_MAX_FILE_BYTES:
                state.add_coverage("actions-artifact-content", "unreadable", "oversized-actions-artifact")
                continue
            artifact_data, download_error = gh_download(f"{base}/actions/artifacts/{artifact_id}/zip")
            if download_error or artifact_data is None:
                status = "unreadable" if download_error == "not_present" else download_error or "tool_failed"
                state.add_coverage("actions-artifact-content", status, "artifact-download-failed")
                continue
            scan_bytes(state, artifact_data, surface="actions-artifact-content", object_id=f"actions-artifact:{artifact_id}", display_path=f"actions-artifact-{artifact_id}.zip")
            checked_artifacts += 1
        state.add_coverage("actions-artifact-content", "checked", object_count=checked_artifacts)

    if stop_when_budget_expires():
        return
    pulls, pulls_error = api_items(f"{base}/pulls?state=all&per_page=100")
    if pulls_error:
        state.add_coverage("pull-reviews", pulls_error, "pull-review-enumeration-failed")
    else:
        review_count = 0
        for pull in pulls:
            if stop_when_budget_expires():
                return
            number = pull.get("number")
            reviews, error = api_items(f"{base}/pulls/{number}/reviews?per_page=100")
            if error:
                state.add_coverage("pull-reviews", error, "pull-review-page-failed")
                continue
            review_count += len(reviews)
            scan_remote_records(state, reviews, surface="pull-reviews", prefix=f"pull:{number}:review", fields=("body",))
        if not pulls:
            state.add_coverage("pull-reviews", "not_present")
        elif review_count == 0 and not any(item.surface == "pull-reviews" and item.status not in {"checked", "not_present"} for item in state.coverage):
            state.add_coverage("pull-reviews", "not_present")

    if stop_when_budget_expires():
        return
    # Discussions use GraphQL because no repository REST endpoint provides their bodies and comments.
    query = "query($owner:String!,$name:String!,$endCursor:String){repository(owner:$owner,name:$name){discussions(first:100,after:$endCursor){nodes{id title body comments(first:100){nodes{id body}pageInfo{hasNextPage endCursor}}}pageInfo{hasNextPage endCursor}}}}"
    discussion_result = run(["gh", "api", "graphql", "--paginate", "-f", f"query={query}", "-F", f"owner={owner}", "-F", f"name={repository}"])
    if discussion_result.returncode != 0:
        reason = "permission_denied" if "403" in discussion_result.stderr or "not accessible" in discussion_result.stderr.lower() else "tool_failed"
        state.add_coverage("discussions", reason, "discussion-enumeration-failed")
    else:
        try:
            decoder = json.JSONDecoder()
            index = 0
            discussion_count = 0
            while index < len(discussion_result.stdout):
                page, index = decoder.raw_decode(discussion_result.stdout, index)
                while index < len(discussion_result.stdout) and discussion_result.stdout[index].isspace():
                    index += 1
                nodes = (((page.get("data") or {}).get("repository") or {}).get("discussions") or {}).get("nodes") or []
                for discussion in nodes:
                    discussion_count += 1
                    scan_remote_records(state, [discussion], surface="discussions", prefix="discussion", fields=("title", "body"))
                    scan_remote_records(state, ((discussion.get("comments") or {}).get("nodes") or []), surface="discussion-comments", prefix=f"discussion:{discussion.get('id')}:comment", fields=("body",))
                    if ((discussion.get("comments") or {}).get("pageInfo") or {}).get("hasNextPage"):
                        state.add_coverage("discussion-comments", "unreadable", "discussion-comment-pagination-not-expanded")
            if discussion_count == 0:
                state.add_coverage("discussions", "not_present")
                state.add_coverage("discussion-comments", "not_present")
        except (json.JSONDecodeError, AttributeError):
            state.add_coverage("discussions", "tool_failed", "discussion-response-invalid")

    if stop_when_budget_expires():
        return
    pages, pages_error = gh_json(f"{base}/pages")
    if pages_error:
        status = "not_present" if pages_error == "tool_failed" and not repo_metadata.get("has_pages") else pages_error
        state.add_coverage("github-pages", status, "pages-metadata-unavailable" if status != "not_present" else "")
        state.add_coverage("github-pages-rendered", "not_present" if status == "not_present" else status, "pages-rendered-unavailable" if status != "not_present" else "")
    else:
        page_record = pages[0] if isinstance(pages, list) and pages else pages
        scan_remote_records(state, [page_record] if isinstance(page_record, dict) else [], surface="github-pages", prefix="pages", fields=("url", "html_url", "source.branch", "source.path"))
        rendered_url = page_record.get("html_url") if isinstance(page_record, dict) else None
        if isinstance(rendered_url, str) and rendered_url:
            audit_rendered_pages(state, rendered_url)
        else:
            state.add_coverage("github-pages-rendered", "unreadable", "pages-rendered-url-unavailable")

    if stop_when_budget_expires():
        return
    # Wiki is a separate Git repository. A failed clone is not treated as absence when the repository advertises Wiki support.
    if repo_metadata.get("has_wiki"):
        with tempfile.TemporaryDirectory(prefix="safe-publish-wiki-") as temporary:
            wiki = Path(temporary) / "wiki.git"
            cloned = run(["git", "clone", "--mirror", f"https://github.com/{owner}/{repository}.wiki.git", str(wiki)])
            if cloned.returncode == 0:
                scan_git_history(state, wiki)
                state.add_coverage("wiki", "checked")
            elif "not found" in cloned.stderr.lower() or "repository not found" in cloned.stderr.lower():
                state.add_coverage("wiki", "not_present")
            else:
                state.add_coverage("wiki", "permission_denied" if "authentication" in cloned.stderr.lower() else "tool_failed", "wiki-clone-failed")
    else:
        state.add_coverage("wiki", "not_present")

    if stop_when_budget_expires():
        return
    runs, runs_error = api_items(f"{base}/actions/runs?per_page=100", "workflow_runs")
    if runs_error:
        state.add_coverage("actions-logs", runs_error, "workflow-run-enumeration-failed")
    elif not runs:
        state.add_coverage("actions-logs", "not_present")
        state.add_coverage("actions-job-summaries", "not_present")
    else:
        checked = 0
        for workflow_run in runs:
            if stop_when_budget_expires():
                return
            run_id = workflow_run.get("id")
            log_data, download_error = gh_download(f"{base}/actions/runs/{run_id}/logs")
            if download_error or log_data is None:
                status = "unreadable" if download_error == "not_present" else download_error or "tool_failed"
                state.add_coverage("actions-logs", status, "workflow-log-download-failed")
                continue
            scan_bytes(state, log_data, surface="actions-logs", object_id=f"actions-log:{run_id}", display_path=f"actions-log-{run_id}.zip")
            checked += 1
        state.add_coverage("actions-logs", "checked", object_count=checked)
        state.add_coverage("actions-job-summaries", "unreadable", "job-summary-api-unavailable", len(runs))

    if stop_when_budget_expires():
        return
    # Cache contents are not downloadable through a stable repository API; metadata remains auditable.
    caches, caches_error = api_items(f"{base}/actions/caches?per_page=100", "actions_caches")
    if caches_error:
        state.add_coverage("actions-caches", caches_error, "cache-metadata-enumeration-failed")
    else:
        scan_remote_records(state, caches, surface="actions-cache-metadata", prefix="cache", fields=("key", "ref"))
        state.add_coverage("actions-cache-content", "unreadable" if caches else "not_present", "cache-content-api-unavailable" if caches else "", len(caches))

    if stop_when_budget_expires():
        return
    # Secrets are intentionally unreadable; names and selected settings are the only declared surface.
    secrets, secrets_error = api_items(f"{base}/actions/secrets?per_page=100", "secrets")
    if secrets_error:
        state.add_coverage("actions-secret-metadata", secrets_error, "secret-metadata-enumeration-failed")
    else:
        scan_remote_records(state, secrets, surface="actions-secret-metadata", prefix="actions-secret", fields=("name",))

    if stop_when_budget_expires():
        return
    rulesets, rulesets_error = api_items(f"{base}/rulesets?per_page=100")
    if rulesets_error:
        state.add_coverage("rulesets", rulesets_error, "ruleset-enumeration-failed")
    else:
        scan_remote_records(state, rulesets, surface="rulesets", prefix="ruleset", fields=("name", "target", "enforcement"))

    if stop_when_budget_expires():
        return
    actions_permissions, permissions_error = gh_json(f"{base}/actions/permissions")
    if permissions_error:
        state.add_coverage("actions-permissions", permissions_error, "actions-permission-read-failed")
    else:
        state.add_coverage("actions-permissions", "checked", object_count=1)

    retention, retention_error = gh_json(f"{base}/actions/permissions/artifact-and-log-retention")
    state.add_coverage("actions-retention", retention_error or "checked", "actions-retention-read-failed" if retention_error else "", 0 if retention_error else 1)

    immutable, immutable_error = gh_json(f"{base}/immutable-releases")
    if immutable_error:
        # The endpoint returns not found when immutability is disabled; preserve the API ambiguity as a setting state, not content coverage.
        state.add_coverage("immutable-releases-setting", "not_present" if immutable_error == "tool_failed" else immutable_error)
    else:
        state.add_coverage("immutable-releases-setting", "checked", object_count=1)

    default_branch = repo_metadata.get("default_branch")
    if default_branch:
        protection, protection_error = gh_json(f"{base}/branches/{urllib.parse.quote(str(default_branch), safe='')}/protection")
        if protection_error:
            state.add_coverage("branch-protection", "not_present" if protection_error == "tool_failed" else protection_error)
        else:
            state.add_coverage("branch-protection", "checked", object_count=1)
    else:
        state.add_coverage("branch-protection", "not_present")

    if stop_when_budget_expires():
        return
    package_count = 0
    package_error: str | None = None
    for package_type in ("container", "npm", "maven", "rubygems", "nuget"):
        if stop_when_budget_expires():
            return
        if package_type not in PACKAGE_CACHE:
            PACKAGE_CACHE[package_type] = api_items(f"user/packages?package_type={package_type}&per_page=100")
        packages, error = PACKAGE_CACHE[package_type]
        if error:
            package_error = error
            continue
        associated = [item for item in packages if ((item.get("repository") or {}).get("full_name") or "").lower() == f"{owner}/{repository}".lower()]
        package_count += len(associated)
        scan_remote_records(state, associated, surface="package-metadata", prefix=f"package:{package_type}", fields=("name", "package_type", "visibility"))
    if package_error and package_count == 0:
        state.add_coverage("packages", package_error, "repository-package-enumeration-failed")
    elif package_count == 0:
        state.add_coverage("packages", "not_present")
        state.add_coverage("container-images", "not_present")
    else:
        state.add_coverage("packages", "checked", object_count=package_count)
        state.add_coverage("package-content", "unreadable", "package-download-and-integrity-layer-not-established", package_count)
        state.add_coverage("container-images", "unreadable", "container-manifest-and-layer-inspection-not-established", package_count)


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


def download_release_assets(
    owner: str,
    repository: str,
    state: ScanState,
    download_root: Path,
    *,
    time_limit_seconds: int = DEFAULT_RELEASE_ASSET_BUDGET_SECONDS,
) -> None:
    deadline = time.monotonic() + max(1, time_limit_seconds)
    releases, error = gh_json(f"repos/{owner}/{repository}/releases?per_page=100")
    if error:
        state.add_coverage("release-assets", error, "release-enumeration-failed")
        return
    assets: list[tuple[int, str, str, int]] = []
    for release in releases or []:
        release_id = int(release.get("id", 0))
        for field in ("name", "body", "tag_name", "target_commitish"):
            value = release.get(field)
            if isinstance(value, str) and value:
                scan_text(state, value, surface="release-metadata", object_id=f"release:{release_id}:{field}", display_path=f"release:{release_id}:{field}")
        for asset in release.get("assets", []):
            assets.append((release_id, str(asset.get("name", "asset")), str(asset.get("url", "")), int(asset.get("size", 0))))
    state.add_coverage("release-metadata", "checked" if releases else "not_present", object_count=len(releases or []))
    if not assets:
        state.add_coverage("release-assets", "not_present")
        return
    checked = 0
    for asset_index, (release_id, name, url, size) in enumerate(assets):
        if time.monotonic() >= deadline:
            state.add_coverage(
                "release-assets",
                "tool_failed",
                "release-asset-time-limit-exceeded",
                len(assets) - asset_index,
            )
            break
        object_id = f"release:{release_id}:{name}"
        if size > DEFAULT_MAX_FILE_BYTES:
            state.add_coverage("release-assets", "unreadable", f"oversized-release-asset:{object_id}")
            continue
        asset_data, download_error = gh_download(url)
        if download_error or asset_data is None:
            status = "unreadable" if download_error == "not_present" else download_error or "tool_failed"
            state.add_coverage("release-assets", status, f"release-asset-download-failed:{object_id}")
            continue
        destination = download_root / str(release_id) / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(asset_data)
        scan_bytes(state, asset_data, surface="release-assets", object_id=object_id, display_path=name)
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


def remote_full_name(repository: Path) -> str | None:
    result = run(["git", "remote", "get-url", "origin"], repository)
    if result.returncode != 0:
        return None
    value = result.stdout.strip().rstrip("/")
    match = re.search(r"github\.com[/:]([^/]+)/([^/]+?)(?:\.git)?$", value, re.IGNORECASE)
    return f"{match.group(1)}/{match.group(2)}" if match else None


def discover_git_repositories(local_roots: Iterable[Path]) -> dict[str, Path]:
    discovered: dict[str, Path] = {}
    visited: set[str] = set()
    excluded = {".git", ".pnpm", ".venv", "venv", "node_modules", "dist", "build", "target", ".cache", "cache", "downloads", "__pycache__"}
    for local_root in local_roots:
        if not local_root.exists():
            continue
        for current, directories, _ in os.walk(local_root, topdown=True, followlinks=False):
            directories[:] = sorted(name for name in directories if name.lower() not in excluded and not (Path(current) / name).is_symlink())
            repository = Path(current)
            if not (repository / ".git").exists():
                continue
            try:
                real = repository.resolve(strict=True)
            except OSError:
                continue
            key = os.path.normcase(str(real))
            if key in visited:
                continue
            visited.add(key)
            full_name = remote_full_name(real)
            if full_name:
                discovered.setdefault(full_name.lower(), real)
    return discovered


def extract_text_values(value: Any, prefix: str = "payload") -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield prefix, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from extract_text_values(child, f"{prefix}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from extract_text_values(child, f"{prefix}[{index}]")


class PrivateCandidateStore:
    def __init__(self, path: Path) -> None:
        self.path = ensure_private_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS candidates (rule_id TEXT, severity TEXT, raw_value TEXT, source_kind TEXT, source_count INTEGER, PRIMARY KEY(rule_id, raw_value, source_kind))"
        )
        self.attempted_count = int(self.connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[0])
        self.limit_exceeded = False
        restrict_private_path(self.path)

    def add(self, candidates: Iterable[dict[str, Any]], source_kind: str) -> bool:
        rows: list[tuple[str, str, str, str, int]] = []
        for item in candidates:
            if self.attempted_count >= MAX_PRIVATE_CANDIDATE_ATTEMPTS:
                self.limit_exceeded = True
                break
            rows.append((item["rule_id"], item["severity"], item["raw_value"], source_kind, 1))
            self.attempted_count += 1
        self.connection.executemany(
            "INSERT INTO candidates VALUES (?, ?, ?, ?, ?) ON CONFLICT(rule_id, raw_value, source_kind) DO UPDATE SET source_count=source_count+1",
            rows,
        )
        return self.limit_exceeded

    def commit(self) -> None:
        self.connection.commit()

    def restore_document(self, document: dict[str, Any]) -> None:
        rows = []
        for item in document.get("candidates", []):
            if not isinstance(item, dict) or not {"rule_id", "severity", "raw_value", "source_kind"}.issubset(item):
                continue
            rows.append((item["rule_id"], item["severity"], item["raw_value"], item["source_kind"], int(item.get("source_count", 1))))
        self.connection.executemany(
            "INSERT INTO candidates VALUES (?, ?, ?, ?, ?) ON CONFLICT(rule_id, raw_value, source_kind) DO UPDATE SET source_count=MAX(source_count, excluded.source_count)",
            rows,
        )

    def write_document(self, output: Path) -> int:
        resolved = ensure_private_path(output)
        count = int(self.connection.execute("SELECT COUNT(*) FROM candidates").fetchone()[0])
        temporary = resolved.with_name(f".{resolved.name}.tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(f'{{\n  "schema_version": {SCHEMA_VERSION},\n  "candidates": [\n')
            first = True
            for rule_id, severity, raw_value, source_kind, source_count in self.connection.execute(
                "SELECT rule_id, severity, raw_value, source_kind, source_count FROM candidates ORDER BY rule_id, source_kind, raw_value"
            ):
                if not first:
                    handle.write(",\n")
                first = False
                handle.write("    " + json.dumps({"rule_id": rule_id, "severity": severity, "raw_value": raw_value, "source_kind": source_kind, "source_count": source_count}, ensure_ascii=False, sort_keys=True))
            handle.write(f'\n  ],\n  "candidate_count": {count}\n}}\n')
        os.replace(temporary, resolved)
        restrict_private_path(resolved)
        return count

    def close(self) -> None:
        self.connection.commit()
        self.connection.close()

    def remove_database(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            try:
                candidate.unlink(missing_ok=True)
            except OSError:
                pass


def discover_saved_project_roots(codex_home: Path) -> tuple[list[Path], str | None]:
    state_path = codex_home / ".codex-global-state.json"
    try:
        document = json.loads(state_path.read_text(encoding="utf-8"))
        values: list[str] = []
        values.extend(document.get("electron-saved-workspace-roots") or [])
        for project in (document.get("local-projects") or {}).values():
            values.extend(project.get("rootPaths") or [])
        unique: dict[str, Path] = {}
        for value in values:
            path = Path(value).expanduser()
            try:
                resolved = path.resolve(strict=True)
            except OSError:
                continue
            unique[os.path.normcase(str(resolved))] = resolved
        return [unique[key] for key in sorted(unique)], None
    except (OSError, ValueError, json.JSONDecodeError, AttributeError):
        return [], "saved-project-state-unreadable"


def iter_project_files(root: Path) -> Iterable[tuple[str, Path]]:
    excluded = {".git", "node_modules", ".venv", "venv", "dist", "build", "target", ".cache", "cache", "downloads", "__pycache__"}
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories[:] = sorted(name for name in directories if name.lower() not in excluded and not (Path(current) / name).is_symlink())
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink():
                continue
            yield path.relative_to(root).as_posix(), path


def scan_local_session_file(path: Path, source_kind: str, policy: dict[str, Any], *, collect_raw: bool = True) -> dict[str, Any]:
    initial_stat = path.stat()
    state = ScanState("local-codex-history", policy, collect_raw=collect_raw)
    session_ids: set[str] = set()
    record_count = 0
    status = "checked"
    candidates: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            for line_number, line in enumerate(handle, start=1):
                record_count += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    state.add_coverage(source_kind, "unreadable", "truncated-or-invalid-jsonl-record")
                    status = "unreadable"
                    continue
                if record.get("type") == "session_meta" and isinstance(record.get("payload"), dict):
                    candidate_id = record["payload"].get("id")
                    if isinstance(candidate_id, str):
                        session_ids.add(candidate_id)
                for field, text_value in extract_text_values(record):
                    state.raw_candidates.clear()
                    state._candidate_keys.clear()
                    scan_text(state, text_value, surface=source_kind, object_id=f"session:{min(session_ids, default='unknown')}:{line_number}:{field}", display_path=f"session-record:{line_number}:{field}")
                    candidates.extend(state.raw_candidates)
    except (OSError, UnicodeError):
        status = "permission_denied"
    try:
        final_stat = path.stat()
        if final_stat.st_size != initial_stat.st_size or final_stat.st_mtime_ns != initial_stat.st_mtime_ns:
            state.add_coverage(source_kind, "unreadable", "session-file-changed-during-scan")
            status = "unreadable"
    except OSError:
        state.add_coverage(source_kind, "permission_denied", "session-file-restat-failed")
        status = "permission_denied"
    if any(item.status not in {"checked", "not_present"} for item in state.coverage):
        status = "unreadable"
    return {
        "session_ids": sorted(session_ids),
        "record_count": record_count,
        "status": status,
        "finding_count": len(state.findings),
        "candidates": candidates,
        "candidate_limit_exceeded": any(item.reason == "raw-candidate-limit-exceeded" for item in state.coverage),
    }


def command_audit_local_session_worker(args: argparse.Namespace) -> int:
    policy = load_policy(Path(args.policy)) if args.policy else empty_policy()
    result = scan_local_session_file(Path(args.session_file), args.source_kind, policy, collect_raw=not args.no_raw)
    write_json(ensure_private_path(Path(args.result)), result, private=True)
    return 0


def command_audit_local(args: argparse.Namespace) -> int:
    codex_home = get_codex_home()
    output = ensure_private_path(Path(args.output))
    candidates_output = ensure_private_path(Path(args.candidates_output))
    checkpoint = ensure_private_path(Path(args.checkpoint))
    policy = load_policy(Path(args.policy)) if args.policy else empty_policy()
    current_scanner_hash = sha256_bytes(Path(__file__).read_bytes())
    current_policy_fingerprint = policy_fingerprint(policy)
    database_path = candidates_output.with_suffix(".sqlite")
    database_preexisting = database_path.exists()
    if not (args.resume and checkpoint.exists()):
        for suffix in ("", "-wal", "-shm"):
            Path(str(database_path) + suffix).unlink(missing_ok=True)
        database_preexisting = False
    store = PrivateCandidateStore(database_path)
    processed: set[str] = set()
    checkpoint_document: dict[str, Any] = {}
    if args.resume and checkpoint.exists():
        try:
            checkpoint_document = json.loads(checkpoint.read_text(encoding="utf-8"))
            processed = set(checkpoint_document.get("processed", []))
        except (OSError, json.JSONDecodeError):
            processed = set()
    checkpoint_compatible = bool(checkpoint_document) and not (
        checkpoint_document.get("schema_version") != 3
        or
        checkpoint_document.get("scanner_sha256") != current_scanner_hash
        or checkpoint_document.get("policy_fingerprint") != current_policy_fingerprint
    )
    if checkpoint_document and not checkpoint_compatible:
        checkpoint_document = {}
        processed = set()
        store.close()
        store.remove_database()
        store = PrivateCandidateStore(candidates_output.with_suffix(".sqlite"))
        database_preexisting = False
    if args.resume and checkpoint_compatible and candidates_output.exists() and not database_preexisting:
        try:
            store.restore_document(json.loads(candidates_output.read_text(encoding="utf-8")))
            store.commit()
        except (OSError, json.JSONDecodeError):
            pass
    if checkpoint_compatible:
        store.attempted_count = max(store.attempted_count, int(checkpoint_document.get("candidate_attempt_count", 0)))
        store.limit_exceeded = bool(checkpoint_document.get("candidate_store_limit_exceeded", False))
    sessions: dict[str, dict[str, Any]] = {
        item["session_id"]: item
        for item in checkpoint_document.get("sessions", [])
        if isinstance(item, dict) and "session_id" in item
    }
    if args.resume and output.exists():
        try:
            previous_report = json.loads(output.read_text(encoding="utf-8"))
            sessions = {item["session_id"]: item for item in previous_report.get("sessions", []) if isinstance(item, dict) and "session_id" in item}
        except (OSError, json.JSONDecodeError):
            sessions = {}
    if processed and not sessions:
        processed = set()
    coverage: list[dict[str, Any]] = []
    total_findings = int(checkpoint_document.get("finding_count", 0))
    project_results: list[dict[str, Any]] = [
        item for item in checkpoint_document.get("projects", []) if isinstance(item, dict) and isinstance(item.get("project_id"), str)
    ]
    processed_projects = {item["project_id"] for item in project_results}
    for source_kind, folder in (("active-session", codex_home / "sessions"), ("archived-session", codex_home / "archived_sessions")):
        if not folder.exists():
            coverage.append({"surface": source_kind, "status": "not_present", "object_count": 0})
            continue
        for path in sorted(folder.rglob("*.jsonl")):
            try:
                initial_stat = path.stat()
            except OSError:
                coverage.append({"surface": source_kind, "status": "permission_denied", "reason": "session-file-stat-failed", "object_count": 0})
                continue
            file_key = f"{initial_stat.st_size}:{initial_stat.st_mtime_ns}:{path.name}"
            if file_key in processed:
                continue
            worker_token = hashlib.sha256(file_key.encode("utf-8")).hexdigest()[:16]
            worker_result_path = checkpoint.with_name(f".{checkpoint.name}.{worker_token}.worker.private.json")
            worker_command = [
                sys.executable,
                "-X",
                "utf8",
                str(Path(__file__).resolve()),
                "_audit-local-session-worker",
                "--session-file",
                str(path),
                "--source-kind",
                source_kind,
                "--result",
                str(worker_result_path),
            ]
            if args.policy:
                worker_command.extend(["--policy", str(args.policy)])
            if store.limit_exceeded:
                worker_command.append("--no-raw")
            try:
                worker = subprocess.run(worker_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=DEFAULT_LOCAL_FILE_BUDGET_SECONDS, check=False)
                if worker.returncode == 0 and worker_result_path.exists():
                    worker_result = json.loads(worker_result_path.read_text(encoding="utf-8"))
                else:
                    worker_result = {"session_ids": [], "record_count": 0, "status": "unreadable", "finding_count": 0, "candidates": [], "candidate_limit_exceeded": True}
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
                worker_result = {"session_ids": [], "record_count": 0, "status": "unreadable", "finding_count": 0, "candidates": [], "candidate_limit_exceeded": True}
            finally:
                worker_result_path.unlink(missing_ok=True)
            status = str(worker_result.get("status", "unreadable"))
            record_count = int(worker_result.get("record_count", 0))
            total_findings += int(worker_result.get("finding_count", 0))
            candidate_limit_exceeded = bool(worker_result.get("candidate_limit_exceeded"))
            if store.add(worker_result.get("candidates", []), source_kind):
                candidate_limit_exceeded = True
            if candidate_limit_exceeded:
                status = "unreadable"
            stable_ids = sorted(set(worker_result.get("session_ids", []))) or [f"unresolved-{worker_token}"]
            for stable_id in stable_ids:
                previous = sessions.get(stable_id)
                if previous:
                    previous["duplicate_file_count"] += 1
                    previous["record_count"] += record_count
                    if status != "checked":
                        previous["status"] = status
                else:
                    sessions[stable_id] = {"session_id": stable_id, "source_kind": source_kind, "status": status, "record_count": record_count, "duplicate_file_count": 0}
            processed.add(file_key)
            store.commit()
            write_json(checkpoint, {"schema_version": 3, "scanner_sha256": current_scanner_hash, "policy_fingerprint": current_policy_fingerprint, "processed": sorted(processed), "sessions": [sessions[key] for key in sorted(sessions)], "projects": project_results, "finding_count": total_findings, "candidate_attempt_count": store.attempted_count, "candidate_store_limit_exceeded": store.limit_exceeded}, private=True)
            print(json.dumps({"phase": "sessions", "processed_file_count": len(processed), "unique_session_count": len(sessions)}, sort_keys=True), flush=True)
        kind_sessions = [item for item in sessions.values() if item["source_kind"] == source_kind]
        kind_status = "checked" if all(item["status"] == "checked" for item in kind_sessions) else "unreadable"
        coverage.append({"surface": source_kind, "status": kind_status, "object_count": len(kind_sessions)})
    roots, root_error = discover_saved_project_roots(codex_home)
    for index, root in enumerate(roots, start=1):
        project_id = f"saved-project-{index}"
        if project_id in processed_projects:
            print(json.dumps({"phase": "saved-projects", "processed_project_count": index, "saved_project_count": len(roots)}, sort_keys=True), flush=True)
            continue
        state = ScanState(f"saved-project-{index}", policy, collect_raw=True)
        file_count = 0
        try:
            iterator = iter_working_tree(root) if (root / ".git").exists() else iter_project_files(root)
            for relative, path in iterator:
                file_count += 1
                try:
                    state.raw_candidates.clear()
                    state._candidate_keys.clear()
                    scan_bytes(state, path.read_bytes(), surface="saved-project", object_id=f"project:{index}:{relative}", display_path=relative)
                    if store.add(state.raw_candidates, "saved-project"):
                        state.add_coverage("saved-project", "tool_failed", "private-candidate-store-limit-exceeded")
                except (OSError, PermissionError):
                    state.add_coverage("saved-project", "permission_denied", "project-file-unreadable")
            state.add_coverage("saved-project", "checked", object_count=file_count)
            status = "checked" if decision_for(state) != "incomplete" else "unreadable"
        except OSError:
            status = "permission_denied"
        total_findings += len(state.findings)
        project_results.append({"project_id": project_id, "status": status, "file_count": file_count, "coverage": consolidated_coverage(state.coverage), "summary": {"finding_count": len(state.findings)}})
        processed_projects.add(project_id)
        store.commit()
        write_json(checkpoint, {"schema_version": 3, "scanner_sha256": current_scanner_hash, "policy_fingerprint": current_policy_fingerprint, "processed": sorted(processed), "sessions": [sessions[key] for key in sorted(sessions)], "projects": project_results, "finding_count": total_findings, "candidate_attempt_count": store.attempted_count, "candidate_store_limit_exceeded": store.limit_exceeded}, private=True)
        print(json.dumps({"phase": "saved-projects", "processed_project_count": index, "saved_project_count": len(roots)}, sort_keys=True), flush=True)
    if root_error:
        coverage.append({"surface": "saved-project-roots", "status": "unreadable", "reason": root_error, "object_count": 0})
    else:
        coverage.append({"surface": "saved-project-roots", "status": "checked", "object_count": len(roots)})
    candidate_count = store.write_document(candidates_output)
    store.close()
    store.remove_database()
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "mode": "periodic-exposure-audit",
        "decision": "incomplete" if any(item.get("status") not in {"checked", "not_present"} for item in coverage) or any(item["status"] != "checked" for item in sessions.values()) or any(item["status"] != "checked" for item in project_results) else ("review" if total_findings else "pass"),
        "session_count": len(sessions),
        "sessions": [sessions[key] for key in sorted(sessions)],
        "saved_project_count": len(project_results),
        "projects": project_results,
        "coverage": coverage,
        "summary": {"candidate_count": candidate_count, "finding_count": total_findings},
        "policy_fingerprint": current_policy_fingerprint,
        "scanner_versions": {
            "safe_publish": "3",
            "safe_publish_sha256": current_scanner_hash,
            "python": platform.python_version(),
            "image_ocr_budget_seconds": DEFAULT_IMAGE_OCR_BUDGET_SECONDS,
        },
    }
    stable = {key: value for key, value in report.items() if key not in {"generated_at", "report_fingerprint"}}
    report["report_fingerprint"] = sha256_bytes(json.dumps(stable, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    write_json(output, report, private=True)
    if args.public_summary:
        write_json(Path(args.public_summary), {"schema_version": SCHEMA_VERSION, "mode": report["mode"], "decision": report["decision"], "scanner_sha256": current_scanner_hash, "session_count": len(sessions), "saved_project_count": len(project_results), "candidate_count": candidate_count, "coverage_status_counts": {status: sum(item.get("status") == status for item in coverage) for status in ("checked", "not_present", "unreadable", "permission_denied", "tool_failed")}})
    print(json.dumps({"decision": report["decision"], "session_count": len(sessions), "saved_project_count": len(project_results), "candidate_count": candidate_count}, sort_keys=True))
    return {"pass": 0, "review": 2, "block": 3, "incomplete": 4}[report["decision"]]


def command_compile_policy(args: argparse.Namespace) -> int:
    source = load_policy(Path(args.policy))
    repository = args.repository
    identifiers = [item for item in source["identifiers"] if "all" in item.get("scopes", ["all"]) or repository in item.get("scopes", [])]
    ids = {item["id"] for item in identifiers}
    compiled = {
        "schema_version": SCHEMA_VERSION,
        "identifiers": identifiers,
        "replacements": [item for item in source["replacements"] if item["identifier_id"] in ids],
        "approved_locations": [item for item in source["approved_locations"] if item["rule_id"] in ids],
        "blocked_paths": source["blocked_paths"],
        "binary_approvals": [item for item in source["binary_approvals"] if item["object"].startswith(("working-tree:", "git:", "release:"))],
        "exceptions": [item for item in source["exceptions"] if item["rule_id"] in ids],
        "risk_acceptances": [item for item in source["risk_acceptances"] if item["repository"] == repository],
    }
    validate_policy(compiled)
    encoded = base64.b64encode(json.dumps(compiled, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if len(encoded) > MAX_SECRET_BYTES:
        raise ValueError("Compiled private policy exceeds 48 KB")
    write_json(Path(args.output), compiled, private=True)
    print(json.dumps({"identifier_count": len(identifiers), "encoded_bytes": len(encoded), "policy_fingerprint": policy_fingerprint(compiled)}, sort_keys=True))
    return 0


def command_audit_fleet(args: argparse.Namespace) -> int:
    root = private_root()
    output = ensure_private_path(Path(args.output))
    candidates_output = ensure_private_path(Path(args.candidates_output))
    local_root = Path(args.local_root).expanduser().resolve() if args.local_root else None
    policy = load_policy(Path(args.policy)) if args.policy else empty_policy()
    current_scanner_hash = sha256_bytes(Path(__file__).read_bytes())
    current_policy_fingerprint = policy_fingerprint(policy)
    repos, error = gh_json("user/repos?affiliation=owner&per_page=100&sort=full_name")
    if error:
        raise RuntimeError("Unable to enumerate the authenticated GitHub repository fleet")
    owned = [repo for repo in repos if (repo.get("owner") or {}).get("login", "").lower() == args.owner.lower()]
    owned_by_id = {int(repo["id"]): repo for repo in owned}
    repositories = [owned_by_id[key] for key in sorted(owned_by_id)]
    local_map = discover_git_repositories([local_root] if local_root else [])
    detailed: list[dict[str, Any]] = []
    resume_compatible = False
    candidate_store = PrivateCandidateStore(candidates_output.with_suffix(".sqlite"))
    if args.resume and output.exists():
        try:
            previous = json.loads(output.read_text(encoding="utf-8"))
            if previous.get("owner", "").lower() == args.owner.lower() and (previous.get("scanner_versions") or {}).get("safe_publish_sha256") == current_scanner_hash and previous.get("policy_fingerprint") == current_policy_fingerprint:
                detailed = list(previous.get("repositories") or [])
                resume_compatible = True
        except (OSError, json.JSONDecodeError):
            detailed = []
    if args.resume and resume_compatible and candidates_output.exists():
        try:
            candidate_store.restore_document(json.loads(candidates_output.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            pass
    elif args.resume and not resume_compatible:
        candidate_store.close()
        candidate_store.remove_database()
        candidate_store = PrivateCandidateStore(candidates_output.with_suffix(".sqlite"))
    completed_ids = {int(item["repository_id"]) for item in detailed if "repository_id" in item}
    ephemeral_mirror_root: Path | None = None
    if args.cache_mirrors:
        mirror_root = root / "mirrors"
    else:
        ephemeral_mirror_root = Path(tempfile.mkdtemp(prefix="safe-publish-mirrors-"))
        mirror_root = ephemeral_mirror_root
        atexit.register(shutil.rmtree, ephemeral_mirror_root, True)
    for index, repo in enumerate(repositories, start=1):
        if int(repo["id"]) in completed_ids:
            print(json.dumps({"progress": index, "repository_count": len(repositories), "resumed": True}, sort_keys=True), flush=True)
            continue
        name = str(repo["name"])
        state = ScanState(name, policy, collect_raw=True)
        mirror = mirror_root / f"{int(repo['id'])}.git"
        prepared, mirror_error = prepare_mirror(args.owner, name, local_map.get(f"{args.owner}/{name}".lower()), mirror)
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
        with tempfile.TemporaryDirectory(prefix="safe-publish-release-") as release_temporary:
            download_release_assets(
                args.owner,
                name,
                state,
                Path(release_temporary),
                time_limit_seconds=getattr(args, "release_time_limit_seconds", DEFAULT_RELEASE_ASSET_BUDGET_SECONDS),
            )
        if args.surface_profile == "repository-associated":
            audit_repository_associated_surfaces(
                state,
                args.owner,
                name,
                repo,
                time_limit_seconds=getattr(args, "associated_time_limit_seconds", DEFAULT_ASSOCIATED_SURFACE_BUDGET_SECONDS),
            )
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
        candidate_store.add(state.raw_candidates, "github-fleet")
        detailed.sort(key=lambda item: item["repository_id"])
        write_json(output, {"schema_version": SCHEMA_VERSION, "generated_at": utc_now(), "owner": args.owner, "mode": "periodic-exposure-audit", "surface_profile": args.surface_profile, "policy_fingerprint": current_policy_fingerprint, "scanner_versions": {"safe_publish": "3", "safe_publish_sha256": current_scanner_hash, "gitleaks": GITLEAKS_VERSION, "python": platform.python_version(), "image_ocr_budget_seconds": DEFAULT_IMAGE_OCR_BUDGET_SECONDS}, "repositories": detailed}, private=True)
        print(json.dumps({"progress": index, "repository_count": len(repositories)}, sort_keys=True), flush=True)
    decision_counts = {decision: sum(item["decision"] == decision for item in detailed) for decision in ("pass", "review", "block", "incomplete")}
    profile_exclusions = ["gists", "github-projects", "codespaces", "billing-data", "external-clones", "other-accounts"]
    if args.surface_profile == "publication":
        profile_exclusions.extend(["issues", "pull-requests", "comments", "reviews", "discussions", "wiki", "github-pages", "actions-logs", "actions-artifacts", "packages", "container-images", "caches", "deployments"])
    fleet_result_explanation = {
        "count_source": "repository_count comes from unique authenticated owner repository IDs; candidate_count comes from the lossless private candidate store; decision_counts come from one strict report per repository",
        "match_reason": "Each strict decision reflects unresolved rule matches and declared surface coverage for that repository",
        "publication_effect": "A periodic fleet audit reports exposure but never authorizes or blocks an exact GitHub write by itself",
        "next_step": "Run the exact publication gate for each intended source commit and release asset before any remote write",
    }
    fleet_report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "mode": "periodic-exposure-audit",
        "surface_profile": args.surface_profile,
        "owner": args.owner,
        "repository_count": len(detailed),
        "decision_counts": decision_counts,
        "policy_fingerprint": current_policy_fingerprint,
        "scanner_versions": {"safe_publish": "3", "safe_publish_sha256": current_scanner_hash, "gitleaks": GITLEAKS_VERSION, "python": platform.python_version(), "image_ocr_budget_seconds": DEFAULT_IMAGE_OCR_BUDGET_SECONDS},
        "declared_exclusions": profile_exclusions,
        "result_explanation": fleet_result_explanation,
        "repositories": detailed,
    }
    candidate_count = candidate_store.write_document(candidates_output)
    candidate_store.close()
    candidate_store.remove_database()
    write_json(output, fleet_report, private=True)
    if ephemeral_mirror_root is not None:
        shutil.rmtree(ephemeral_mirror_root, ignore_errors=True)
    if args.public_summary:
        public_summary = {
            "schema_version": SCHEMA_VERSION,
            "generated_at": fleet_report["generated_at"],
            "mode": fleet_report["mode"],
            "surface_profile": fleet_report["surface_profile"],
            "scanner_sha256": current_scanner_hash,
            "owner_repository_count": len(detailed),
            "public_count": sum(item["visibility"] == "public" for item in detailed),
            "private_count": sum(item["visibility"] == "private" for item in detailed),
            "fork_count": sum(item["fork"] for item in detailed),
            "archived_count": sum(item["archived"] for item in detailed),
            "candidate_count": candidate_count,
            "decision_counts": decision_counts,
            "finding_counts_by_rule": {},
            "coverage_gap_counts_by_surface": {},
            "coverage_status_counts": {},
            "coverage_gap_reason_counts": {},
            "repository_security_setting_counts": {},
            "user_level_push_protection": "unknown",
            "legacy_local_inventory": aggregate_local_inventory(local_map),
            "result_explanation": fleet_result_explanation,
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
    print(json.dumps({"repository_count": len(detailed), "candidate_count": candidate_count, "decision_counts": decision_counts, "result_explanation": fleet_result_explanation}, sort_keys=True))
    return 0 if len(detailed) == len(owned_by_id) else 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit and gate a sanitized GitHub publication without exposing raw matches")
    parser.add_argument("--version", action="version", version=f"github-safe-publish {TOOL_VERSION}")
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
    audit.add_argument("--associated-time-limit-seconds", type=int, default=DEFAULT_ASSOCIATED_SURFACE_BUDGET_SECONDS)
    audit.add_argument("--release-time-limit-seconds", type=int, default=DEFAULT_RELEASE_ASSET_BUDGET_SECONDS)
    audit.add_argument("--surface-profile", choices=("publication", "repository-associated"), default="publication")
    audit.add_argument("--resume", action="store_true")
    audit.add_argument("--cache-mirrors", action="store_true", help="Retain private mirrors for an explicitly approved secure cache")
    audit.set_defaults(handler=command_audit_fleet)

    local = subcommands.add_parser("audit-local", help="Audit local Codex sessions and saved project roots without exposing raw candidates")
    local.add_argument("--policy")
    local.add_argument("--output", required=True)
    local.add_argument("--candidates-output", required=True)
    local.add_argument("--checkpoint", required=True)
    local.add_argument("--public-summary")
    local.add_argument("--resume", action="store_true")
    local.set_defaults(handler=command_audit_local)

    local_worker = subcommands.add_parser("_audit-local-session-worker", help=argparse.SUPPRESS)
    local_worker.add_argument("--session-file", required=True)
    local_worker.add_argument("--source-kind", required=True, choices=("active-session", "archived-session"))
    local_worker.add_argument("--policy")
    local_worker.add_argument("--result", required=True)
    local_worker.add_argument("--no-raw", action="store_true")
    local_worker.set_defaults(handler=command_audit_local_session_worker)

    worktree_worker = subcommands.add_parser("_scan-worktree-worker", help=argparse.SUPPRESS)
    worktree_worker.add_argument("--task", required=True)
    worktree_worker.set_defaults(handler=command_scan_worktree_worker)

    history_worker = subcommands.add_parser("_scan-git-history-worker", help=argparse.SUPPRESS)
    history_worker.add_argument("--task", required=True)
    history_worker.set_defaults(handler=command_scan_git_history_worker)

    compile_policy = subcommands.add_parser("compile-policy", help="Compile a repository-scoped v3 policy from the private master policy")
    compile_policy.add_argument("--policy", required=True)
    compile_policy.add_argument("--repository", required=True)
    compile_policy.add_argument("--output", required=True)
    compile_policy.set_defaults(handler=command_compile_policy)

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

    gate = subcommands.add_parser("gate", help="Audit strictly and decide publication with the selected release profile")
    gate.add_argument("--source", required=True)
    gate.add_argument("--repository")
    gate.add_argument("--policy")
    gate.add_argument("--policy-b64-env")
    gate.add_argument("--generic-only", action="store_true")
    gate.add_argument("--release-asset", action="append", default=[])
    gate.add_argument("--gitleaks-path")
    gate.add_argument("--release-profile", choices=tuple(sorted(RELEASE_PROFILES)), default="permissive-noncritical")
    gate.add_argument("--git-history-checkpoint")
    gate.add_argument("--worktree-checkpoint")
    gate.add_argument("--ocr-checkpoint")
    gate.add_argument("--worktree-time-limit-seconds", type=int, default=DEFAULT_GATE_WORKTREE_BUDGET_SECONDS)
    gate.add_argument("--worktree-checkpoint-interval", type=int, default=DEFAULT_WORKTREE_CHECKPOINT_INTERVAL)
    gate.add_argument("--git-history-time-limit-seconds", type=int, default=DEFAULT_GATE_HISTORY_BUDGET_SECONDS)
    gate.add_argument("--git-history-checkpoint-interval", type=int, default=DEFAULT_HISTORY_CHECKPOINT_INTERVAL)
    gate.add_argument("--report", required=True)
    gate.add_argument("--public-summary")
    gate.set_defaults(handler=command_gate)

    doctor = subcommands.add_parser("doctor", help="Check local parser and publication dependencies without changing a repository")
    doctor.add_argument("--source")
    doctor.add_argument("--all", action="store_true", help="Require every supported parser layer")
    doctor.add_argument("--output")
    doctor.set_defaults(handler=command_doctor)

    managed = subcommands.add_parser("managed-publish", help="Gate one exact worktree candidate and publish it through a pull request")
    managed.add_argument("--source", required=True)
    managed.add_argument("--repository", required=True)
    managed.add_argument("--base-commit", required=True)
    managed.add_argument("--base-branch")
    managed.add_argument("--policy", required=True)
    managed.add_argument("--private-output-dir", required=True)
    managed.add_argument("--checkpoint")
    managed.add_argument("--public-summary")
    managed.add_argument("--readme-auditor")
    managed.add_argument("--validation-command", action="append", default=[])
    managed.add_argument("--validation-timeout-seconds", type=int, default=900)
    managed.add_argument("--checks-timeout-seconds", type=int, default=1800)
    managed.add_argument("--intent", choices=("audit", "pr", "auto-merge"), default="audit")
    managed.add_argument("--branch")
    managed.add_argument("--commit-message", default="chore: publish verified skill update")
    managed.add_argument("--pr-title", default="Publish verified skill update")
    managed.add_argument("--pr-body", default="Generated from an isolated candidate and approved by the local trusted publication gate")
    managed.add_argument("--release-asset", action="append", default=[])
    managed.add_argument("--gitleaks-path")
    managed.add_argument("--release-profile", choices=tuple(sorted(RELEASE_PROFILES)), default="permissive-noncritical")
    managed.add_argument("--git-history-time-limit-seconds", type=int, default=DEFAULT_GATE_HISTORY_BUDGET_SECONDS)
    managed.add_argument("--git-history-checkpoint-interval", type=int, default=DEFAULT_HISTORY_CHECKPOINT_INTERVAL)
    managed.add_argument("--worktree-time-limit-seconds", type=int, default=DEFAULT_GATE_WORKTREE_BUDGET_SECONDS)
    managed.add_argument("--worktree-checkpoint-interval", type=int, default=DEFAULT_WORKTREE_CHECKPOINT_INTERVAL)
    managed.add_argument("--resume", action="store_true")
    managed.set_defaults(handler=command_managed_publish)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, RuntimeError, ValueError) as exc:
        # The exception class is safe to expose; the message is intentionally generic.
        print(
            json.dumps(
                {"decision": "incomplete", "publication_decision": "deny", "error": exc.__class__.__name__},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
