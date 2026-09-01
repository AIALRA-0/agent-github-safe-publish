from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Iterable
import warnings
import zipfile

from .inventory import committed_blob_sha256s
from .model import PublicObservation, SourceFinding


TEXT_EXTENSIONS = {
    ".c", ".cc", ".cfg", ".conf", ".cpp", ".css", ".csv", ".env", ".go",
    ".h", ".hpp", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".md",
    ".ps1", ".py", ".rb", ".rs", ".sh", ".sql", ".toml", ".ts", ".tsx",
    ".txt", ".xml", ".yaml", ".yml",
}
DATABASE_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}
DATABASE_SIDECAR_SUFFIXES = {".db-shm", ".db-wal", ".sqlite-shm", ".sqlite-wal", ".sqlite3-shm", ".sqlite3-wal"}
ARCHIVE_EXTENSIONS = {".zip"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".ico", ".icns"}
OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx"}
FONT_EXTENSIONS = {".ttf", ".otf", ".woff", ".woff2"}
MEDIA_EXTENSIONS = {".mp3", ".mp4", ".mov", ".wav", ".m4a", ".webm"}
REMOVABLE_ARTIFACT_EXTENSIONS = {".doc", ".xls", ".ppt", ".7z", ".rar", ".exe", ".dll", ".bin"}
LEGAL_FILENAMES = {"license", "license.md", "license.txt", "notice", "notice.md", "notice.txt", "citation.cff", "copying", "copyright"}

CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|cookie|session)[\"']?\]?\s*[:=]\s*(\"[^\"\r\n]{8,}\"|'[^'\r\n]{8,}'|[^\s\"'`,;]{8,})"
)
PRIVATE_IPV4 = re.compile(r"(?<!\d)(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?!\d)")
URL = re.compile(r"https?://[^\s\"'<>()]+", re.I)
BRAND = re.compile(r"(?i)(?<![A-Za-z0-9])AIALRA(?![A-Za-z0-9])")
LFS_POINTER = re.compile(r"(?m)\Aversion https://git-lfs\.github\.com/spec/v1\s*$.*^oid sha256:[0-9a-f]{64}\s*$.*^size \d+\s*$", re.S)
_OCR_ENGINE = None
MAX_IMAGE_PIXELS = 50_000_000
MAX_IMAGE_FRAMES = 100
MAX_PDF_PAGES = 500
SOURCE_CODE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js", ".jsx",
    ".kt", ".mjs", ".php", ".ps1", ".psm1", ".py", ".pyi", ".rb", ".rs", ".sh",
    ".swift", ".ts", ".tsx", ".vue",
}


def _is_exact_placeholder(value: str) -> bool:
    stripped = value.strip()
    normalized = stripped.strip("{}[]()<>\"'").lower()
    if normalized in {"changeme", "change-me", "placeholder", "redacted", "example", "required-at-runtime"}:
        return True
    if re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", stripped):
        return True
    if re.fullmatch(r"(?i)\$env:[A-Za-z_][A-Za-z0-9_]*", stripped):
        return True
    if re.fullmatch(r"%[A-Za-z_][A-Za-z0-9_]*%", stripped):
        return True
    return bool(re.fullmatch(
        r"(?i)(?:example|placeholder|redacted|change[-_]?me|replace[-_]?me|your[-_][A-Za-z0-9_-]+)(?:[-_](?:password|secret|token|key))?",
        normalized,
    ))


def _is_nonliteral_assignment(match: re.Match[str], text: str, display_path: str, raw: str) -> bool:
    if _is_exact_placeholder(raw):
        return True
    start = match.start(2)
    quoted = start > 0 and text[start] in {"'", '"'}
    suffix = Path(display_path.split("!", 1)[0]).suffix.lower()
    if suffix not in SOURCE_CODE_SUFFIXES or quoted:
        return False
    unquoted = raw.strip("\"'")
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", unquoted):
        return True
    return any(character in unquoted for character in ("$", "(", ")", "[", "]", "{", "}", "."))


def _active_credential_match(text: str, display_path: str = "") -> bool:
    return bool(_active_credential_matches(text, display_path))


def _active_credential_matches(text: str, display_path: str = "") -> list[re.Match[str]]:
    active: list[re.Match[str]] = []
    for match in CREDENTIAL_ASSIGNMENT.finditer(text):
        value = match.group(2).strip("\"'")
        lowered = value.lower()
        if value.startswith(("${", "<")) or "environ" in lowered or "process.env" in lowered:
            continue
        if _is_nonliteral_assignment(match, text, display_path, match.group(2)):
            continue
        active.append(match)
    return active


def _high_confidence_credential(match: re.Match[str]) -> bool:
    value = match.group(2).strip("\"'")
    if any(character.isspace() for character in value):
        return False
    classes = sum((
        any(character.islower() for character in value),
        any(character.isupper() for character in value),
        any(character.isdigit() for character in value),
        any(not character.isalnum() for character in value),
    ))
    if re.match(r"(?i)^(?:gh[pousr]_|github_pat_|sk-|akia|xox[baprs]-)", value):
        return True
    key = match.group(1).lower().replace("-", "_")
    if key in {"password", "passwd", "pwd", "secret", "api_key", "apikey", "access_key", "client_secret"}:
        return len(value) >= 8 and classes >= 3
    return len(value) >= 12 and classes >= 3


def _finding(rule_id: str, category: str, path: str, data: bytes, hint: str) -> SourceFinding:
    digest = hashlib.sha256(data).hexdigest()
    stable = hashlib.sha256(f"{rule_id}\0{path}\0{digest}".encode("utf-8")).hexdigest()[:24]
    return SourceFinding(stable, rule_id, category, path, digest, hint)


def _stream_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _finding_from_digest(rule_id: str, category: str, path: str, digest: str, hint: str) -> SourceFinding:
    stable = hashlib.sha256(f"{rule_id}\0{path}\0{digest}".encode("utf-8")).hexdigest()[:24]
    return SourceFinding(stable, rule_id, category, path, digest, hint)


def _contains_private_text(text: str, policy: dict, display_path: str = "") -> bool:
    if _active_credential_match(text, display_path) or PRIVATE_IPV4.search(text):
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


def _looks_like_translation_catalog(text: str) -> bool:
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return False
    if not isinstance(document, dict):
        return False
    pending = list(document.values())
    scalar_count = 0
    string_count = 0
    visited = 0
    while pending and visited < 100000:
        value = pending.pop()
        visited += 1
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        else:
            scalar_count += 1
            string_count += isinstance(value, str)
    return not pending and scalar_count >= 20 and string_count / scalar_count >= 0.8


def _zip_remediation(path: Path, policy: dict) -> str | None:
    maximum_member_bytes = int(policy["security_runtime"].get("maximum_object_bytes", 25 * 1024 * 1024))
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > 10000 or sum(item.file_size for item in members) > 512 * 1024 * 1024:
                return "remove-and-stub"
            for member in members:
                if member.file_size > maximum_member_bytes:
                    return "remove-and-stub"
                normalized = Path(member.filename)
                if normalized.is_absolute() or ".." in normalized.parts or member.is_dir():
                    if not member.is_dir():
                        return "remove-and-stub"
                    continue
                if normalized.suffix.lower() not in TEXT_EXTENSIONS and normalized.suffix:
                    return "repack"
                try:
                    if _contains_private_text(archive.read(member).decode("utf-8"), policy, member.filename):
                        return "repack"
                except UnicodeDecodeError:
                    return "repack"
        return None
    except (OSError, zipfile.BadZipFile):
        return "remove-and-stub"


def _image_inspection(data: bytes, policy: dict, display_path: str) -> tuple[str | None, str]:
    """Inspect metadata, decoded symbols, and OCR text without returning extracted values."""
    try:
        import io
        from PIL import Image, ImageSequence

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                if image.width * image.height > MAX_IMAGE_PIXELS or getattr(image, "n_frames", 1) > MAX_IMAGE_FRAMES:
                    return "remove-and-stub", "image-resource-limit"
                image.load()
                has_metadata = bool(image.getexif()) or bool({key: value for key, value in image.info.items() if key not in {"duration", "loop", "transparency"}})
                frames = [frame.convert("RGB") for frame in ImageSequence.Iterator(image)]
    except Exception:
        return "remove-and-stub", "image-unreadable"
    private_pixels = False
    try:
        import numpy as np
        from rapidocr_onnxruntime import RapidOCR

        global _OCR_ENGINE
        if _OCR_ENGINE is None:
            _OCR_ENGINE = RapidOCR()
        engine = _OCR_ENGINE
        for frame in frames:
            result, _ = engine(np.asarray(frame))
            for item in result or []:
                if len(item) >= 2 and _contains_private_text(str(item[1]), policy, display_path):
                    private_pixels = True
                    break
            if private_pixels:
                break
    except Exception:
        return "remove-and-stub", "image-ocr-unavailable"
    try:
        import cv2
        import numpy as np

        detector = cv2.QRCodeDetector()
        for frame in frames:
            decoded, _, _ = detector.detectAndDecode(np.asarray(frame))
            if decoded and _contains_private_text(decoded, policy, display_path):
                private_pixels = True
                break
    except Exception:
        return "remove-and-stub", "image-symbol-parser-unavailable"
    if private_pixels:
        return "redact-pixels", "image-pixels"
    if has_metadata:
        return "strip-metadata", "image-metadata"
    return None, "image-pixels-metadata"


def _pdf_inspection(data: bytes, policy: dict, display_path: str) -> tuple[str | None, str]:
    try:
        import io
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            return "remove-and-stub", "pdf-encrypted"
        if len(reader.pages) > MAX_PDF_PAGES:
            return "remove-and-stub", "pdf-page-limit"
        has_hidden = bool(reader.metadata) or bool(getattr(reader, "attachments", {}) or {})
        for page in reader.pages:
            if _contains_private_text(page.extract_text() or "", policy, display_path):
                return "remove-and-stub", "pdf-private-text"
    except Exception:
        return "remove-and-stub", "pdf-parser-unavailable"
    try:
        import fitz
        import numpy as np
        from rapidocr_onnxruntime import RapidOCR

        global _OCR_ENGINE
        if _OCR_ENGINE is None:
            _OCR_ENGINE = RapidOCR()
        engine = _OCR_ENGINE
        with fitz.open(stream=data, filetype="pdf") as document:
            for page in document:
                pixmap = page.get_pixmap(matrix=fitz.Matrix(1.25, 1.25), alpha=False)
                if pixmap.width * pixmap.height > MAX_IMAGE_PIXELS:
                    return "remove-and-stub", "pdf-render-limit"
                image = np.frombuffer(pixmap.samples, dtype=np.uint8).reshape(pixmap.height, pixmap.width, pixmap.n)
                result, _ = engine(image)
                for item in result or []:
                    if len(item) >= 2 and _contains_private_text(str(item[1]), policy, display_path):
                        return "remove-and-stub", "pdf-private-pixels"
    except Exception:
        return "remove-and-stub", "pdf-ocr-unavailable"
    return ("strip-metadata", "pdf-metadata") if has_hidden else (None, "pdf-text-pixels-metadata")


def _office_inspection(path: Path, policy: dict) -> tuple[str | None, str]:
    maximum_member_bytes = int(policy["security_runtime"].get("maximum_object_bytes", 25 * 1024 * 1024))
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > 10000:
                return "remove-and-stub", "office-member-limit"
            total = 0
            metadata = False
            for member in members:
                if member.file_size > maximum_member_bytes:
                    return "remove-and-stub", "office-member-size-limit"
                normalized = Path(member.filename)
                if normalized.is_absolute() or ".." in normalized.parts:
                    return "remove-and-stub", "office-path-traversal"
                total += member.file_size
                if total > 512 * 1024 * 1024:
                    return "remove-and-stub", "office-expansion-limit"
                lowered = member.filename.lower()
                if lowered.endswith(("vbaproject.bin", ".ole", ".bin")) or "/embeddings/" in lowered:
                    return "remove-and-stub", "office-active-or-embedded-content"
                data = archive.read(member)
                if lowered.startswith("docprops/"):
                    metadata = metadata or bool(data.strip())
                if lowered.endswith((".xml", ".rels", ".txt")):
                    try:
                        if _contains_private_text(data.decode("utf-8"), policy, f"{path.name}!{member.filename}"):
                            return "remove-and-stub", "office-private-text"
                    except UnicodeDecodeError:
                        return "remove-and-stub", "office-undecodable-xml"
    except (OSError, zipfile.BadZipFile):
        return "remove-and-stub", "office-parser-unavailable"
    return ("strip-metadata", "office-metadata") if metadata else (None, "office-package")


def _font_inspection(path: Path, policy: dict) -> tuple[str | None, str]:
    try:
        from fontTools.ttLib import TTFont

        font = TTFont(path, lazy=False)
        try:
            values = []
            if "name" in font:
                for record in font["name"].names:
                    try:
                        values.append(record.toUnicode())
                    except Exception:
                        continue
            if _contains_private_text("\n".join(values), policy, path.name):
                return "remove-and-stub", "font-private-metadata"
        finally:
            font.close()
    except Exception:
        return "remove-and-stub", "font-parser-unavailable"
    return None, "font-tables-metadata"


def _binary_strings_private(data: bytes, policy: dict, display_path: str) -> bool:
    strings = []
    for match in re.finditer(rb"[\x20-\x7e]{6,}", data):
        strings.append(match.group(0).decode("ascii", errors="ignore"))
        if len(strings) >= 10000:
            break
    return _contains_private_text("\n".join(strings), policy, display_path)


def iter_candidate_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if ".git" in path.parts or not (path.is_file() or path.is_symlink()):
            continue
        yield path


def inspect_tree_detailed(
    root: Path,
    policy: dict,
    *,
    inherited_source: Path | None = None,
    source_receipt: dict | None = None,
) -> tuple[list[SourceFinding], list[PublicObservation], list[dict]]:
    findings: list[SourceFinding] = []
    observations: list[PublicObservation] = []
    coverage: list[dict] = []
    source_digests: dict[str, str] = {}
    inspecting_bound_source = (
        source_receipt is not None
        and inherited_source is not None
        and root.resolve() == inherited_source.resolve()
    )
    if source_receipt is not None and inherited_source is not None and not inspecting_bound_source:
        source_digests = committed_blob_sha256s(inherited_source, str(source_receipt["source_commit"]))
    mapping_by_entity = {item.get("entity_id"): item.get("replacement") for item in policy["synthetic_mappings"]}
    maximum_bytes = int(policy["security_runtime"].get("maximum_object_bytes", 25 * 1024 * 1024))
    for path in iter_candidate_files(root):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = path.readlink().as_posix().encode("utf-8", errors="surrogateescape")
            findings.append(_finding("artifact.symlink", "unsupported-artifact", relative, target, "remove-and-stub"))
            coverage.append({"path": relative, "status": "checked", "parser": "symlink-policy", "sha256": hashlib.sha256(target).hexdigest()})
            continue
        if path.stat().st_size > maximum_bytes:
            digest = _stream_sha256(path)
            findings.append(_finding_from_digest("artifact.oversized", "unsupported-artifact", relative, digest, "remove-and-stub"))
            coverage.append({"path": relative, "status": "checked", "parser": "bounded-size-policy", "sha256": digest})
            continue
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        suffix = path.suffix.lower()
        source_match = inspecting_bound_source or source_digests.get(relative) == digest
        if path.name.lower() in LEGAL_FILENAMES:
            try:
                legal_text = data.decode("utf-8")
            except UnicodeDecodeError:
                legal_text = ""
            if legal_text and _contains_private_text(legal_text, policy):
                findings.append(_finding("legal.protected-content", "legal", relative, data, "needs-owner-decision"))
            else:
                observations.append(PublicObservation("public.legal-record", relative, "Legal record retained without automatic rewriting"))
            coverage.append({"path": relative, "status": "checked", "parser": "legal-text", "sha256": digest})
            continue
        if path.name == ".gitmodules":
            findings.append(_finding("artifact.submodule", "unsupported-artifact", relative, data, "remove-and-stub"))
            coverage.append({"path": relative, "status": "checked", "parser": "gitmodules", "sha256": digest})
            continue
        if suffix in DATABASE_EXTENSIONS:
            if source_match:
                observations.append(PublicObservation("public.retained-audited-database", relative, "Exact database fixture retained under a complete source-audit receipt"))
                coverage.append({"path": relative, "status": "checked", "parser": "bound-source-audit-receipt", "sha256": digest})
                continue
            if _sqlite_requires_synthesis(path, policy):
                findings.append(_finding("data.sqlite", "real-data", relative, data, "synthesize"))
            coverage.append({"path": relative, "status": "checked", "parser": "sqlite-read-only", "sha256": digest})
            continue
        if any(relative.lower().endswith(item) for item in DATABASE_SIDECAR_SUFFIXES):
            if source_match:
                observations.append(PublicObservation("public.retained-audited-database-sidecar", relative, "Exact database sidecar retained under a complete source-audit receipt"))
                coverage.append({"path": relative, "status": "checked", "parser": "bound-source-audit-receipt", "sha256": digest})
                continue
            findings.append(_finding("data.sqlite-sidecar", "real-data", relative, data, "synthesize"))
            coverage.append({"path": relative, "status": "checked", "parser": "sqlite-sidecar-policy", "sha256": digest})
            continue
        if suffix == ".ipynb":
            if _notebook_requires_sanitization(data, policy):
                findings.append(_finding("data.notebook", "real-data", relative, data, "regenerate"))
            coverage.append({"path": relative, "status": "checked", "parser": "notebook-json", "sha256": digest})
            continue
        deep_extensions = IMAGE_EXTENSIONS | ARCHIVE_EXTENSIONS | {".pdf"} | OFFICE_EXTENSIONS | FONT_EXTENSIONS | MEDIA_EXTENSIONS | REMOVABLE_ARTIFACT_EXTENSIONS | {".wasm"}
        if source_match and suffix in deep_extensions:
            observations.append(PublicObservation("public.retained-audited-object", relative, "Unchanged object retained under an exact complete source-audit receipt"))
            coverage.append({"path": relative, "status": "checked", "parser": "bound-source-audit-receipt", "sha256": digest})
            continue
        if suffix in ARCHIVE_EXTENSIONS:
            archive_action = _zip_remediation(path, policy)
            if archive_action:
                findings.append(_finding("artifact.archive", "unsupported-artifact", relative, data, archive_action))
            coverage.append({"path": relative, "status": "checked", "parser": "bounded-zip", "sha256": digest})
            continue
        if suffix in IMAGE_EXTENSIONS:
            action, parser = _image_inspection(data, policy, relative)
            if action:
                rule = "artifact.image-private-pixels" if action == "redact-pixels" else "artifact.image-sanitization"
                findings.append(_finding(rule, "unsupported-artifact", relative, data, action))
            coverage.append({"path": relative, "status": "checked", "parser": parser, "sha256": digest})
            continue
        if suffix == ".pdf":
            action, parser = _pdf_inspection(data, policy, relative)
            if action:
                findings.append(_finding("artifact.pdf-sanitization", "unsupported-artifact", relative, data, action))
            coverage.append({"path": relative, "status": "checked", "parser": parser, "sha256": digest})
            continue
        if suffix in OFFICE_EXTENSIONS:
            action, parser = _office_inspection(path, policy)
            if action:
                findings.append(_finding("artifact.office-sanitization", "unsupported-artifact", relative, data, action))
            coverage.append({"path": relative, "status": "checked", "parser": parser, "sha256": digest})
            continue
        if suffix in FONT_EXTENSIONS:
            action, parser = _font_inspection(path, policy)
            if action:
                findings.append(_finding("artifact.font-sanitization", "unsupported-artifact", relative, data, action))
            coverage.append({"path": relative, "status": "checked", "parser": parser, "sha256": digest})
            continue
        if suffix == ".wasm":
            if _binary_strings_private(data, policy, relative):
                findings.append(_finding("artifact.wasm-private-text", "unsupported-artifact", relative, data, "remove-and-stub"))
            coverage.append({"path": relative, "status": "checked", "parser": "wasm-printable-sections", "sha256": digest})
            continue
        if suffix in MEDIA_EXTENSIONS:
            findings.append(_finding("artifact.media-sanitization", "unsupported-artifact", relative, data, "remove-and-stub"))
            coverage.append({"path": relative, "status": "checked", "parser": "media-remove-policy", "sha256": digest})
            continue
        if suffix in REMOVABLE_ARTIFACT_EXTENSIONS:
            findings.append(_finding("artifact.unsupported", "unsupported-artifact", relative, data, "remove-and-stub"))
            coverage.append({"path": relative, "status": "checked", "parser": "unsupported-format-policy", "sha256": digest})
            continue
        if path.name == ".env" or relative.endswith("/.env"):
            findings.append(_finding("path.private-env", "credential", relative, data, "externalize"))
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            if source_match:
                observations.append(PublicObservation("public.retained-audited-object", relative, "Unchanged object retained under an exact complete source-audit receipt"))
                coverage.append({"path": relative, "status": "checked", "parser": "bound-source-audit-receipt", "sha256": digest})
                continue
            rule = "artifact.undecodable" if suffix in TEXT_EXTENSIONS else "artifact.opaque"
            findings.append(_finding(rule, "unsupported-artifact", relative, data, "remove-and-stub"))
            coverage.append({"path": relative, "status": "checked", "parser": "text-or-opaque-policy", "sha256": digest})
            continue
        if LFS_POINTER.search(text):
            findings.append(_finding("artifact.lfs-pointer", "unsupported-artifact", relative, data, "remove-and-stub"))
            coverage.append({"path": relative, "status": "checked", "parser": "git-lfs-pointer", "sha256": digest})
            continue
        credential_matches = _active_credential_matches(text, relative)
        if credential_matches:
            translation_catalog = suffix == ".json" and _looks_like_translation_catalog(text)
            if source_match and (translation_catalog or not any(_high_confidence_credential(match) for match in credential_matches)):
                observations.append(PublicObservation("public.audited-ambiguous-assignment", relative, "Ambiguous assignment retained under an exact complete source-audit receipt; Gitleaks remains mandatory at certification"))
            else:
                findings.append(_finding("credential.assignment", "credential", relative, data, "externalize"))
        if PRIVATE_IPV4.search(text):
            if source_match:
                observations.append(PublicObservation("public.audited-private-range-example", relative, "Private-range example retained under an exact complete source-audit receipt"))
            else:
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
        coverage.append({"path": relative, "status": "checked", "parser": "utf8-text", "sha256": digest})
    return findings, observations, coverage


def inspect_tree(root: Path, policy: dict) -> tuple[list[SourceFinding], list[PublicObservation]]:
    findings, observations, _ = inspect_tree_detailed(root, policy)
    return findings, observations
