from __future__ import annotations

import csv
import io
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import zipfile

from .detectors import CREDENTIAL_ASSIGNMENT, PRIVATE_IPV4, TEXT_EXTENSIONS


def synthesize_sqlite(path: Path) -> None:
    source = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        statements = [
            row[0]
            for row in source.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND type IN ('table','index','view') AND name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, name"
            )
            if row[0]
        ]
    finally:
        source.close()
    replacement = path.with_suffix(path.suffix + ".synthetic")
    connection = sqlite3.connect(replacement)
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()
    replacement.replace(path)


def _replace_private_text(text: str, policy: dict) -> str:
    mappings = {item.get("entity_id"): item.get("replacement", "ExampleValue") for item in policy["synthetic_mappings"]}
    updated = PRIVATE_IPV4.sub("192.0.2.10", text)
    for entity in policy["sensitive_entities"]:
        replacement = mappings.get(entity["id"], "ExampleValue")
        updated = updated.replace(entity["value"], replacement) if entity["kind"] == "literal" else re.sub(entity["value"], replacement, updated)
    updated = CREDENTIAL_ASSIGNMENT.sub(lambda match: f'{match.group(1)}=<REQUIRED_AT_RUNTIME>', updated)
    return updated


def sanitize_notebook(path: Path, policy: dict) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    for cell in document.get("cells", []):
        cell["outputs"] = []
        cell["execution_count"] = None
        source = cell.get("source", [])
        if isinstance(source, list):
            cell["source"] = [_replace_private_text(str(line), policy) for line in source]
        elif isinstance(source, str):
            cell["source"] = _replace_private_text(source, policy)
    document["metadata"] = {}
    path.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=1) + "\n", encoding="utf-8")


def sanitize_csv(path: Path) -> None:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader, [])
    with path.open("w", encoding="utf-8", newline="") as handle:
        if header:
            csv.writer(handle).writerow(header)


def sanitize_zip(path: Path, policy: dict) -> None:
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > 10000:
            raise ValueError("Archive member limit exceeded")
        output: list[tuple[str, bytes]] = []
        total = 0
        for member in members:
            normalized = Path(member.filename)
            if normalized.is_absolute() or ".." in normalized.parts or member.is_dir():
                if member.is_dir():
                    continue
                raise ValueError("Archive contains an unsafe path")
            data = archive.read(member)
            total += len(data)
            if total > 512 * 1024 * 1024:
                raise ValueError("Archive expansion limit exceeded")
            suffix = normalized.suffix.lower()
            if suffix in TEXT_EXTENSIONS or not suffix:
                try:
                    data = _replace_private_text(data.decode("utf-8"), policy).encode("utf-8")
                except UnicodeDecodeError:
                    continue
            else:
                continue
            output.append((normalized.as_posix(), data))
    temporary = path.with_suffix(path.suffix + ".sanitized")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(output):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, data)
    temporary.replace(path)


def transform_artifact(path: Path, action: str, policy: dict) -> bool:
    suffix = path.suffix.lower()
    if suffix in {".db", ".sqlite", ".sqlite3"} and action == "synthesize":
        synthesize_sqlite(path)
        return True
    if suffix == ".ipynb" and action == "regenerate":
        sanitize_notebook(path, policy)
        return True
    if suffix == ".zip" and action == "repack":
        sanitize_zip(path, policy)
        return True
    if suffix == ".csv" and action == "synthesize":
        sanitize_csv(path)
        return True
    return False
