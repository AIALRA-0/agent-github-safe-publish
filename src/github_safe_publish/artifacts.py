from __future__ import annotations

import csv
import json
from pathlib import Path
import re
import sqlite3
import warnings
import zipfile
import xml.etree.ElementTree as ET

from .detectors import CREDENTIAL_ASSIGNMENT, MAX_IMAGE_FRAMES, MAX_IMAGE_PIXELS, PRIVATE_IPV4, TEXT_EXTENSIONS, _contains_private_text


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
    maximum_member_bytes = int(policy["security_runtime"].get("maximum_object_bytes", 25 * 1024 * 1024))
    temporary = path.with_suffix(path.suffix + ".sanitized")
    with zipfile.ZipFile(path) as archive, zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as destination:
        members = archive.infolist()
        if len(members) > 10000:
            raise ValueError("Archive member limit exceeded")
        total = 0
        for member in sorted(members, key=lambda item: item.filename):
            normalized = Path(member.filename)
            if normalized.is_absolute() or ".." in normalized.parts or member.is_dir():
                if member.is_dir():
                    continue
                raise ValueError("Archive contains an unsafe path")
            if member.file_size > maximum_member_bytes:
                raise ValueError("Archive member size limit exceeded")
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
            info = zipfile.ZipInfo(normalized.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            destination.writestr(info, data)
    temporary.replace(path)


def _save_clean_image(image, path: Path, *, frames=None) -> None:
    image_format = image.format or {
        ".jpg": "JPEG", ".jpeg": "JPEG", ".png": "PNG", ".gif": "GIF", ".webp": "WEBP",
        ".bmp": "BMP", ".tif": "TIFF", ".tiff": "TIFF", ".ico": "ICO", ".icns": "ICNS",
    }.get(path.suffix.lower(), "PNG")
    temporary = path.with_suffix(path.suffix + ".sanitized")
    options = {}
    if frames and len(frames) > 1:
        options.update(save_all=True, append_images=frames[1:], loop=int(image.info.get("loop", 0)), duration=image.info.get("duration", 100))
    frames[0].save(temporary, format=image_format, **options) if frames else image.save(temporary, format=image_format)
    temporary.replace(path)


def strip_image_metadata(path: Path) -> None:
    from PIL import Image, ImageSequence

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(path) as image:
            if image.width * image.height > MAX_IMAGE_PIXELS or getattr(image, "n_frames", 1) > MAX_IMAGE_FRAMES:
                raise ValueError("Image resource limit exceeded")
            image_format = image.format
            frames = [frame.convert("RGBA" if image_format in {"PNG", "WEBP"} else "RGB") for frame in ImageSequence.Iterator(image)]
            frames[0].format = image_format
            _save_clean_image(image, path, frames=frames)


def redact_image_pixels(path: Path, policy: dict) -> None:
    from PIL import Image, ImageDraw, ImageSequence
    import cv2
    import numpy as np
    from rapidocr_onnxruntime import RapidOCR

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(path) as image:
            if image.width * image.height > MAX_IMAGE_PIXELS or getattr(image, "n_frames", 1) > MAX_IMAGE_FRAMES:
                raise ValueError("Image resource limit exceeded")
            image_format = image.format
            frames = [frame.convert("RGB") for frame in ImageSequence.Iterator(image)]
            engine = RapidOCR()
            qr = cv2.QRCodeDetector()
            for frame in frames:
                drawing = ImageDraw.Draw(frame)
                array = np.asarray(frame)
                result, _ = engine(array)
                for item in result or []:
                    if len(item) < 2 or not _contains_private_text(str(item[1]), policy, path.name):
                        continue
                    points = item[0]
                    xs = [float(point[0]) for point in points]
                    ys = [float(point[1]) for point in points]
                    drawing.rectangle((min(xs), min(ys), max(xs), max(ys)), fill="black")
                decoded, points, _ = qr.detectAndDecode(array)
                if decoded and points is not None and _contains_private_text(decoded, policy, path.name):
                    flattened = points.reshape(-1, 2)
                    drawing.polygon([(float(x), float(y)) for x, y in flattened], fill="black")
            frames[0].format = image_format
            _save_clean_image(image, path, frames=frames)


def strip_pdf_metadata(path: Path) -> None:
    import fitz

    temporary = path.with_suffix(path.suffix + ".sanitized")
    with fitz.open(path) as document:
        document.set_metadata({})
        for name in list(document.embfile_names()):
            document.embfile_del(name)
        for page in document:
            annotation = page.first_annot
            while annotation is not None:
                following = annotation.next
                page.delete_annot(annotation)
                annotation = following
        document.save(temporary, garbage=4, clean=True, deflate=True)
    temporary.replace(path)


def strip_office_metadata(path: Path, policy: dict) -> None:
    maximum_member_bytes = int(policy["security_runtime"].get("maximum_object_bytes", 25 * 1024 * 1024))
    temporary = path.with_suffix(path.suffix + ".sanitized")
    with zipfile.ZipFile(path) as source, zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as destination:
        for member in sorted(source.infolist(), key=lambda item: item.filename):
            if member.is_dir():
                continue
            if member.file_size > maximum_member_bytes:
                raise ValueError("Office member size limit exceeded")
            data = source.read(member)
            if member.filename.lower().startswith("docprops/") and member.filename.lower().endswith(".xml"):
                try:
                    root = ET.fromstring(data)
                    for element in root.iter():
                        if len(element) == 0:
                            element.text = None
                    data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
                except ET.ParseError as exc:
                    raise ValueError("Office metadata XML is invalid") from exc
            info = zipfile.ZipInfo(member.filename, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = member.external_attr
            destination.writestr(info, data)
    temporary.replace(path)


def transform_artifact(path: Path, action: str, policy: dict) -> bool:
    suffix = path.suffix.lower()
    lowered = path.name.lower()
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
    if action == "synthesize" and lowered.endswith((".db-shm", ".db-wal", ".sqlite-shm", ".sqlite-wal", ".sqlite3-shm", ".sqlite3-wal")):
        path.unlink()
        return True
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".ico", ".icns"}:
        if action == "strip-metadata":
            strip_image_metadata(path)
            return True
        if action == "redact-pixels":
            redact_image_pixels(path, policy)
            return True
    if suffix == ".pdf" and action == "strip-metadata":
        strip_pdf_metadata(path)
        return True
    if suffix in {".docx", ".xlsx", ".pptx"} and action == "strip-metadata":
        strip_office_metadata(path, policy)
        return True
    return False
