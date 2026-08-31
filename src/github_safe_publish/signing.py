from __future__ import annotations

import base64
from dataclasses import asdict
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .model import SafetyCertification


DPAPI_PREFIX = "dpapi-v1:"


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _dpapi_transform(data: bytes, *, protect: bool) -> bytes:
    """Protect key material for the current Windows user without exposing it to a subprocess."""
    if os.name != "nt":
        return data
    source = ctypes.create_string_buffer(data)
    source_blob = _DataBlob(len(data), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
    output_blob = _DataBlob()
    if protect:
        ok = ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(source_blob),
            "github-safe-publish",
            None,
            None,
            None,
            0x01,
            ctypes.byref(output_blob),
        )
    else:
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(source_blob),
            None,
            None,
            None,
            None,
            0x01,
            ctypes.byref(output_blob),
        )
    if not ok:
        raise OSError("Windows data protection could not process the certification key")
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output_blob.pbData)


def _encode_private_key(raw: bytes) -> str:
    if os.name == "nt":
        return DPAPI_PREFIX + base64.b64encode(_dpapi_transform(raw, protect=True)).decode("ascii") + "\n"
    return base64.b64encode(raw).decode("ascii") + "\n"


def _decode_private_key(encoded: str) -> tuple[bytes, bool]:
    stripped = encoded.strip()
    if stripped.startswith(DPAPI_PREFIX):
        if os.name != "nt":
            raise OSError("A Windows-protected certification key cannot be opened on this platform")
        return _dpapi_transform(base64.b64decode(stripped[len(DPAPI_PREFIX):], validate=True), protect=False), False
    return base64.b64decode(stripped, validate=True), os.name == "nt"


def _payload(certification: SafetyCertification) -> bytes:
    document = asdict(certification)
    document["signature"] = None
    document["public_key"] = None
    document["public_key_fingerprint"] = None
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_or_create_private_key(path: Path) -> Ed25519PrivateKey:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path.parent, 0o700)
    if path.exists():
        raw, migrate = _decode_private_key(path.read_text(encoding="ascii"))
        key = Ed25519PrivateKey.from_private_bytes(raw)
        if migrate:
            path.write_text(_encode_private_key(raw), encoding="ascii")
            os.chmod(path, 0o600)
        return key
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    path.write_text(_encode_private_key(raw), encoding="ascii")
    os.chmod(path, 0o600)
    return key


def private_key_fingerprint(path: Path) -> str:
    public = load_or_create_private_key(path).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public).hexdigest()


def sign_certification(certification: SafetyCertification, key_path: Path) -> SafetyCertification:
    key = load_or_create_private_key(key_path)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    certification.public_key = base64.b64encode(public).decode("ascii")
    certification.public_key_fingerprint = hashlib.sha256(public).hexdigest()
    certification.signature = base64.b64encode(key.sign(_payload(certification))).decode("ascii")
    return certification


def verify_certification(certification: SafetyCertification, trusted_fingerprint: str | None) -> bool:
    if not trusted_fingerprint:
        return False
    if not certification.signature or not certification.public_key or not certification.public_key_fingerprint:
        return False
    try:
        public = base64.b64decode(certification.public_key)
        if hashlib.sha256(public).hexdigest() != certification.public_key_fingerprint:
            return False
        if certification.public_key_fingerprint != trusted_fingerprint:
            return False
        Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(certification.signature), _payload(certification))
        return True
    except Exception:
        return False
