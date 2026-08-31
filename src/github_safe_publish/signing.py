from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .model import SafetyCertification


def _payload(certification: SafetyCertification) -> bytes:
    document = asdict(certification)
    document["signature"] = None
    document["public_key"] = None
    document["public_key_fingerprint"] = None
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_or_create_private_key(path: Path) -> Ed25519PrivateKey:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raw = base64.b64decode(path.read_text(encoding="ascii"))
        return Ed25519PrivateKey.from_private_bytes(raw)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    path.write_text(base64.b64encode(raw).decode("ascii") + "\n", encoding="ascii")
    os.chmod(path, 0o600)
    return key


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
