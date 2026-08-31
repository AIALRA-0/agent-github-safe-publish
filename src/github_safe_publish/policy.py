from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any


REQUIRED_V4_FIELDS = {
    "publication",
    "sensitive_entities",
    "synthetic_mappings",
    "remediation_defaults",
    "object_rules",
    "retention_rules",
    "history_strategy",
    "functional_contract",
    "degradation_policy",
    "validation",
    "security_runtime",
    "remote_target",
}


DEFAULT_REMEDIATION = {
    "credential": "externalize",
    "private-identity": "replace",
    "private-infrastructure": "parameterize",
    "real-data": "synthesize",
    "unsupported-artifact": "remove-and-stub",
    "unknown-provenance": "exclude-component",
}


def _private_regex_is_bounded(expression: str) -> bool:
    if len(expression) > 512 or "\x00" in expression:
        return False
    index = 0
    in_class = False
    while index < len(expression):
        character = expression[index]
        if character == "\\":
            index += 2
            continue
        if character == "[":
            if in_class:
                return False
            in_class = True
            index += 1
            continue
        if character == "]":
            if not in_class:
                return False
            in_class = False
            index += 1
            continue
        if in_class:
            index += 1
            continue
        if character in "*+?()":
            return False
        if character == "{":
            closing = expression.find("}", index + 1)
            if closing < 0:
                return False
            match = re.fullmatch(r"(\d+)(?:,(\d+))?", expression[index + 1:closing])
            if not match:
                return False
            lower = int(match.group(1))
            upper = int(match.group(2) or lower)
            if upper < lower or upper > 64:
                return False
            index = closing + 1
            continue
        if character == "}":
            return False
        index += 1
    return not in_class


def _exact_repository_path(value: object) -> bool:
    if not isinstance(value, str) or not value or "\\" in value or any(character in value for character in "*?[]"):
        return False
    path = Path(value)
    return not path.is_absolute() and value not in {".", ".."} and ".." not in path.parts


def default_policy() -> dict[str, Any]:
    return {
        "schema_version": 4,
        "publication": {"mode": "new-publication"},
        "sensitive_entities": [],
        "synthetic_mappings": [],
        "remediation_defaults": dict(DEFAULT_REMEDIATION),
        "object_rules": [],
        "retention_rules": [],
        "history_strategy": {"mode": "new-root"},
        "functional_contract": {"commands": []},
        "degradation_policy": {"maximum_automatic": "minor", "optional_paths": []},
        "validation": {"timeout_seconds": 900},
        "security_runtime": {"network": "disabled", "container_required": False, "maximum_object_bytes": 26214400},
        "remote_target": {"repository": "", "branch": "main", "expected_base": None},
    }


def migrate_policy(document: dict[str, Any]) -> dict[str, Any]:
    version = document.get("schema_version")
    if version == 4:
        return json.loads(json.dumps(document))
    if version not in {1, 2, 3}:
        raise ValueError("Unknown policy schema version")
    migrated = default_policy()
    migrated["sensitive_entities"] = [
        {
            "id": item.get("id", f"legacy-{index}"),
            "kind": item.get("kind", "literal"),
            "value": item.get("value", ""),
            "category": "private-identity",
        }
        for index, item in enumerate(document.get("identifiers", []), 1)
    ]
    migrated["synthetic_mappings"] = [
        {"entity_id": item.get("rule_id", item.get("id", "legacy")), "replacement": item.get("replacement", "ExampleValue")}
        for item in document.get("replacements", [])
    ]
    migrated["object_rules"] = [
        {"path": path, "action": "remove"} for path in document.get("blocked_paths", [])
    ]
    migrated["retention_rules"] = [
        {"rule_id": item.get("rule_id"), "object": item.get("object"), "legacy_review_only": True}
        for item in document.get("approved_locations", [])
    ]
    return migrated


def validate_policy(document: dict[str, Any]) -> dict[str, Any]:
    policy = migrate_policy(document)
    missing = REQUIRED_V4_FIELDS.difference(policy)
    if missing:
        raise ValueError("Policy v4 is missing required fields")
    if policy.get("schema_version") != 4:
        raise ValueError("Policy migration did not produce version 4")
    maximum = policy["degradation_policy"].get("maximum_automatic", "minor")
    if maximum not in {"none", "minor"}:
        raise ValueError("Automatic degradation may be only none or minor")
    publication_mode = policy["publication"].get("mode")
    if publication_mode not in {"new-publication", "update-existing-public", "history-migration"}:
        raise ValueError("Unsupported publication mode")
    expected_history = {
        "new-publication": "new-root",
        "update-existing-public": "public-base-overlay",
        "history-migration": "full-migration",
    }[publication_mode]
    if policy["history_strategy"].get("mode") != expected_history:
        raise ValueError("History strategy differs from the publication mode")
    if publication_mode == "update-existing-public":
        if not policy["publication"].get("public_base") or not policy["remote_target"].get("expected_base"):
            raise ValueError("Existing-public mode requires a public base and expected remote base")
    for path in policy["degradation_policy"].get("optional_paths", []):
        if not _exact_repository_path(path):
            raise ValueError("Optional paths must be exact repository-relative paths")
    for rule in policy["object_rules"]:
        if not isinstance(rule, dict) or rule.get("action") not in {"remove", "rename"} or not _exact_repository_path(rule.get("path")):
            raise ValueError("Object rules must name one supported exact repository-relative path")
        if rule["action"] == "rename" and not _exact_repository_path(rule.get("target")):
            raise ValueError("Rename targets must be exact repository-relative paths")
    for entity in policy["sensitive_entities"]:
        if not {"id", "kind", "value", "category"}.issubset(entity):
            raise ValueError("Sensitive entity is incomplete")
        if entity["kind"] not in {"literal", "regex"}:
            raise ValueError("Sensitive entity kind is unsupported")
        if not isinstance(entity["value"], str) or not entity["value"]:
            raise ValueError("Sensitive entity value must be a non-empty string")
        if entity["kind"] == "regex":
            if not _private_regex_is_bounded(entity["value"]):
                raise ValueError("Sensitive entity regex is not bounded")
            try:
                re.compile(entity["value"])
            except re.error as exc:
                raise ValueError("Sensitive entity regex is invalid") from exc
    document_without_retention = json.loads(json.dumps(policy))
    document_without_retention["retention_rules"] = []
    retention_binding = policy_sha256(document_without_retention)
    required_retention = {
        "action", "object", "sha256", "scanner_ids", "tool_version", "policy_sha256",
        "issued_by", "issued_at", "expires_at", "review_trigger",
    }
    for rule in policy["retention_rules"]:
        if rule.get("legacy_review_only"):
            continue
        if not required_retention.issubset(rule) or rule.get("action") != "retain-public":
            raise ValueError("Retention evidence is incomplete")
        if not _exact_repository_path(rule["object"]):
            raise ValueError("Retention evidence must name one exact object")
        if not re.fullmatch(r"[0-9a-f]{64}", str(rule["sha256"])):
            raise ValueError("Retention object digest is invalid")
        if not isinstance(rule["scanner_ids"], list) or not rule["scanner_ids"]:
            raise ValueError("Retention evidence requires the scanner set")
        if rule["policy_sha256"] != retention_binding:
            raise ValueError("Retention evidence targets another policy")
        try:
            expires_at = datetime.fromisoformat(str(rule["expires_at"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Retention evidence expiration is invalid") from exc
        if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
            raise ValueError("Retention evidence has expired")
        if rule["review_trigger"] != "content-policy-scanner-or-expiry-change":
            raise ValueError("Retention evidence review trigger is invalid")
    scanner = policy["security_runtime"].get("credential_scanner")
    if scanner is not None:
        if not isinstance(scanner, dict) or not {"path", "sha256", "version"}.issubset(scanner):
            raise ValueError("Credential scanner binding is incomplete")
        if scanner["version"] != "8.30.1" or not re.fullmatch(r"[0-9a-f]{64}", str(scanner["sha256"])):
            raise ValueError("Credential scanner binding is invalid")
    return policy


def load_policy(path: Path, source: Path | None = None) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if source is not None:
        try:
            resolved.relative_to(source.expanduser().resolve())
        except ValueError:
            pass
        else:
            raise ValueError("Private policy cannot be loaded from inside the source repository")
    if resolved.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Private policy exceeds the bounded size limit")
    return validate_policy(json.loads(resolved.read_text(encoding="utf-8")))


def policy_sha256(policy: dict[str, Any]) -> str:
    encoded = json.dumps(policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
