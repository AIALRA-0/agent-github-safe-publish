from __future__ import annotations

import hashlib
import json
from pathlib import Path
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
    if policy["publication"].get("mode") not in {"new-publication", "update-existing-public", "history-migration"}:
        raise ValueError("Unsupported publication mode")
    for entity in policy["sensitive_entities"]:
        if not {"id", "kind", "value", "category"}.issubset(entity):
            raise ValueError("Sensitive entity is incomplete")
        if entity["kind"] not in {"literal", "regex"}:
            raise ValueError("Sensitive entity kind is unsupported")
    return policy


def load_policy(path: Path) -> dict[str, Any]:
    return validate_policy(json.loads(path.read_text(encoding="utf-8")))


def policy_sha256(policy: dict[str, Any]) -> str:
    encoded = json.dumps(policy, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
