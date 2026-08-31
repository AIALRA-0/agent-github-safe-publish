from __future__ import annotations

import hashlib

from .model import RemediationAction, SourceFinding


def remediation_plan(findings: list[SourceFinding], policy: dict) -> tuple[list[RemediationAction], list[SourceFinding]]:
    actions: list[RemediationAction] = []
    needs_input: list[SourceFinding] = []
    mappings = {item.get("entity_id"): item.get("replacement") for item in policy["synthetic_mappings"]}
    for finding in findings:
        action = finding.remediation_hint or policy["remediation_defaults"].get(finding.category)
        if action in {"needs-owner-decision", None}:
            needs_input.append(finding)
            continue
        replacement = mappings.get(finding.rule_id)
        action_id = hashlib.sha256(f"{finding.finding_id}\0{action}\0{replacement}".encode()).hexdigest()[:24]
        actions.append(RemediationAction(action_id, finding.finding_id, action, finding.object_path, replacement))
    return actions, needs_input
