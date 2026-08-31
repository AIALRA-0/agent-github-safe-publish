from __future__ import annotations

import json
from pathlib import Path
import re
import shutil

from .detectors import CREDENTIAL_ASSIGNMENT, PRIVATE_IPV4
from .artifacts import transform_artifact
from .model import RemediationAction


def _credential_replacement(path: Path, name: str) -> str:
    normalized = name.upper().replace("-", "_")
    suffix = path.suffix.lower()
    if suffix == ".py":
        return f'{name} = os.environ.get("{normalized}", "<REQUIRED_AT_RUNTIME>")'
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        return f"{name} = process.env.{normalized}"
    return f'{name}=${{{normalized}}}'


def _externalize_credentials(path: Path, text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return _credential_replacement(path, match.group(1))

    updated = CREDENTIAL_ASSIGNMENT.sub(replace, text)
    if path.suffix.lower() == ".py" and updated != text and "import os" not in updated:
        updated = "import os\n" + updated
    return updated


def _remove_lfs_rule(root: Path, relative: str) -> bool:
    attributes = root / ".gitattributes"
    if not attributes.is_file():
        return False
    original = attributes.read_text(encoding="utf-8", errors="strict")
    normalized = relative.replace("\\", "/")
    kept = []
    for line in original.splitlines():
        stripped = line.strip()
        if "filter=lfs" in stripped and stripped.split(maxsplit=1)[0] in {normalized, Path(normalized).name}:
            continue
        kept.append(line)
    updated = "\n".join(kept) + ("\n" if kept else "")
    if updated == original:
        return False
    attributes.write_text(updated, encoding="utf-8")
    return True


def transform_candidate(root: Path, actions: list[RemediationAction], policy: dict) -> tuple[list[dict], list[str]]:
    by_path: dict[str, list[RemediationAction]] = {}
    for action in actions:
        by_path.setdefault(action.object_path, []).append(action)
    transformations: list[dict] = []
    removed: list[str] = []
    mapped_values = {item.get("entity_id"): item.get("replacement", "ExampleValue") for item in policy["synthetic_mappings"]}
    for relative, path_actions in sorted(by_path.items()):
        path = root / relative
        if not path.exists():
            continue
        artifact_action = next((action.action for action in path_actions if action.action in {"synthesize", "regenerate", "repack"}), None)
        if artifact_action and transform_artifact(path, artifact_action, policy):
            transformations.append({"action": artifact_action, "path": relative})
            continue
        remove_object = any(action.action in {"remove", "remove-and-stub", "exclude-component"} for action in path_actions)
        externalize_env = path.name == ".env" and any(action.action == "externalize" for action in path_actions)
        if remove_object or externalize_env:
            if path.name == ".env":
                example = path.with_name(".env.example")
                lines = []
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    name = line.split("=", 1)[0].strip()
                    if name and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                        lines.append(f"{name}=<REQUIRED_AT_RUNTIME>")
                example.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
                transformations.append({"action": "externalize", "path": relative, "replacement": example.relative_to(root).as_posix()})
            else:
                stub = path.with_suffix(path.suffix + ".removed.md")
                stub.write_text("This optional private artifact was removed from the public candidate\n", encoding="utf-8")
                transformations.append({"action": "remove-and-stub", "path": relative, "replacement": stub.relative_to(root).as_posix()})
            path.unlink()
            if any(action.finding_id and action.action in {"remove", "remove-and-stub"} for action in path_actions) and _remove_lfs_rule(root, relative):
                transformations.append({"action": "remove-lfs-rule", "path": ".gitattributes", "replacement": relative})
            removed.append(relative)
            continue
        text = path.read_text(encoding="utf-8", errors="strict")
        updated = text
        for action in path_actions:
            if action.action == "externalize":
                updated = _externalize_credentials(path, updated)
            elif action.action == "parameterize":
                updated = PRIVATE_IPV4.sub("192.0.2.10", updated)
            elif action.action in {"replace", "synthesize"}:
                for entity in policy["sensitive_entities"]:
                    replacement = mapped_values.get(entity["id"], action.replacement or "ExampleValue")
                    if entity["kind"] == "literal":
                        updated = updated.replace(entity["value"], replacement)
                    else:
                        updated = re.sub(entity["value"], replacement, updated)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            transformations.append({"action": "transform-text", "path": relative})
    for rule in policy["object_rules"]:
        relative = rule.get("path")
        if not relative or any(token in relative for token in "*?[]"):
            continue
        path = root / relative
        if rule.get("action") == "remove" and path.exists() and path.is_file():
            path.unlink()
            removed.append(relative)
            transformations.append({"action": "remove", "path": relative})
        elif rule.get("action") == "rename" and path.exists():
            target = root / rule["target"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), str(target))
            transformations.append({"action": "rename", "path": relative, "replacement": rule["target"]})
    if transformations:
        report = root / "PUBLICATION_CHANGES.json"
        report.write_text(json.dumps({"transformations": transformations}, indent=2) + "\n", encoding="utf-8")
    return transformations, removed
