from __future__ import annotations

import json
from pathlib import Path
import posixpath
import re
import shutil

from .detectors import PRIVATE_IPV4, TEXT_EXTENSIONS
from .artifacts import transform_artifact
from .model import RemediationAction


CREDENTIAL_NAME = re.compile(r"(?i)^(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|cookie|session)$")
TEXT_FILENAMES = {"dockerfile", "gemfile", "makefile", "procfile"}


def _scrub_json_credentials(value):
    if isinstance(value, dict):
        return {
            key: "<REQUIRED_AT_RUNTIME>" if CREDENTIAL_NAME.fullmatch(str(key)) and isinstance(item, str) else _scrub_json_credentials(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_scrub_json_credentials(item) for item in value]
    return value


def _externalize_credentials(path: Path, text: str) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            return text
        updated = json.dumps(_scrub_json_credentials(document), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        return updated if updated != text else text
    python_assignment = re.compile(
        r"(?im)^(?P<indent>[ \t]*)(?P<name>password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|cookie|session)[ \t]*=[ \t]*(?P<quote>['\"])[^'\"\r\n]{8,}(?P=quote)(?P<tail>[ \t]*(?:#.*)?)$"
    )
    script_assignment = re.compile(
        r"(?im)^(?P<indent>[ \t]*)(?P<prefix>(?:const|let|var)[ \t]+)(?P<name>password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|cookie|session)[ \t]*=[ \t]*(?P<quote>['\"])[^'\"\r\n]{8,}(?P=quote)(?P<tail>[ \t]*;?[ \t]*)$"
    )
    config_assignment = re.compile(
        r"(?im)^(?P<indent>[ \t]*)(?P<name>password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|cookie|session)(?P<separator>[ \t]*[:=][ \t]*)(?P<value>[^\r\n#]{8,})(?P<tail>[ \t]*(?:#.*)?)$"
    )
    if suffix == ".py":
        def replace_python(match: re.Match[str]) -> str:
            name = match.group("name")
            variable = name.upper().replace("-", "_")
            return f'{match.group("indent")}{name} = os.environ.get("{variable}", "<REQUIRED_AT_RUNTIME>"){match.group("tail")}'

        updated = python_assignment.sub(replace_python, text)
        if updated != text and not re.search(r"(?m)^import os(?:\s|$)", updated):
            updated = "import os\n" + updated
        return updated
    if suffix in {".js", ".jsx", ".mjs", ".ts", ".tsx"}:
        return script_assignment.sub(
            lambda match: f'{match.group("indent")}{match.group("prefix")}{match.group("name")} = process.env.{match.group("name").upper().replace("-", "_")}{match.group("tail")}',
            text,
        )
    return config_assignment.sub(
        lambda match: f'{match.group("indent")}{match.group("name")}{match.group("separator")}${{{match.group("name").upper().replace("-", "_")}}}{match.group("tail")}',
        text,
    )


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


def _next_public_stub(root: Path) -> Path:
    directory = root / "docs" / "safe-publish"
    directory.mkdir(parents=True, exist_ok=True)
    for index in range(1, 100_000):
        candidate = directory / f"removed-object-{index:03d}.md"
        if not candidate.exists():
            return candidate
    raise RuntimeError("The public removal-stub namespace is exhausted")


def _write_public_stub(root: Path) -> Path:
    stub = _next_public_stub(root)
    stub.write_text(
        "# Removed optional object\n\n"
        "The source object was excluded because the public candidate could not prove that it was safe to retain\n",
        encoding="utf-8",
    )
    return stub


def _replace_reference_token(text: str, old: str, new: str) -> str:
    if not old or old == ".":
        return text
    boundary = r"A-Za-z0-9_./\\~-"
    pattern = re.compile(rf"(?<![{boundary}]){re.escape(old)}(?![{boundary}])")
    return pattern.sub(lambda _: new, text)


def _reference_variants(old: str, new: str, document: Path, root: Path) -> list[tuple[str, str]]:
    old = old.replace("\\", "/")
    new = new.replace("\\", "/")
    parent = document.parent.relative_to(root).as_posix()
    parent = "." if parent == "." else parent
    relative_old = posixpath.relpath(old, parent)
    relative_new = posixpath.relpath(new, parent)
    variants = [(old, new), (relative_old, relative_new)]
    if not relative_old.startswith("."):
        variants.append((f"./{relative_old}", f"./{relative_new}"))
    old_suffix = Path(old).suffix
    new_suffix = Path(new).suffix
    if old_suffix and old_suffix == new_suffix:
        variants.extend(
            (
                (old.removesuffix(old_suffix), new.removesuffix(new_suffix)),
                (relative_old.removesuffix(old_suffix), relative_new.removesuffix(new_suffix)),
            )
        )
    return list(dict.fromkeys(variants))


def _repair_python_imports(text: str, old: str, new: str) -> str:
    if not old.endswith(".py") or not new.endswith(".py"):
        return text
    old_module = old.removesuffix(".py").replace("/", ".")
    new_module = new.removesuffix(".py").replace("/", ".")
    text = re.sub(
        rf"(?m)^(?P<prefix>[ \t]*from[ \t]+){re.escape(old_module)}(?P<suffix>[ \t]+import[ \t]+)",
        rf"\g<prefix>{new_module}\g<suffix>",
        text,
    )
    return re.sub(
        rf"(?m)^(?P<prefix>[ \t]*import[ \t]+){re.escape(old_module)}(?P<suffix>(?:[ \t]+as[ \t]+[A-Za-z_][A-Za-z0-9_]*)?[ \t]*(?:#.*)?)$",
        rf"\g<prefix>{new_module}\g<suffix>",
        text,
    )


def _repair_references(root: Path, renames: list[tuple[str, str]]) -> list[str]:
    changed: list[str] = []
    for document in sorted(root.rglob("*")):
        if not document.is_file() or ".git" in document.parts:
            continue
        if document.suffix.lower() not in TEXT_EXTENSIONS and document.name.lower() not in TEXT_FILENAMES:
            continue
        try:
            original = document.read_text(encoding="utf-8", errors="strict")
        except UnicodeError:
            continue
        updated = original
        for old, new in renames:
            if document.suffix.lower() == ".py":
                updated = _repair_python_imports(updated, old, new)
            for old_reference, new_reference in _reference_variants(old, new, document, root):
                updated = _replace_reference_token(updated, old_reference, new_reference)
        if updated != original:
            document.write_text(updated, encoding="utf-8")
            changed.append(document.relative_to(root).as_posix())
    return changed


def _write_public_change_summary(root: Path, transformations: list[dict]) -> None:
    counts: dict[str, int] = {}
    for transformation in transformations:
        action = str(transformation["action"])
        counts[action] = counts.get(action, 0) + 1
    report = root / "PUBLICATION_CHANGES.json"
    report.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "summary": [{"action": action, "count": counts[action]} for action in sorted(counts)],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


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
            if any(action.action in {"remove", "remove-and-stub", "exclude-component"} for action in path_actions):
                stub = _write_public_stub(root)
                transformations.append({"action": "remove-and-stub", "path": relative, "replacement": stub.relative_to(root).as_posix()})
                removed.append(relative)
            continue
        artifact_action = next((action.action for action in path_actions if action.action in {"synthesize", "regenerate", "repack", "strip-metadata", "redact-pixels", "rebuild"}), None)
        if artifact_action and transform_artifact(path, artifact_action, policy):
            transformations.append({"action": artifact_action, "path": relative})
            if not path.exists():
                removed.append(relative)
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
                stub = _write_public_stub(root)
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
    renames: list[tuple[str, str]] = []
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
            if target.exists():
                raise ValueError("A rename target already exists in the candidate")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), str(target))
            renames.append((relative.replace("\\", "/"), rule["target"].replace("\\", "/")))
            transformations.append({"action": "rename", "path": relative, "replacement": rule["target"]})
    for repaired in _repair_references(root, renames):
        transformations.append({"action": "repair-reference", "path": repaired})
    if transformations:
        _write_public_change_summary(root, transformations)
    return transformations, removed
