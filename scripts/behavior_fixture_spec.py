"""Pure, standard-library fixture specifications; no model, Git, network or IO.

Parent integration contract
---------------------------
1. prepare_fixture_spec(scenario) validates explicit preparation data only. It
   never consults requests, required actions, stop labels or expected answers.
2. The parent creates commits for the returned ``required_bindings``, then calls
   bind_fixture_aliases(plan, actual_commits). Alias values are commit OIDs, not
   tag-object OIDs. The parent materializes the returned local/remote ref maps.
3. validate_materialized_fixture(plan, observed) must pass before a model run.
   ``observed`` contains state, local_branches, remote_branches, remote_tags
   (peeled commit OIDs), current_branch and detached. No filesystem is accessed
   here; collecting these facts and checking Git ancestry belongs to the parent.
4. before_operation returns copied state/runtime, execute, result and git_updates.
   Apply/verify Git updates before exposing the state. If execute is true, invoke
   the real controller, catching its failures into a result envelope. Always call
   after_operation, including for reads, failures and skipped operations.
5. Persist the returned state AND runtime before returning the delivered result,
   even on failure or a read. Persist before_operation too if crash recovery is
   needed. An unfinished pending operation must be reconciled, never replayed
   blindly. This module is serial per fixture; parent locking/atomic storage is
   required. An external Git-update failure is an infrastructure failure.

Result envelopes are {status: success|error|timeout, exit_code: int, output: JSON}.
After-hooks preserve the actual backend result separately from delivered output,
so a committed write with a failed response cannot erase the actual write.
``backend_changes`` and fixture ``effects`` have separate attribution. Never
grade an environment-injected ref/rule change as a model write.

Plans, requirements, transition schedules and runtime journals are custodian
data, not agent-visible state. No functions change their arguments. Schema
validation certifies supported declarations, not arbitrary natural-language
premises; the custodian must bind every factual premise to preparation data or
a supported requirement. Legacy records with missing specs fail unchanged.
"""

from __future__ import annotations

from copy import deepcopy
import json
import re
from typing import Any


VERSION = "1"
OPERATIONS = (
    "inspect", "protection-read", "branch-read", "branch-push", "tag-read",
    "tag-create", "release-read", "release-create", "release-update",
    "asset-read", "asset-upload", "pr-read", "pr-create", "pr-update",
    "pr-merge", "metadata-update", "rules-update", "credential-update",
    "remote-delete",
)
PROFILES = (
    "default", "existing_tag", "existing_release", "existing_pull_request",
    "protected_branch", "authorization_revoked", "release_update_failure",
    "dirty_worktree", "detached_head", "shallow_clone",
)
ROLES = ("base", "candidate", "remote_advanced", "remote_candidate")
SPEC_FIELDS = ("fixture_setup", "fixture_state", "fixture_transitions", "fixture_requirements")
_ALIAS = r"^@[A-Za-z][A-Za-z0-9_-]*$"
_NAME = r"^[A-Za-z][A-Za-z0-9_-]*$"
_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_STRING = {"type": "string"}
_BOOL = {"type": "boolean"}
_MISSING = object()


class FixtureSpecError(ValueError):
    """Stable error codes only; never interpolate private values or answers."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(";".join(errors))


def _object(properties: dict, required: tuple | list = ()) -> dict:
    return {"type": "object", "properties": properties,
            "required": list(required), "additionalProperties": False}


def _map(values: dict) -> dict:
    return {"type": "object", "additionalProperties": values}


def _array(items: dict) -> dict:
    return {"type": "array", "items": items}


def _state_schema() -> dict:
    return _object({
        "repository": {"type": "string", "minLength": 1},
        "repository_id": {"type": "string", "minLength": 1},
        "branches": _map({"type": "string", "pattern": _ALIAS}),
        "tags": _map({"type": "string", "pattern": _ALIAS}),
        "releases": _map(_object({
            "tag": _STRING, "title": _STRING, "body": _STRING,
            "draft": _BOOL, "prerelease": _BOOL,
        }, ("tag", "title", "body", "draft", "prerelease"))),
        "assets": _map(_object({
            "size": {"type": "integer", "minimum": 0},
            "sha256": {"type": "string", "pattern": r"^[0-9a-f]{64}$"},
        }, ("size", "sha256"))),
        "pull_requests": _map(_object({
            "title": _STRING, "body": _STRING, "head": _STRING,
            "base": _STRING, "merged": _BOOL,
            "state": {"type": "string", "enum": ["open", "closed"]},
        }, ("title", "body", "head", "base", "merged", "state"))),
        "repository_metadata": _map(_STRING),
        "repository_rules": _object({"requires_pull_request": _BOOL, "admins_enforced": _BOOL}),
        "authorization_revoked": _BOOL,
        "fail_operations": _array({"type": "string", "enum": list(OPERATIONS)}),
    })


def _result_schema() -> dict:
    return _object({
        "status": {"type": "string", "enum": ["success", "error", "timeout"]},
        "exit_code": {"type": "integer", "minimum": 0},
        "output": {},
    }, ("status", "exit_code", "output"))


def fixture_schema_properties() -> dict:
    """Return fresh JSON Schema fields also used by the local validator."""
    setup = {name: _BOOL for name in (
        "detached_head", "local_candidate", "missing_lfs", "private_submodule",
        "remote_advanced", "remote_candidate_branch", "remote_url_changed",
        "shallow", "similar_remotes", "trusted_agents",
    )}
    setup.update({name: _array(_STRING) for name in (
        "dirty_files", "ignored_files", "untracked_files",
    )})
    setup.update({
        "candidate_files": _map(_STRING),
        "commit_aliases": _map({"type": "string", "enum": list(ROLES)}),
        "local_branches": _map({"type": "string", "pattern": _ALIAS}),
        "current_branch": {"type": "string", "minLength": 1},
    })
    path = {"type": "array", "items": {"type": "string", "minLength": 1}, "minItems": 1}
    patch = _object({"path": path, "op": {"type": "string", "enum": ["set", "delete"]}, "value": {}},
                    ("path", "op"))
    trigger = _object({
        "phase": {"type": "string", "enum": ["before", "after"]},
        "operation": {"type": "string", "enum": list(OPERATIONS)},
        "target": {"type": ["string", "null"]},
        "occurrence": {"type": ["integer", "null"], "minimum": 1},
        "when_result": {"type": "string", "enum": ["any", "success", "failure"]},
    }, ("phase", "operation", "target", "occurrence", "when_result"))
    transition = _object({
        "id": {"type": "string", "pattern": _NAME}, "trigger": trigger,
        "once": _BOOL, "changes": _array(patch),
        "result": {"anyOf": [_result_schema(), {"type": "null"}]},
    }, ("id", "trigger", "once", "changes", "result"))
    requirement = _object({
        "at": {"type": "string", "minLength": 1},
        "kind": {"type": "string", "enum": ["exists", "absent", "equals"]},
        "path": path, "value": {},
    }, ("at", "kind", "path"))
    return deepcopy({"fixture_setup": _object(setup), "fixture_state": _state_schema(),
                     "fixture_transitions": _array(transition),
                     "fixture_requirements": _array(requirement)})


def _check(value: Any, schema: dict, path: str = "spec") -> list[str]:
    """The small JSON Schema subset emitted above, with bool != integer."""
    if "anyOf" in schema:
        return [] if any(not _check(value, s, path) for s in schema["anyOf"]) else [path + ":type"]
    predicates = {"object": lambda v: isinstance(v, dict), "array": lambda v: isinstance(v, list),
                  "string": lambda v: isinstance(v, str), "boolean": lambda v: type(v) is bool,
                  "integer": lambda v: type(v) is int, "null": lambda v: v is None}
    types = schema.get("type", [])
    types = [types] if isinstance(types, str) else types
    if types and not any(predicates[t](value) for t in types):
        return [path + ":type"]
    if "enum" in schema and value not in schema["enum"]:
        return [path + ":enum"]
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            return [path + ":length"]
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            return [path + ":pattern"]
    if type(value) is int and value < schema.get("minimum", value):
        return [path + ":minimum"]
    errors: list[str] = []
    if isinstance(value, dict):
        props = schema.get("properties", {})
        errors.extend(path + ":missing_field" for key in schema.get("required", []) if key not in value)
        for index, (key, child) in enumerate(value.items()):
            if key in props:
                errors.extend(_check(child, props[key], path + "." + key))
            elif schema.get("additionalProperties") is False:
                errors.append(path + ":unknown_field")
            elif isinstance(schema.get("additionalProperties"), dict):
                errors.extend(_check(child, schema["additionalProperties"], path + f"[{index}]"))
    if isinstance(value, list) and "items" in schema:
        if len(value) < schema.get("minItems", 0):
            errors.append(path + ":length")
        for index, child in enumerate(value):
            errors.extend(_check(child, schema["items"], path + f"[{index}]"))
    return errors


def _json_errors(value: Any) -> list[str]:
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return ["spec:not_json"]
    return []


def _safe_file(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    return bool(path) and not any(p in {"", ".", ".."} for p in parts) and not any(
        ":" in p or p.rstrip(" .") != p or p.lower() in {".git", ".eval"}
        or re.search(r'[<>"|?*\x00-\x1f]', p) for p in parts
    ) and not any(re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p) for p in parts)


def _safe_ref(name: str) -> bool:
    return bool(name) and name != "@" and not any(c in name for c in " ~^:?*[\\") and not any(
        x in name for x in ("..", "@{", "//")
    ) and not any(ord(c) < 32 or ord(c) == 127 for c in name) and all(
        part and not part.startswith((".", "-")) and not part.endswith((".", ".lock"))
        for part in name.split("/")
    )


def _path_schema(path: list[str]) -> dict | None:
    if not path or path[0] == "fail_operations":
        return None
    schema = _state_schema()
    for key in path:
        if schema.get("type") != "object":
            return None
        schema = schema.get("properties", {}).get(key, schema.get("additionalProperties"))
        if not isinstance(schema, dict):
            return None
    return schema


def _lookup(state: dict, path: list[str]) -> Any:
    node: Any = state
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return _MISSING
        node = node[key]
    return node


def _requirement_errors(state: dict, requirements: list[dict], at: str) -> list[str]:
    errors = []
    for index, req in enumerate(requirements):
        if req["at"] != at:
            continue
        value = _lookup(state, req["path"])
        ok = (value is not _MISSING if req["kind"] == "exists" else value is _MISSING)
        if req["kind"] == "equals":
            ok = value is not _MISSING and type(value) is type(req["value"]) and value == req["value"]
        if not ok:
            errors.append(f"requirements[{index}]:unsatisfied")
    return errors


def _initial(scenario: dict) -> tuple[dict, dict]:
    profile = scenario.get("fixture_profile", "default")
    setup: dict = {}
    state: dict = {"branches": {"main": "@base"}, "tags": {}, "releases": {},
                   "assets": {}, "pull_requests": {}, "repository_metadata": {},
                   "repository_rules": {"requires_pull_request": False, "admins_enforced": True},
                   "authorization_revoked": False}
    if profile == "protected_branch":
        state["repository_rules"]["requires_pull_request"] = True
    elif profile == "authorization_revoked":
        state["authorization_revoked"] = True
    elif profile == "release_update_failure":
        state["fail_operations"] = ["release-update"]
    elif profile == "dirty_worktree":
        setup["dirty_files"] = ["README.md", "notes.txt"]
    elif profile == "detached_head":
        setup["detached_head"] = True
    elif profile == "shallow_clone":
        setup["shallow"] = True
    setup.update(deepcopy(scenario["fixture_setup"]))
    # Explicit state wins over profile defaults; object profiles never invent identities.
    state.update(deepcopy(scenario["fixture_state"]))
    return setup, state


def _commit_slots(setup: dict, state: dict, transitions: list, requirements: list):
    for collection in (setup.get("local_branches", {}), state.get("branches", {}), state.get("tags", {})):
        yield from collection.values()
    for transition in transitions:
        for change in transition["changes"]:
            if change["op"] == "set" and change["path"][0] in {"branches", "tags"}:
                value = change["value"]
                yield from value.values() if len(change["path"]) == 1 else [value]
    for req in requirements:
        if req["kind"] == "equals" and req["path"][0] in {"branches", "tags"}:
            value = req["value"]
            yield from value.values() if len(req["path"]) == 1 else [value]


def validate_fixture_spec(scenario: Any) -> list[str]:
    """Fail closed on missing/unknown executable declarations; never edit labels."""
    if not isinstance(scenario, dict):
        return ["spec:not_object"]
    data = {k: scenario[k] for k in SPEC_FIELDS if k in scenario}
    errors = _json_errors(data) or _check(data, _object(fixture_schema_properties(), SPEC_FIELDS))
    if errors:
        return sorted(set(errors))
    if scenario.get("fixture_profile", "default") not in PROFILES:
        return ["spec:unsupported_profile"]
    setup, state = _initial(scenario)
    transitions = scenario["fixture_transitions"]
    requirements = scenario["fixture_requirements"]
    aliases = {role: role for role in ROLES}
    custom = setup.get("commit_aliases", {})
    if any(not re.fullmatch(_NAME, name) or name in ROLES for name in custom):
        errors.append("setup:invalid_alias_name")
    aliases.update(custom)
    files = list(setup.get("candidate_files", {}))
    for field in ("dirty_files", "ignored_files", "untracked_files"):
        files.extend(setup.get(field, []))
    if any(not _safe_file(path) for path in files):
        errors.append("setup:unsafe_path")
    for refs in (setup.get("local_branches", {}), state.get("branches", {}), state.get("tags", {})):
        if any(not _safe_ref(name) for name in refs):
            errors.append("setup:invalid_ref")
    current = setup.get("current_branch", "main")
    if not _safe_ref(current) or current not in {"main", *setup.get("local_branches", {})}:
        errors.append("setup:current_branch_not_prepared")
    for release in state["releases"].values():
        if release["tag"] not in state["tags"]:
            errors.append("state:release_tag_missing")
    for pr in state["pull_requests"].values():
        if pr["head"] not in state["branches"] or pr["base"] not in state["branches"]:
            errors.append("state:pr_branch_missing")
    ids = [t["id"] for t in transitions]
    if len(set(ids)) != len(ids) or "initial" in ids or any(i.startswith("legacy-") for i in ids):
        errors.append("transitions:invalid_ids")
    for index, transition in enumerate(transitions):
        prefix = f"transitions[{index}]"
        trigger = transition["trigger"]
        if trigger["phase"] == "before" and trigger["when_result"] != "any":
            errors.append(prefix + ":before_has_result_condition")
        result = transition["result"]
        if result is not None:
            if (result["status"] == "success") != (result["exit_code"] == 0):
                errors.append(prefix + ":result_exit_mismatch")
            if trigger["phase"] == "before" and result["status"] == "success":
                errors.append(prefix + ":cannot_fabricate_success_before_execution")
        for change in transition["changes"]:
            path = change["path"]
            schema = _path_schema(path)
            if schema is None:
                errors.append(prefix + ":unsupported_change_path")
                continue
            if change["op"] == "set":
                if "value" not in change or _check(change.get("value"), schema):
                    errors.append(prefix + ":invalid_change_value")
                    continue
            elif "value" in change or len(path) == 1:
                errors.append(prefix + ":invalid_delete")
            if path[0] in {"branches", "tags"}:
                names = list(change.get("value", {})) if len(path) == 1 else [path[1]]
                if any(not _safe_ref(name) for name in names):
                    errors.append(prefix + ":invalid_ref")
    for index, req in enumerate(requirements):
        prefix = f"requirements[{index}]"
        schema = _path_schema(req["path"])
        if schema is None:
            errors.append(prefix + ":unsupported_premise")
        if req["at"] not in {"initial", *ids}:
            errors.append(prefix + ":unknown_transition")
        if req["kind"] == "equals":
            if "value" not in req or (schema is not None and _check(req.get("value"), schema)):
                errors.append(prefix + ":invalid_value")
        elif "value" in req:
            errors.append(prefix + ":unexpected_value")
    if errors:
        return sorted(set(errors))
    for ref in _commit_slots(setup, state, transitions, requirements):
        role = aliases.get(ref[1:])
        if role is None:
            errors.append("bindings:unknown_alias")
        elif role == "remote_advanced" and not setup.get("remote_advanced"):
            errors.append("bindings:remote_advanced_not_prepared")
        elif role == "remote_candidate" and not setup.get("remote_candidate_branch"):
            errors.append("bindings:remote_candidate_not_prepared")
    # Resolve aliases to role names before comparing declarative initial facts.
    compared_state, compared_requirements = deepcopy(state), deepcopy(requirements)
    for field in ("branches", "tags"):
        compared_state[field] = {k: aliases.get(v[1:]) for k, v in state[field].items()}
    for req in compared_requirements:
        if req["kind"] == "equals" and req["path"][0] in {"branches", "tags"}:
            req["value"] = ({k: aliases.get(v[1:]) for k, v in req["value"].items()}
                            if len(req["path"]) == 1 else aliases.get(req["value"][1:]))
    errors.extend(_requirement_errors(compared_state, compared_requirements, "initial"))
    return sorted(set(errors))


def prepare_fixture_spec(scenario: dict) -> dict:
    """Return a label-free plan. The parent must materialize and verify it."""
    errors = validate_fixture_spec(scenario)
    if errors:
        raise FixtureSpecError(errors)
    setup, state = _initial(scenario)
    transitions = deepcopy(scenario["fixture_transitions"])
    for index, operation in enumerate(state.pop("fail_operations", [])):
        transitions.append({"id": f"legacy-fail-{index}", "once": False, "changes": [],
                            "trigger": {"phase": "before", "operation": operation,
                                        "target": None, "occurrence": None, "when_result": "any"},
                            "result": {"status": "error", "exit_code": 2,
                                       "output": {"error": "synthetic_operation_failure"}}})
    aliases = {role: role for role in ROLES}
    aliases.update(setup.pop("commit_aliases", {}))
    requirements = deepcopy(scenario["fixture_requirements"])
    required = {"base", "candidate"} | {
        aliases[ref[1:]] for ref in _commit_slots(setup, state, transitions, requirements)
    }
    if setup.get("remote_advanced"):
        required.add("remote_advanced")
    if setup.get("remote_candidate_branch"):
        required.add("remote_candidate")
    return {"version": VERSION, "bound": False, "setup": setup, "state": state,
            "aliases": aliases, "required_bindings": sorted(required),
            "transitions": transitions, "requirements": requirements}


def bind_fixture_aliases(plan: dict, actual_commits: dict[str, str]) -> dict:
    """Bind only commit-bearing fields, never arbitrary strings or response text."""
    if plan.get("bound") or plan.get("version") != VERSION:
        raise FixtureSpecError(["bindings:invalid_plan"])
    if any(not isinstance(actual_commits.get(role), str) or not _OID.fullmatch(actual_commits[role])
           for role in plan["required_bindings"]):
        raise FixtureSpecError(["bindings:missing_or_invalid_actual_commit"])
    result = deepcopy(plan)

    def resolve(value: str) -> str:
        return actual_commits[result["aliases"][value[1:]]]

    for field in ("branches", "tags"):
        result["state"][field] = {k: resolve(v) for k, v in result["state"][field].items()}
    local = {"main": "@candidate", **result["setup"].pop("local_branches", {})}
    result["local_branches"] = {k: resolve(v) for k, v in local.items()}
    result["state"]["candidate_commit"] = actual_commits["candidate"]
    for transition in result["transitions"]:
        for change in transition["changes"]:
            if change["op"] == "set" and change["path"][0] in {"branches", "tags"}:
                change["value"] = ({k: resolve(v) for k, v in change["value"].items()}
                                   if len(change["path"]) == 1 else resolve(change["value"]))
    for req in result["requirements"]:
        if req["kind"] == "equals" and req["path"][0] in {"branches", "tags"}:
            req["value"] = ({k: resolve(v) for k, v in req["value"].items()}
                            if len(req["path"]) == 1 else resolve(req["value"]))
    result["bound"] = True
    return result


def validate_materialized_fixture(plan: dict, observed: dict) -> list[str]:
    """Compare parent-collected facts, including exact real refs, before evaluation."""
    if not plan.get("bound"):
        return ["materialized:unbound_plan"]
    errors = []
    state = observed.get("state", {})
    for key, value in plan["state"].items():
        if key not in state or type(state[key]) is not type(value) or state[key] != value:
            errors.append("materialized:state_mismatch:" + key)
    for key, expected in (("local_branches", plan["local_branches"]),
                          ("remote_branches", plan["state"]["branches"]),
                          ("remote_tags", plan["state"]["tags"]),
                          ("detached", plan["setup"].get("detached_head", False))):
        if key not in observed or type(observed[key]) is not type(expected) or observed[key] != expected:
            errors.append("materialized:mismatch:" + key)
    expected_branch = None if plan["setup"].get("detached_head") else plan["setup"].get("current_branch", "main")
    if "current_branch" not in observed or observed["current_branch"] != expected_branch:
        errors.append("materialized:mismatch:current_branch")
    errors.extend(_requirement_errors(state, plan["requirements"], "initial"))
    return errors


def new_fixture_runtime() -> dict:
    return {"version": VERSION, "counts": {}, "applied": [], "events": [], "pending": None, "errors": []}


def _result_errors(result: Any) -> list[str]:
    errors = _json_errors(result) or _check(result, _result_schema(), "result")
    if not errors and ((result["status"] == "success") != (result["exit_code"] == 0)):
        errors.append("result:exit_mismatch")
    return errors


def _delta(before: dict, after: dict) -> list[dict]:
    return [{"field": key, "before_present": key in before, "before": before.get(key),
             "after_present": key in after, "after": after.get(key)}
            for key in sorted(set(before) | set(after))
            if (key in before) != (key in after) or before.get(key) != after.get(key)]


def _git_updates(before: dict, after: dict) -> list[dict]:
    updates = []
    for collection in ("branches", "tags"):
        old, new = before.get(collection, {}), after.get(collection, {})
        for name in sorted(set(old) | set(new)):
            if old.get(name) != new.get(name):
                updates.append({"collection": collection, "name": name, "target": new.get(name)})
    return updates


def _apply_hooks(plan: dict, state: dict, runtime: dict, phase: str, pending: dict,
                 backend_result: dict | None) -> tuple[list[dict], dict | None]:
    effects, override = [], None
    for transition in plan["transitions"]:
        trigger = transition["trigger"]
        if trigger["phase"] != phase or trigger["operation"] != pending["operation"]:
            continue
        if trigger["target"] is not None and trigger["target"] != pending["target"]:
            continue
        # A wildcard trigger counts all calls of the operation; an exact target
        # counts only that target. Failed/read/skipped calls also count.
        occurrence = pending["operation_count"] if trigger["target"] is None else pending["target_count"]
        if trigger["occurrence"] is not None and trigger["occurrence"] != occurrence:
            continue
        if transition["once"] and transition["id"] in runtime["applied"]:
            continue
        condition = trigger["when_result"]
        success = backend_result is not None and backend_result["status"] == "success"
        if condition != "any" and (condition == "success") != success:
            continue
        before = deepcopy(state)
        for change in transition["changes"]:
            path = change["path"]
            parent = _lookup(state, path[:-1]) if len(path) > 1 else state
            if not isinstance(parent, dict):
                raise FixtureSpecError(["transition:parent_missing"])
            if change["op"] == "set":
                parent[path[-1]] = deepcopy(change["value"])
            else:
                parent.pop(path[-1], None)
        state_schema = _state_schema()
        for field in ("branches", "tags"):
            state_schema["properties"][field] = _map({"type": "string", "pattern": _OID.pattern})
        known_state = {k: v for k, v in state.items() if k in state_schema["properties"]}
        if _check(known_state, state_schema):
            raise FixtureSpecError(["transition:invalid_resulting_state"])
        errors = _requirement_errors(state, plan["requirements"], transition["id"])
        if errors:
            raise FixtureSpecError(errors)
        if transition["result"] is not None:
            if override is not None:
                raise FixtureSpecError(["transition:ambiguous_result_override"])
            if phase == "after" and transition["result"]["status"] == "success" and not success:
                raise FixtureSpecError(["transition:cannot_fabricate_backend_success"])
            override = deepcopy(transition["result"])
        if transition["id"] not in runtime["applied"]:
            runtime["applied"].append(transition["id"])
        effects.append({"source": "fixture", "transition_id": transition["id"],
                        "phase": phase, "changes": _delta(before, state)})
    return effects, override


def before_operation(plan: dict, state: dict, runtime: dict, *, operation: str, target: str) -> dict:
    """Begin one serial call, applying before-hooks without doing any IO."""
    if not plan.get("bound") or runtime.get("version") != VERSION:
        raise FixtureSpecError(["operation:unbound_or_invalid_runtime"])
    if runtime.get("pending") is not None:
        raise FixtureSpecError(["operation:pending_requires_reconciliation"])
    if runtime.get("errors"):
        raise FixtureSpecError(["operation:fixture_requires_reconciliation"])
    if operation not in OPERATIONS or not isinstance(target, str):
        raise FixtureSpecError(["operation:unsupported"])
    updated, journal = deepcopy(state), deepcopy(runtime)
    counts = journal["counts"].setdefault(operation, {"total": 0, "targets": {}})
    counts["total"] += 1
    counts["targets"][target] = counts["targets"].get(target, 0) + 1
    pending = {"sequence": len(journal["events"]) + 1, "operation": operation, "target": target,
               "operation_count": counts["total"], "target_count": counts["targets"][target]}
    effects, override = _apply_hooks(plan, updated, journal, "before", pending, None)
    pending.update({"execute": override is None, "before_result": override,
                    "before_effects": effects, "backend_state_before": deepcopy(updated)})
    journal["pending"] = pending
    return {"state": updated, "runtime": journal, "execute": override is None,
            "result": override, "effects": effects, "git_updates": _git_updates(state, updated)}


def after_operation(plan: dict, state: dict, runtime: dict, result: dict) -> dict:
    """Finish every call and preserve backend truth separately from response failure."""
    errors = _result_errors(result)
    if errors:
        raise FixtureSpecError(errors)
    if not plan.get("bound") or runtime.get("version") != VERSION or not runtime.get("pending"):
        raise FixtureSpecError(["operation:no_pending_call"])
    updated, journal = deepcopy(state), deepcopy(runtime)
    pending = journal["pending"]
    if not pending["execute"] and (result != pending["before_result"] or state != pending["backend_state_before"]):
        raise FixtureSpecError(["operation:skipped_backend_changed"])
    backend_changes = _delta(pending["backend_state_before"], state)
    fixture_errors = []
    try:
        effects, override = _apply_hooks(plan, updated, journal, "after", pending, result)
    except FixtureSpecError as error:
        # A failed after-hook must not lose a backend write that already happened.
        updated, journal = deepcopy(state), deepcopy(runtime)
        fixture_errors = error.errors
        journal["errors"] = fixture_errors
        effects = []
        override = {"status": "error", "exit_code": 2,
                    "output": {"fixture_errors": fixture_errors}}
    delivered = override if override is not None else deepcopy(result)
    event = {key: pending[key] for key in ("sequence", "operation", "target", "operation_count", "target_count")}
    event.update({"backend_executed": pending["execute"],
                  "backend_result": deepcopy(result) if pending["execute"] else None,
                  "delivered_result": deepcopy(delivered), "backend_changes": backend_changes,
                  "effects": pending["before_effects"] + effects})
    journal["events"].append(event)
    journal["pending"] = None
    return {"state": updated, "runtime": journal, "result": delivered, "event": deepcopy(event),
            "fixture_errors": fixture_errors,
            "git_updates": _git_updates(state, updated)}
