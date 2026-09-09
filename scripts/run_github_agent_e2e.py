"""Model-directed orchestration for parent-prepared controlled GitHub E2E.

Nothing runs on import and there is no execution main. run_flow(flow,args) and
run_flows(flows,args) explicitly run real capture/read/write operations when
called. They never prepare fixtures, create repositories, change rules, create
tags, rebase candidates, or grade a run as passed.

Flow input: {"flow": <one of FLOW_NAMES>, "checkout": <absolute path>,
"contract": <github_e2e_decisions contract>, "untrusted_text": [{source,text}]}.
The parent prepares the actual contracts/checkouts and grades the observations.
collect_snapshot(flow) reads GitHub and local ancestry. capture_decision(session,
flow,args,turn) calls the parent collector ONLY when explicitly invoked; args
provides codex, model, reasoning, raw_output_dir, timeout_seconds and skill.
Optionally args.capture_transport is a trusted parent callable with signature
    (prompt, schema_dict, model, reasoning, timeout) -> (CompletedProcess, decision)
where decision is a parsed JSON object (or None if capture failed). It receives
no environment, checkout path, executor or GitHub credential arguments. The
parent callback must forward only these inputs to its verified external runtime.
It owns that runtime's tool/permission configuration; native CLI flags below do
not apply to an external transport. Both paths persist visible output and the
final JSON in the same parent-owned external raw directory and reject tool events.
An optional process.capture_provenance dictionary from the trusted transport is
stored beside them as capture-provenance.json. Supported fields: runtime_record
(absolute Linux record path), optional windows_transport_sha256 and
linux_transport_sha256 (source-byte SHA256 digests). Model JSON is never a source
of provenance; these parent assertions are not independent isolation proof.
build_parser() exposes those options, including --skill (default ROOT/SKILL.md),
without a runnable CLI entrypoint. run_flow uses the existing validate_decision
and apply_feedback bridge for every step, and returns initial_snapshot, events
(decisions/plans/preflight and resulting snapshots/feedback), final_session and
a factual status such as model_stopped, decision_rejected or incomplete.
Neither model_stopped nor a six-element result is a grade or a pass.

Optional args.on_remote_change(flow, old_snapshot, fresh_snapshot) -> {ref:OID}
is trusted parent coordination, called only after an observed preflight change.
It may reconcile local authorized content and return replacement candidates on
already-authorized branch refs. The driver re-observes them, uses refresh_snapshot
and asks the model again; no rejected write is automatically retried. Callback
activity is recorded separately as parent coordination, never model execution.
A parent that does not provide this hook can leave the candidate unchanged and
let the model read or stop. args.max_turns defaults to 12. Exhaustion returns
turn_limit without an extra capture or a fabricated model stop. The run record
is returned in memory; durable mid-run journaling is parent-owned and external.
Optional args.resume_session continues a parent-verified, nonpending, nonstopped
session with the exact matching flow contract. Fresh changed facts take the same
refresh/parent-coordination path before capture. Existing step/readback state is
preserved; capture numbering starts at that step, and max_turns bounds this
invocation. resumed_from records the source request/snapshot identities; the
parent retains and links the original record and chooses the external raw root.

Raw visible model JSONL and the last message go only to --raw-output-dir outside
the source repository and all fixture checkouts. The prompt contains a redacted
closed contract and observations, plus the exact candidate Skill and its default
reference text. It contains no generated executor commands or environment values.
The output schema binds request identities and authorized ref spellings only;
all closed action/kind choices remain available for the model to decide.
_capture_codex is the parent's visible-output collector.

IMPORTANT: tool-disable flags, read-only sandbox requests and environment
scrubbing are NOT proof of tool or credential isolation. An observed tool event
aborts before executor dispatch, but cannot undo anything that tool already did.
The parent must establish isolation before any real model launch. This driver
does not qualify the separate native local-tool evaluation.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from uuid import uuid4

from github_e2e_decisions import (
    ALLOWED_REPOSITORY, DECISION_SCHEMA, DecisionError, WRITE_KINDS,
    apply_feedback, build_request, refresh_snapshot, start_session, validate_decision,
)
from run_behavior_eval import _capture_codex, _safe_environment, _visible_jsonl
from run_github_e2e import REPOSITORY_URL, _api_items, _gh, _json, _remote_ref, _run
from eval_runtime_permissions import linux_permission_args


ROOT = Path(__file__).resolve().parents[1]
FLOW_NAMES = frozenset({"push_only", "protected_without_bypass", "pr_create_only", "remote_race", "tag_and_release", "instruction_injection"})
TOOL_DISABLES = ("shell_tool", "unified_exec", "multi_agent", "plugins", "remote_plugin", "skill_search", "plugin_sharing")
DEFAULT_SKILL_REFERENCES = ("references/review-and-memory.md",)


def build_parser() -> argparse.ArgumentParser:
    """Argument definitions for the parent adapter; there is no execution main."""
    parser = argparse.ArgumentParser(description="Closed GitHub decision adapter configuration")
    parser.add_argument("--skill", type=Path, default=ROOT / "SKILL.md")
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--model", required=True)
    parser.add_argument("--reasoning", default="high")
    parser.add_argument("--raw-output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--max-turns", type=int, default=12)
    return parser


def _skill_input(path: Path) -> dict:
    # Decode bytes directly to retain original CRLF/LF text, with no truncation,
    # redaction, installed-skill fallback, or evaluation answer sources.
    skill = path.resolve()
    content = skill.read_bytes().decode("utf-8")
    references = []
    for relative in DEFAULT_SKILL_REFERENCES:
        if relative in content:
            target = (skill.parent / relative).resolve()
            _require(target.is_relative_to(skill.parent), "Skill reference escapes its candidate directory")
            references.append({"name": relative, "text": target.read_bytes().decode("utf-8")})
    return {"name": skill.name, "text": content, "references": references}


def _sanitize_state(value, roots: list[Path]):
    """Sanitize observation/request strings without truncating their content.

    This is transport redaction, not a guarantee that arbitrary text is secret-
    free. Candidate Skill/reference text deliberately does not pass through it.
    """
    if isinstance(value, str):
        text = value
        for root in sorted(roots, key=lambda path: len(str(path)), reverse=True):
            for spelling in {str(root), str(root).replace("\\", "/")}:
                text = text.replace(spelling, "<LOCAL_PATH>")
        text = re.sub(r"(?i)((?:token|password|secret|api[_-]?key|authorization)\s*[:=]\s*)[^\s,;]+", r"\1<REDACTED>", text)
        text = re.sub(r"(?i)(?<![A-Z0-9])[A-Z]:[\\/][^\s\"'<>]+", "<LOCAL_PATH>", text)
        text = re.sub(r"\\\\[^\s\"'<>]+", "<LOCAL_PATH>", text)
        return re.sub(r"(?<![\w:/])/(?!/)[^\s\"'<>]+", "<LOCAL_PATH>", text)
    if isinstance(value, list):
        return [_sanitize_state(item, roots) for item in value]
    if isinstance(value, dict):
        return {_sanitize_state(key, roots): _sanitize_state(item, roots) for key, item in value.items()}
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DecisionError(message)


def _validate_flow(flow: dict, raw_root: Path | None = None) -> None:
    _require(isinstance(flow, dict) and set(flow) == {"flow", "checkout", "contract", "untrusted_text"}, "unexpected flow fields")
    _require(flow["flow"] in FLOW_NAMES, "unknown flow label")
    checkout = Path(flow["checkout"])
    _require(checkout.is_absolute(), "checkout must be absolute")
    if raw_root is not None:
        raw = raw_root.resolve()
        _require(not raw.is_relative_to(ROOT) and not raw.is_relative_to(checkout.resolve()), "raw output must be outside source and fixture repositories")
    empty = {"snapshot_id": "input-validation", "repo": ALLOWED_REPOSITORY, "refs": {}, "branch_rules": {}, "candidates": {}, "tags": {}, "prs": {}, "releases": {}, "untrusted_text": flow["untrusted_text"]}
    start_session(flow["contract"], empty)


def _api(endpoint: str):
    result = _gh(ALLOWED_REPOSITORY, "api", f"repos/{ALLOWED_REPOSITORY}/{endpoint}", check=False)
    if result.returncode == 0:
        return _json(result)
    if "(HTTP 404)" in result.stderr:
        return None
    raise RuntimeError("GitHub observation failed; absence was not established")


def _verify_checkout(checkout: Path) -> None:
    _require(checkout.is_absolute(), "checkout must be absolute")
    for options in ([], ["--push"]):
        actual = _run(["git", "remote", "get-url", *options, "--all", "origin"], checkout).stdout.strip()
        _require(actual == REPOSITORY_URL, "checkout origin differs from the exact synthetic repository")
    # Local configuration is not suppressed by _run's global/system isolation.
    config = _run(["git", "config", "--local", "--name-only", "--list"], checkout).stdout.lower().splitlines()
    _require(not any(key.startswith(("include", "url.", "http.", "credential.")) or key in {"remote.origin.mirror", "remote.origin.push", "push.followtags"} for key in config), "checkout contains routing or push overrides")


def _classic_patterns() -> list[str] | None:
    owner, name = ALLOWED_REPOSITORY.split("/")
    query = "query($owner:String!,$name:String!){repository(owner:$owner,name:$name){nameWithOwner branchProtectionRules(first:100){nodes{pattern} pageInfo{hasNextPage}}}}"
    result = _gh(ALLOWED_REPOSITORY, "api", "graphql", "-f", f"query={query}", "-f", f"owner={owner}", "-f", f"name={name}", check=False)
    if result.returncode:
        return None
    payload = _json(result)
    repo = (payload.get("data") or {}).get("repository")
    if payload.get("errors") or not repo or repo.get("nameWithOwner") != ALLOWED_REPOSITORY:
        return None
    rules = repo.get("branchProtectionRules") or {}
    if rules.get("pageInfo", {}).get("hasNextPage") is not False:
        return None
    nodes = rules.get("nodes")
    if not isinstance(nodes, list) or any(not isinstance(item.get("pattern"), str) for item in nodes):
        return None
    return [item["pattern"] for item in nodes]


def _direct_push_allowed(ref: str, patterns: list[str] | None):
    name = ref.removeprefix("refs/heads/")
    if patterns is None:
        return None
    # Do not guess GitHub's wildcard matching/bypass semantics. Exact rules
    # and any wildcard rule conservatively block direct pushes in this driver.
    if any(pattern == name or any(char in pattern for char in "*?[\\") for pattern in patterns):
        return False
    branch = _api(f"branches/{name}")
    if branch is not None and branch.get("protected") is not False:
        return False
    rules = _api(f"rules/branches/{name}")
    return True if rules == [] else False if isinstance(rules, list) else None


def _read_pr(ref: str):
    head = ref.removeprefix("refs/heads/")
    owner = ALLOWED_REPOSITORY.split("/")[0]
    items = _api_items(ALLOWED_REPOSITORY, f"pulls?state=all&head={owner}:{head}&per_page=100")
    _require(len(items) <= 1, "multiple PRs for the target head require parent disambiguation")
    if not items:
        return None
    pr = items[0]
    _require(pr["head"]["ref"] == head and pr["head"]["repo"]["full_name"] == ALLOWED_REPOSITORY and pr["base"]["repo"]["full_name"] == ALLOWED_REPOSITORY, "PR repository/head identity mismatch")
    return {"number": pr["number"], "head": pr["head"]["sha"], "base_ref": f"refs/heads/{pr['base']['ref']}", "title": pr["title"], "body": pr["body"] or "", "state": "MERGED" if pr["merged_at"] else pr["state"].upper(), "merged": pr["merged_at"] is not None}


def collect_snapshot(flow: dict) -> dict:
    """Read actual authorized targets, failing closed on ambiguous observations."""
    _validate_flow(flow)
    contract, checkout = flow["contract"], Path(flow["checkout"])
    _require(contract["repo"] == ALLOWED_REPOSITORY, "repository outside allowlist")
    _verify_checkout(checkout)
    state = {"snapshot_id": uuid4().hex, "repo": ALLOWED_REPOSITORY, "refs": {}, "branch_rules": {}, "candidates": {}, "tags": {}, "prs": {}, "releases": {}, "untrusted_text": deepcopy(flow["untrusted_text"])}
    # Validate the closed contract before even constructing an API endpoint.
    start_session(contract, state)
    operations = contract["operations"]
    refs = {op["ref"] for op in operations} | {op["base_ref"] for op in operations if "base_ref" in op}
    for ref in sorted(refs):
        state["refs"][ref] = _remote_ref(checkout, ref)
    patterns = _classic_patterns() if any(op["action"] == "branchpush" for op in operations) else None
    for op in operations:
        action, ref = op["action"], op["ref"]
        if action == "branchpush":
            base, candidate = state["refs"][ref], op["commit"]
            actual = _run(["git", "rev-parse", "--verify", f"{candidate}^{{commit}}"], checkout).stdout.strip()
            _require(actual == candidate, "authorized candidate commit is not available")
            if base is not None:
                _run(["git", "fetch", "--no-tags", "origin", ref], checkout)
                ancestry = _run(["git", "merge-base", "--is-ancestor", base, candidate], checkout, check=False)
                _require(ancestry.returncode in {0, 1}, "ancestry check could not be completed")
                fast_forward = ancestry.returncode == 0
            else:
                fast_forward = True
            state["candidates"][ref] = {"commit": candidate, "based_on": base, "fast_forward": fast_forward}
            state["branch_rules"][ref] = _direct_push_allowed(ref, patterns)
        if action == "prcreate" or (action == "readback" and op["kind"] == "pr"):
            state["prs"][ref] = _read_pr(ref)
        if ref.startswith("refs/tags/"):
            oid = state["refs"][ref]
            state["tags"][ref] = None if oid is None else {"object": oid, "target": _remote_ref(checkout, ref + "^{}") or oid}
        if action == "releasecreate" or (action == "readback" and op["kind"] == "release"):
            release = _api(f"releases/tags/{ref.removeprefix('refs/tags/')}")
            if release is not None:
                _require(release["tag_name"] == ref.removeprefix("refs/tags/"), "release tag identity mismatch")
                release = {"id": release["id"], "title": release["name"] or "", "body": release["body"] or "", "draft": release["draft"], "prerelease": release["prerelease"], "assets": [asset["name"] for asset in release["assets"]]}
            state["releases"][ref] = release
    for ref, oid in state["refs"].items():
        _require(_remote_ref(checkout, ref) == oid, "remote changed during snapshot collection")
    start_session(contract, state)  # Validate observation types and tag consistency.
    return state


def _codex_command(args, work: Path, schema: Path, final: Path) -> list[str]:
    command = [args.codex, "--cd", str(work), "--enable", "skip_host_skill_discovery"]
    for feature in TOOL_DISABLES:
        command.extend(["--disable", feature])
    command += ["exec", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "--json", "--color", "never", "--output-schema", str(schema), "--output-last-message", str(final), "--model", args.model, "--config", f'model_reasoning_effort="{args.reasoning}"', "--config", "show_raw_agent_reasoning=false", "--config", "shell_environment_policy.experimental_use_profile=false"]
    if sys.platform == "linux":
        command.extend(linux_permission_args(work))
    else:
        # Preserve the native fallback, without certifying Windows isolation.
        command.extend(["--sandbox", "read-only"])
    return command + ["-"]


def _reject_tool_events(stdout: str) -> None:
    """A post-capture guard, NOT a pre-execution isolation mechanism."""
    for line in stdout.splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        _require(isinstance(event, dict), "unrecognized model event")
        kind = event.get("type")
        if kind in {"item.started", "item.updated", "item.completed"}:
            _require(isinstance(event.get("item"), dict) and event["item"].get("type") == "agent_message", "model emitted a tool or unsupported item; isolation is not established")
        else:
            _require(kind in {"thread.started", "turn.started", "turn.completed"}, "model failed or emitted an unsupported event")


def bind_decision_schema(request: dict) -> dict:
    """Type exact request identities/refs, without choosing an action or outcome."""
    schema = deepcopy(DECISION_SCHEMA)
    properties = schema["properties"]
    identities = {
        "schema_version": request["decision_schema"]["properties"]["schema_version"]["const"],
        "repo": request["authorization"]["repo"],
        "request_id": request["request_id"],
        "snapshot_id": request["facts"]["snapshot_id"],
    }
    for name, value in identities.items():
        properties[name]["const"] = value
    operations = request["authorization"]["operations"]
    readback_refs = {read["ref"] for operation in operations for read in operation["readbacks"]}
    refs = {operation["ref"] for operation in operations} | readback_refs
    properties["ref"]["enum"] = [None, *sorted(refs)]
    if readback_refs:
        properties["readbacks"]["items"]["properties"]["ref"]["enum"] = sorted(readback_refs)
    else:
        # An empty array remains valid; JSON Schema does not permit enum=[].
        properties["readbacks"]["maxItems"] = 0
    return schema


def _validate_capture_provenance(value: dict) -> dict:
    allowed = {"runtime_record", "windows_transport_sha256", "linux_transport_sha256"}
    _require(isinstance(value, dict) and "runtime_record" in value and set(value) <= allowed, "unsupported transport provenance fields")
    path = value["runtime_record"]
    _require(isinstance(path, str) and re.fullmatch(r"/[A-Za-z0-9_./-]+", path) is not None and all(part not in {"", ".", ".."} for part in path.split("/")[1:]), "invalid transport runtime record path")
    for name in allowed - {"runtime_record"}:
        if name in value:
            _require(isinstance(value[name], str) and re.fullmatch(r"[0-9a-f]{64}", value[name]) is not None, "invalid transport source digest")
    return deepcopy(value)


def capture_decision(session: dict, flow: dict, args, turn: int) -> tuple[dict, str]:
    _validate_flow(flow, args.raw_output_dir)
    _require(session["contract"] == flow["contract"], "session does not match the parent's flow contract")
    transport = getattr(args, "capture_transport", None)
    _require(transport is None or callable(transport), "capture_transport must be a trusted callable")
    candidate_skill = _skill_input(Path(getattr(args, "skill", ROOT / "SKILL.md")))
    raw = args.raw_output_dir.resolve() / flow["flow"] / f"turn-{turn:03d}"
    raw.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="gsp-closed-decision-") as temporary:
        work = Path(temporary)
        gh_config = work / "empty-gh"
        gh_config.mkdir()
        schema, final = raw / "schema.json", raw / "decision.json"
        request = _sanitize_state(build_request(session), [ROOT, Path(flow["checkout"]), args.raw_output_dir, work])
        bound_schema = bind_decision_schema(request)
        request["decision_schema"] = deepcopy(bound_schema)
        schema.write_text(json.dumps(bound_schema), encoding="utf-8")
        request["candidate_skill"] = candidate_skill
        prompt = json.dumps(request, ensure_ascii=False)
        (raw / "request.json").write_text(prompt, encoding="utf-8")
        if transport is None:
            process = _capture_codex(_codex_command(args, work, schema, final), cwd=work, env=_safe_environment(gh_config), prompt=prompt, timeout=args.timeout_seconds)
        else:
            process, decision = transport(prompt, deepcopy(bound_schema), args.model, args.reasoning, args.timeout_seconds)
            if decision is not None:
                final.write_text(json.dumps(decision, ensure_ascii=False), encoding="utf-8")
        visible = _visible_jsonl(process.stdout)
        (raw / "visible.jsonl").write_text(visible, encoding="utf-8")
        (raw / "stderr.txt").write_text(process.stderr, encoding="utf-8")
        if transport is not None and getattr(process, "capture_provenance", None) is not None:
            provenance = _validate_capture_provenance(process.capture_provenance)
            (raw / "capture-provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
        _require(process.returncode == 0, "model capture failed; no executor action dispatched")
        _reject_tool_events(visible)
        _require(final.is_file(), "model did not produce a closed final decision")
        decision = json.loads(final.read_text(encoding="utf-8"))
        _require(isinstance(decision, dict), "model final decision must be a JSON object")
    return decision, str(raw / "visible.jsonl")


def execute_plan(flow: dict, session: dict, decision: dict, plan: dict, snapshot: dict):
    """Execute only an exactly regenerated write plan. Reads/stop use run_flow.

    The bridge and fresh snapshot are mandatory; an arbitrary plan dictionary is
    not executable authority. No shell strings, force flags or cleanup actions
    are accepted. Ordinary GitHub enforcement remains active.
    """
    _validate_flow(flow)
    _require(flow["contract"] == session["contract"], "executor contract mismatch")
    _, expected = validate_decision(session, decision, snapshot)
    _require(plan == expected and plan["operation"] in WRITE_KINDS, "executor requires the exact validated write plan")
    checkout = Path(flow["checkout"])
    _verify_checkout(checkout)
    action, ref, parameters = plan["operation"], plan["ref"], plan["parameters"]
    if action == "branchpush":
        _require(_direct_push_allowed(ref, _classic_patterns()) is True, "direct push protection changed or is unknown")
        _require(_remote_ref(checkout, ref) == parameters["expected_remote_oid"], "remote changed immediately before push")
        return _run(["git", "push", "origin", f"{parameters['commit']}:{ref}"], checkout, check=False)
    if action == "prcreate":
        _require(_read_pr(ref) is None, "PR already exists; no duplicate create")
        _require(_remote_ref(checkout, ref) == parameters["commit"] and _remote_ref(checkout, parameters["base_ref"]) == snapshot["refs"][parameters["base_ref"]], "PR branch changed immediately before create")
        return _gh(ALLOWED_REPOSITORY, "pr", "create", "--head", ref.removeprefix("refs/heads/"), "--base", parameters["base_ref"].removeprefix("refs/heads/"), "--title", parameters["title"], "--body", parameters["body"], check=False)
    _require(parameters["verify_tag"] is True, "release requires --verify-tag")
    tag = snapshot["tags"][ref]
    _require(_api(f"releases/tags/{ref.removeprefix('refs/tags/')}") is None, "release already exists; no duplicate create")
    _require(_remote_ref(checkout, ref) == tag["object"] and (_remote_ref(checkout, ref + "^{}") or tag["object"]) == parameters["target_commit"], "tag changed immediately before release create")
    return _gh(ALLOWED_REPOSITORY, "release", "create", ref.removeprefix("refs/tags/"), "--verify-tag", "--title", parameters["title"], "--notes", parameters["body"], check=False)


def _same_facts(first: dict, second: dict) -> bool:
    return {key: value for key, value in first.items() if key != "snapshot_id"} == {key: value for key, value in second.items() if key != "snapshot_id"}


def _coordinate_change(flow: dict, session: dict, fresh: dict, args, event: dict) -> tuple[dict, dict]:
    hook = getattr(args, "on_remote_change", None)
    _require(hook is None or callable(hook), "on_remote_change must be a trusted callable")
    revisions = {} if hook is None else hook(deepcopy(flow), deepcopy(session["snapshot"]), deepcopy(fresh))
    _require(isinstance(revisions, dict), "parent coordination must return a ref-to-commit map")
    allowed = {operation["ref"] for operation in flow["contract"]["operations"] if operation["action"] == "branchpush"}
    _require(set(revisions) <= allowed, "parent coordination cannot expand target refs")
    updated_flow = deepcopy(flow)
    for operation in updated_flow["contract"]["operations"]:
        if operation["action"] == "branchpush" and operation["ref"] in revisions:
            operation["commit"] = revisions[operation["ref"]]
    _validate_flow(updated_flow)
    if hook is not None:
        event["parent_coordination"] = {"source": "trusted_parent", "reconciled_commits": deepcopy(revisions)}
        fresh = collect_snapshot(updated_flow)
        event["coordinated_snapshot"] = deepcopy(fresh)
    return updated_flow, refresh_snapshot(session, fresh, reconciled_commits=revisions)


def run_flow(flow: dict, args) -> dict:
    """Run actual model decisions, with explicit evidence and no outcome grade.

    Returned errors retain completed events and pending write state. No capture,
    write, failed readback or uncertain write is automatically retried. A stop
    is always the model's decision, never generated to impersonate the model.
    """
    _validate_flow(flow, args.raw_output_dir)
    maximum = getattr(args, "max_turns", 12)
    _require(type(maximum) is int and maximum > 0, "max_turns must be positive")
    active_flow = deepcopy(flow)
    resume = getattr(args, "resume_session", None)
    if resume is not None:
        _require(isinstance(resume, dict) and resume.get("contract") == flow["contract"], "resume contract must match the exact flow")
        _require(resume.get("pending") is None and resume.get("stopped") is False, "cannot resume a pending or stopped session")
        _require(type(resume.get("step")) is int and resume["step"] >= 0, "invalid resume step")
        start_session(resume["contract"], resume["snapshot"])  # Validate, not reset.
        build_request(resume)
    session = deepcopy(resume)
    record = {"flow": flow["flow"], "status": "initializing", "grading": "caller_required", "fixture_setup": "parent_owned", "events": []}
    if session is not None:
        record["resumed_from"] = {"request_id": build_request(session)["request_id"], "snapshot_id": session["snapshot"]["snapshot_id"]}
    stage = "initial_snapshot"
    try:
        initial = collect_snapshot(active_flow)
        record["initial_snapshot"] = deepcopy(initial)
        if session is None:
            session = start_session(active_flow["contract"], initial)
        else:
            start_session(active_flow["contract"], initial)
            if not _same_facts(session["snapshot"], initial):
                stage = "resume_coordination"
                record["resume_refresh"] = {"result": "changed_before_capture_no_write"}
                active_flow, session = _coordinate_change(active_flow, session, initial, args, record["resume_refresh"])
        first_turn = session["step"]
        for turn in range(first_turn, first_turn + maximum):
            event = {"turn": turn, "request_id": build_request(session)["request_id"], "request_snapshot": deepcopy(session["snapshot"])}
            record["events"].append(event)
            stage = "capture"
            decision, raw_reference = capture_decision(session, active_flow, args, turn)
            event.update(decision=deepcopy(decision), raw_reference=raw_reference)
            stage = "decision_validation"
            # Check closed identity/authority before taking any action on model
            # text. In particular, a valid stop causes no further network read.
            waiting, plan = validate_decision(session, decision, session["snapshot"])
            if plan["operation"] == "stop":
                event.update(plan=deepcopy(plan), result="model_stop")
                session = waiting
                record["status"] = "model_stopped"
                break
            stage = "preflight_snapshot"
            fresh = collect_snapshot(active_flow)
            event["preflight_snapshot"] = deepcopy(fresh)
            if plan["operation"] in WRITE_KINDS and not _same_facts(session["snapshot"], fresh):
                event["result"] = "preflight_changed_no_write"
                stage = "parent_coordination"
                active_flow, session = _coordinate_change(active_flow, session, fresh, args, event)
                continue
            waiting, plan = validate_decision(session, decision, fresh)
            event["plan"] = deepcopy(plan)
            status = "success"
            if plan["operation"] in WRITE_KINDS:
                stage = "executor"
                try:
                    result = execute_plan(active_flow, session, decision, plan, fresh)
                    status = "success" if result.returncode == 0 else "failed"
                    event["executor_result"] = {"status": status, "exit_code": result.returncode}
                except subprocess.TimeoutExpired:
                    status = "unknown"
                    event["executor_result"] = {"status": status, "exit_code": None}
            else:
                # A read is performed by the actual following snapshot calls;
                # it has no fabricated single-process exit code.
                event["executor_result"] = {"status": "pending_observation", "exit_code": None}
            session = waiting  # Preserve the pending write if observation fails.
            feedback = {"request_id": plan["request_id"], "operation": plan["operation"], "ref": plan["ref"], "status": status}
            if plan["operation"] in WRITE_KINDS:
                event["feedback"] = deepcopy(feedback)
            stage = "post_snapshot"
            after = collect_snapshot(active_flow)
            event["post_snapshot"] = deepcopy(after)
            if plan["operation"] not in WRITE_KINDS:
                event["executor_result"] = {"status": "success", "exit_code": None, "source": "actual_snapshot_read"}
            event["feedback"] = deepcopy(feedback)
            stage = "feedback_validation"
            session = apply_feedback(session, feedback, after)
            event["result"] = "feedback_recorded"
        else:
            record["status"] = "turn_limit"
    except Exception as error:
        record["status"] = "decision_rejected" if stage == "decision_validation" else "incomplete"
        # Exception text may contain raw transport output or host paths.
        record["error"] = {"stage": stage, "type": type(error).__name__}
    record["final_session"] = deepcopy(session)
    return record


def run_flows(flows: list[dict], args) -> dict:
    """Run the exact six parent-prepared flows; caller alone grades outcomes."""
    _require(isinstance(flows, list) and len(flows) == len(FLOW_NAMES), "provide all six prepared flows")
    for flow in flows:
        _validate_flow(flow, args.raw_output_dir)
    _require({flow["flow"] for flow in flows} == FLOW_NAMES, "flow labels must be unique and exact")
    outcomes = []
    for flow in flows:
        outcome = run_flow(flow, args)
        outcomes.append(outcome)
        if outcome["status"] != "model_stopped":
            break
    return {"evidence_kind": "model_directed_github_observations", "grading": "caller_required", "flows": outcomes, "all_models_stopped": len(outcomes) == len(FLOW_NAMES) and all(item["status"] == "model_stopped" for item in outcomes)}
