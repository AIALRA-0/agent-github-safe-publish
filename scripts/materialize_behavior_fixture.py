"""Materialize a bound fixture in a dedicated, already initialized temporary repo.

Only stdlib and local Git are used. No model invocation, network transport,
checkout, worktree-file removal, credential access, or parent-module imports.

materialize(plan, work, actual_commits, env) -> bound_plan

The parent must allocate tempfile.TemporaryDirectory(prefix='gsp-behavior-eval-'),
initialize its work/.git and remote.git, prepare files/commits, and pass actual
commit OIDs for base/candidate and every other required role. Missing OIDs are
errors. The parent owns file/LFS/submodule/scanner preparation and isolation.

This helper synchronizes only refs/heads, refs/tags and local refs/remotes/origin
inside those two repositories; surplus refs in those namespaces are removed to
match the explicit plan. Objects and worktree files are never deleted. Annotated
tags are unsigned synthetic tags; cryptographic signature prerequisites remain
unsupported by the spec. No checkout is performed: the desired initial HEAD must
already equal the current work HEAD, otherwise preparation fails before writes.

After Git readback, explicit bound state is merged into .eval/remote-state.json
without removing parent control fields, read back, and validated. The returned
bound_plan is ready for the parent to save as .eval/fixture-plan.json. A failure
is an infrastructure/preparation failure, never a model pass. Cross-repository
updates are not one atomic transaction: retain a failed temporary fixture for
diagnosis instead of exposing a partially prepared fixture to the model.
"""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any

from behavior_fixture_spec import FixtureSpecError, bind_fixture_aliases, validate_materialized_fixture


_ROOT_NAME = re.compile(r"^gsp-behavior-eval-[A-Za-z0-9_-]{6,}$")
_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _fail(code: str) -> None:
    raise FixtureSpecError(["materialize:" + code])


def _reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _paths(work: Path) -> tuple[Path, Path, Path]:
    absolute = Path(os.path.abspath(work))
    # In a read-denied Linux sandbox tempfile falls back to the writable cwd.
    # The dedicated Linux launcher allocates fixtures directly under /tmp.
    temporary = Path("/tmp" if sys.platform == "linux" else tempfile.gettempdir()).resolve(strict=True)
    root = absolute.parent
    if absolute.name != "work" or root.parent.resolve(strict=True) != temporary:
        _fail("not_dedicated_temporary_fixture")
    bare = root / "remote.git"
    for path in (root, absolute, absolute / ".git", bare):
        if not path.is_dir() or _reparse(path):
            _fail("unsafe_repository_path")
    # Windows TEMP may use a user's 8.3 name while resolve() returns the long
    # name. Normalize after refusing links inside the fixture, then require the
    # same direct-root layout and unique canonical fixture name as before.
    root, absolute, bare = root.resolve(strict=True), absolute.resolve(strict=True), bare.resolve(strict=True)
    if (root.parent != temporary or not _ROOT_NAME.fullmatch(root.name)
            or absolute.parent != root or bare.parent != root
            or (absolute / ".git").resolve(strict=True).parent != absolute):
        _fail("not_dedicated_temporary_fixture")
    for git_dir in (absolute / ".git", bare):
        # A gitfile, junction, symlink, alternates or config include could escape
        # the checked root before even the first Git command.
        for directory, dirs, files in os.walk(git_dir, followlinks=False):
            for name in dirs + files:
                path = Path(directory) / name
                if _reparse(path):
                    _fail("repository_contains_reparse_point")
        for name in ("commondir", "objects/info/alternates", "objects/info/http-alternates"):
            path = git_dir / name
            if path.exists() and path.read_bytes().strip():
                _fail("external_object_or_common_directory")
        config = git_dir / "config"
        if config.exists():
            text = config.read_text(encoding="utf-8")
            if re.search(r"(?im)^\s*\[\s*(?:include|includeIf)\b", text):
                _fail("config_include_not_supported")
            if re.search(r"(?im)^\s*(?:worktree|worktreeConfig)\s*=", text):
                _fail("external_worktree_not_supported")
    eval_dir = absolute / ".eval"
    if eval_dir.exists() and (not eval_dir.is_dir() or _reparse(eval_dir)):
        _fail("unsafe_state_directory")
    state_file = eval_dir / "remote-state.json"
    if state_file.exists() and (not state_file.is_file() or _reparse(state_file)):
        _fail("unsafe_state_file")
    return absolute, root, bare


class _LocalGit:
    def __init__(self, root: Path, env: dict[str, str]):
        self.env = {k: v for k, v in env.items() if not k.upper().startswith("GIT_")}
        self.env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                         "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                         "GIT_ALLOW_PROTOCOL": "file", "GIT_LFS_SKIP_SMUDGE": "1"})
        self.root = root
        self.hooks = root / ".fixture-no-hooks"
        if self.hooks.exists():
            if not self.hooks.is_dir() or _reparse(self.hooks) or any(self.hooks.iterdir()):
                _fail("unsafe_hooks_directory")
        else:
            self.hooks.mkdir()

    def run(self, git_dir: Path, *args: str, data: bytes | None = None,
            allow_failure: bool = False) -> subprocess.CompletedProcess:
        command = ["git", "-c", f"core.hooksPath={self.hooks}", "-c", "core.fsmonitor=false",
                   "-c", "gc.auto=0", "-c", "maintenance.auto=false",
                   "-c", "protocol.allow=never", "-c", "protocol.file.allow=always",
                   "-c", "fetch.recurseSubmodules=false", "-c", "fetch.writeCommitGraph=false",
                   "-c", "tag.gpgSign=false", "--git-dir", str(git_dir), *args]
        try:
            result = subprocess.run(command, cwd=self.root, env=self.env, input=data,
                                    capture_output=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired):
            _fail("local_git_unavailable_or_timeout")
        if result.returncode != 0 and not allow_failure:
            _fail("local_git_command_failed")
        return result

    def text(self, git_dir: Path, *args: str) -> str:
        return self.run(git_dir, *args).stdout.decode("utf-8", errors="strict").strip()


def _refs(git: _LocalGit, git_dir: Path, prefix: str) -> dict[str, str]:
    text = git.text(git_dir, "for-each-ref", "--format=%(refname) %(objectname)", prefix)
    result = {}
    for line in text.splitlines():
        name, oid = line.split(" ", 1)
        if not name.startswith(prefix) or not _OID.fullmatch(oid):
            _fail("invalid_git_readback")
        result[name[len(prefix):]] = oid
    return result


def _commit_exists(git: _LocalGit, git_dir: Path, oid: str) -> bool:
    result = git.run(git_dir, "cat-file", "-t", oid, allow_failure=True)
    return result.returncode == 0 and result.stdout.strip() == b"commit"


def _transfer_commit(git: _LocalGit, source: Path, destination: Path, oid: str) -> None:
    # Both repositories have already been checked; no configured remote is used.
    git.run(destination, "fetch", "--no-tags", "--no-write-fetch-head", "--no-recurse-submodules",
            "--", str(source), oid)
    if not _commit_exists(git, destination, oid):
        _fail("commit_transfer_readback_failed")


def _sync_refs(git: _LocalGit, git_dir: Path, desired: dict[str, dict[str, str]],
               previous: dict[str, dict[str, str]] | None = None) -> None:
    lines = ["start"]
    for prefix, new in desired.items():
        old = previous[prefix] if previous is not None else _refs(git, git_dir, prefix)
        for name in sorted(set(old) | set(new)):
            if old.get(name) == new.get(name):
                continue
            if name not in new:
                lines.append(f"delete {prefix}{name} {old[name]}")
            elif name not in old:
                lines.append(f"create {prefix}{name} {new[name]}")
            else:
                lines.append(f"update {prefix}{name} {new[name]} {old[name]}")
    lines.extend(["prepare", "commit", ""])
    git.run(git_dir, "update-ref", "--no-deref", "--stdin", data="\n".join(lines).encode("utf-8"))


def _tag_objects(git: _LocalGit, git_dir: Path, tags: dict[str, str]) -> dict[str, str]:
    objects = {}
    for name, commit in tags.items():
        data = (f"object {commit}\ntype commit\ntag {name}\n"
                "tagger Synthetic Fixture <fixture@example.invalid> 0 +0000\n\n"
                f"Synthetic fixture annotated tag {name}\n").encode("utf-8")
        oid = git.run(git_dir, "mktag", data=data).stdout.decode("ascii").strip()
        if not _OID.fullmatch(oid):
            _fail("invalid_tag_object")
        objects[name] = oid
    return objects


def _peeled_tags(git: _LocalGit, git_dir: Path) -> dict[str, str]:
    result = {}
    for name, oid in _refs(git, git_dir, "refs/tags/").items():
        if git.text(git_dir, "cat-file", "-t", oid) != "tag":
            _fail("tag_is_not_annotated")
        result[name] = git.text(git_dir, "rev-parse", "--verify", f"{oid}^{{commit}}")
    return result


def apply_git_updates(work: Path | str, updates: list[dict], env: dict[str, str]) -> list[dict]:
    """Apply hook effects to the checked local bare remote, returning fixture events.

    updates is the before/after hook's git_updates list of
    {collection: branches|tags, name: str, target: commit_oid|None}.
    Capture exact old ref OIDs before mutation and use them as update-ref CAS
    preconditions. Return both ref OIDs and peeled commit targets with source
    'fixture'. The parent persists these alongside hook effects, not as model
    writes. Local branches/tags/remote-tracking refs are intentionally unchanged:
    a later model fetch must observe a remote-side change normally.
    """
    if not isinstance(updates, list):
        _fail("invalid_git_updates")
    if not updates:
        return []
    work, root, bare = _paths(Path(work))
    seen = set()
    for update in updates:
        if not isinstance(update, dict) or set(update) != {"collection", "name", "target"}:
            _fail("invalid_git_updates")
        if update["collection"] not in {"branches", "tags"} or not isinstance(update["name"], str):
            _fail("invalid_git_updates")
        if update["target"] is not None and (not isinstance(update["target"], str) or not _OID.fullmatch(update["target"])):
            _fail("invalid_git_update_target")
        identity = (update["collection"], update["name"])
        if identity in seen:
            _fail("duplicate_git_update")
        seen.add(identity)
    if not updates:
        return []
    git = _LocalGit(root, env)
    if git.text(bare, "rev-parse", "--is-bare-repository") != "true":
        _fail("remote_is_not_bare")
    prefixes = {"branches": "refs/heads/", "tags": "refs/tags/"}
    for update in updates:
        git.run(bare, "check-ref-format", prefixes[update["collection"]] + update["name"])
    old = {prefix: _refs(git, bare, prefix) for prefix in set(prefixes[u["collection"]] for u in updates)}
    desired = deepcopy(old)
    effects = []
    # Check all targets before writing refs; supplied commit OIDs are never guessed.
    for target in {u["target"] for u in updates if u["target"] is not None}:
        if not _commit_exists(git, bare, target):
            if not _commit_exists(git, work / ".git", target):
                _fail("bound_commit_does_not_exist")
            _transfer_commit(git, work / ".git", bare, target)
    for update in updates:
        collection, name, target = update["collection"], update["name"], update["target"]
        prefix = prefixes[collection]
        old_oid = old[prefix].get(name)
        old_target = (git.text(bare, "rev-parse", "--verify", f"{old_oid}^{{commit}}")
                      if old_oid is not None else None)
        if target is None:
            desired[prefix].pop(name, None)
        elif collection == "tags":
            desired[prefix][name] = _tag_objects(git, bare, {name: target})[name]
        else:
            desired[prefix][name] = target
        effects.append({"source": "fixture", "collection": collection, "name": name,
                        "before": {"ref_oid": old_oid, "target": old_target},
                        "after": {"ref_oid": desired[prefix].get(name), "target": target}})
    _sync_refs(git, bare, desired, previous=old)
    readback = {prefix: _refs(git, bare, prefix) for prefix in desired}
    for effect in effects:
        prefix, name = prefixes[effect["collection"]], effect["name"]
        oid = readback[prefix].get(name)
        if oid != effect["after"]["ref_oid"]:
            _fail("hook_ref_readback_mismatch")
        if oid is not None:
            if git.text(bare, "rev-parse", "--verify", f"{oid}^{{commit}}") != effect["after"]["target"]:
                _fail("hook_target_readback_mismatch")
            if effect["collection"] == "tags" and git.text(bare, "cat-file", "-t", oid) != "tag":
                _fail("tag_is_not_annotated")
    return effects


def materialize(plan: dict, work: Path | str, actual_commits: dict[str, str], env: dict[str, str]) -> dict:
    """Bind, materialize and verify only a dedicated temporary fixture."""
    # Validation and binding precede all writes, including creating helper dirs.
    work, root, bare = _paths(Path(work))
    bound = bind_fixture_aliases(plan, actual_commits)
    git_dir = work / ".git"
    git = _LocalGit(root, env)
    if git.text(git_dir, "rev-parse", "--is-bare-repository") != "false":
        _fail("work_is_bare")
    if git.text(bare, "rev-parse", "--is-bare-repository") != "true":
        _fail("remote_is_not_bare")
    for prefix, refs in (("refs/heads/", bound["local_branches"]),
                         ("refs/tags/", bound.get("local_tags", {})),
                         ("refs/heads/", bound["state"]["branches"]),
                         ("refs/tags/", bound["state"]["tags"])):
        for name in refs:
            git.run(git_dir, "check-ref-format", prefix + name)
    current = bound["setup"].get("current_branch", "main")
    desired_head = (actual_commits["candidate"] if bound["setup"].get("detached_head")
                    else bound["local_branches"][current])
    if git.text(git_dir, "rev-parse", "--verify", "HEAD^{commit}") != desired_head:
        _fail("head_requires_parent_preparation")
    locations = {}
    for role in bound["required_bindings"]:
        oid = actual_commits[role]
        locations[oid] = (_commit_exists(git, git_dir, oid), _commit_exists(git, bare, oid))
        if not any(locations[oid]):
            _fail("bound_commit_does_not_exist")
    state_file = work / ".eval" / "remote-state.json"
    prior_state: dict[str, Any] = {}
    if state_file.exists():
        try:
            prior_state = json.loads(state_file.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            _fail("invalid_existing_state")
        if not isinstance(prior_state, dict):
            _fail("invalid_existing_state")
    for oid, (in_work, in_remote) in locations.items():
        if not in_work:
            _transfer_commit(git, bare, git_dir, oid)
        if not in_remote:
            _transfer_commit(git, git_dir, bare, oid)
    tags = bound["state"]["tags"]
    local_targets = bound.get("local_tags", tags)
    local_tags = _tag_objects(git, git_dir, local_targets)
    remote_tags = _tag_objects(git, bare, tags)
    branches = bound["state"]["branches"]
    _sync_refs(git, bare, {"refs/heads/": branches, "refs/tags/": remote_tags})
    # Detach temporarily so deleting/renaming an initial branch cannot leave HEAD
    # dangling. Updating HEAD here does not check out or delete any worktree file.
    git.run(git_dir, "update-ref", "--no-deref", "HEAD", desired_head)
    _sync_refs(git, git_dir, {"refs/heads/": bound["local_branches"], "refs/tags/": local_tags,
                            "refs/remotes/origin/": branches})
    if not bound["setup"].get("detached_head"):
        git.run(git_dir, "symbolic-ref", "HEAD", f"refs/heads/{current}")
    if "main" in branches:
        git.run(bare, "symbolic-ref", "HEAD", "refs/heads/main")
    # Verify Git before installing state used by the controller.
    facts = {"state": deepcopy(bound["state"]),
             "local_branches": _refs(git, git_dir, "refs/heads/"),
             "local_tags": _peeled_tags(git, git_dir),
             "remote_branches": _refs(git, bare, "refs/heads/"),
             "remote_tags": _peeled_tags(git, bare)}
    if facts["local_tags"] != local_targets:
        _fail("local_tag_readback_mismatch")
    if _refs(git, git_dir, "refs/remotes/origin/") != branches:
        _fail("remote_tracking_readback_mismatch")
    symbolic = git.run(git_dir, "symbolic-ref", "--quiet", "--short", "HEAD", allow_failure=True)
    if symbolic.returncode not in {0, 1}:
        _fail("head_readback_failed")
    facts["detached"] = symbolic.returncode == 1
    facts["current_branch"] = None if facts["detached"] else symbolic.stdout.decode("utf-8").strip()
    errors = validate_materialized_fixture(bound, facts)
    if errors:
        raise FixtureSpecError(errors)
    prior_state.update(deepcopy(bound["state"]))
    state_file.parent.mkdir(exist_ok=True)
    # No arbitrary temporary file cleanup: all writes stay in this checked state
    # directory, and a failed replacement is retained for diagnosis.
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=state_file.parent,
                                     prefix="fixture-state-", suffix=".tmp", delete=False) as stream:
        json.dump(prior_state, stream, ensure_ascii=False, allow_nan=False, indent=2)
        stream.write("\n")
        temporary_state = stream.name
    os.replace(temporary_state, state_file)
    facts["state"] = json.loads(state_file.read_text(encoding="utf-8"))
    errors = validate_materialized_fixture(bound, facts)
    if errors:
        raise FixtureSpecError(errors)
    return bound
