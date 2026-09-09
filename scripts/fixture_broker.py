"""Private, serial Linux filesystem broker for synthetic publication EVALS ONLY.

Parent API / launch (no model call or GitHub connection):
    python -I /repo/scripts/fixture_broker.py --work FIXTURE/work
        --bare FIXTURE/remote.git --private /private/PER_RUN
        --spool FIXTURE/work/.eval/broker-io [--ready-file /private/PER_RUN/ready.json]
    Add --snapshot-only to print a parent-only full grading snapshot and exit.
    Or --snapshot-evidence to print {grading_state, attribution_snapshot}, with
    attribution_snapshot={state (retaining fixture_events), git (actual refs)}.

The parent prepares private/remote-state.json and private/fixture-plan.json,
removes their model-tree copies, and stages fixture_broker_client.py as
work/.eval/fixture_control.py. Wait for private/ready.json, then run the model.
To finish, the parent creates private/stop-requested.json, waits for successful
server exit, then calls validate_terminal_records(private) before snapshots.
The server finishes its current synchronous request and writes stopped.json;
that marker proves quiescence, not successful custody. There is no shutdown RPC.
FixtureBroker(work=..., bare=..., private=..., spool_path=...).serve() is the
equivalent API (spool_path=...), but cwd MUST already be work. Only CLI main
changes cwd, once. Neither snapshot nor shutdown is an RPC operation.

The parent MUST isolate this process without host/CLI/GitHub credentials; make
the fixed bare repository model-read-only and broker-writable; protect /repo
code and /private from model reads/writes; serialize other parent bare writers.
Path checks do NOT establish these mount/permission boundaries. No global
interceptor, sandbox setup, authentication access, or production Skill gate.

Untrusted requests contain ONLY {version:1, argv:[controller argument strings]}.
The controller owns operation authorization. The broker rejects --state, option
abbreviations, extra fields, executable strings and unsupported arguments.
There are no payload-file options: asset-upload uses size/sha256 metadata only.

Model Git config is never executed. Each request uses a private config-free
source Git view, with no-follow bounded copies of object/ref data. Source
includes, alternates, gitfiles and symlinks are rejected. Git only contacts the
fixed parent-owned local bare repository, never a configured remote. Controller
callbacks are git_runner, git_updates, observer; see _execute_bound.

Spool files are <32 lowercase hex>.request.json / .response.json. Client polling
has a maximum ten-second deadline and no automatic replay; server polls this
one directory at 20ms until the parent requests stop. No socket or
network permission is used. Request IDs are consumed durably before dispatch.
Client replies are writable by the model and are NOT trusted evidence.

Private evidence: checkpoints.jsonl is fsynced at every observer phase;
observations.jsonl records each complete four-window observation + CAS receipts
before the delivered reply. requests.jsonl retains complete/incomplete request
status. These files are parent evidence, never model-visible responses. An
incomplete record is not a successful attribution result.
"""

from __future__ import annotations

import argparse
import configparser
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time

# -I deliberately ignores cwd/PYTHONPATH. Only the parent-owned code directory
# is added; never import code from the model worktree.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import eval_fixture_control as controller
from fixture_broker_client import MAX_REPLY, MAX_REQUEST

OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9_][A-Za-z0-9_./-]*\Z")
OPTIONS = {
    "inspect": set(), "protection-read": set(),
    "branch-read": {"--branch"}, "branch-push": {"--branch", "--commit"},
    "tag-read": {"--tag"}, "tag-create": {"--tag", "--commit"},
    "release-read": {"--tag"},
    "release-create": {"--tag", "--title", "--body"},
    "release-update": {"--tag", "--title", "--body"},
    "asset-read": {"--name", "--tag"},
    "asset-upload": {"--name", "--tag", "--size", "--sha256"},
    "pr-read": {"--number"}, "pr-create": {"--number", "--head", "--base", "--title", "--body"},
    "pr-update": {"--number", "--title", "--body"}, "pr-merge": {"--number"},
    "metadata-update": {"--name", "--value"}, "rules-update": {"--name", "--value"},
    "credential-update": {"--name", "--value"}, "remote-delete": {"--name"},
}


def require(condition, message="invalid_fixture_request"):
    if not condition:
        raise ValueError(message)


def valid_ref(value):
    return bool(REF.fullmatch(value)) and ".." not in value and "//" not in value and all(
        not part.startswith(".") and not part.endswith((".", ".lock")) for part in value.split("/"))


def revision(value):
    base = value.removesuffix("^{commit}")
    return base == "HEAD" or bool(OID.fullmatch(base)) or valid_ref(base)


def parse_request(payload, state_path):
    require(isinstance(payload, dict) and set(payload) == {"version", "argv"})
    require(type(payload["version"]) is int and payload["version"] == 1)
    argv = payload["argv"]
    require(isinstance(argv, list) and 1 <= len(argv) <= 33
            and all(isinstance(arg, str) and "\x00" not in arg and len(arg) <= 16384 for arg in argv))
    if argv == ["--help"]:
        return None
    require(argv[0] in OPTIONS)
    seen = set()
    index = 1
    while index < len(argv):
        flag, separator, _ = argv[index].partition("=")
        require(flag in OPTIONS[argv[0]] and flag not in seen)
        seen.add(flag)
        index += 1
        if not separator:
            require(index < len(argv) and not argv[index].startswith("--"))
            index += 1
    parser = controller.build_parser()
    parser.allow_abbrev = False
    def fail(_message):
        raise ValueError("invalid_controller_arguments")
    parser.error = fail
    args = parser.parse_args(argv)
    args.state = state_path
    for field, prefix in (("branch", "heads"), ("head", "heads"), ("base", "heads"), ("tag", "tags")):
        require(valid_ref(f"refs/{prefix}/{getattr(args, field)}"))
    if args.commit is not None:
        require(revision(args.commit))
    require(type(args.size) is int and args.size >= 0 and bool(re.fullmatch(r"[0-9a-f]{64}", args.sha256)))
    return args


def safe_environment():
    """Build, never filter, the environment; inherit no credentials/config."""
    return {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "XDG_CONFIG_HOME": "/nonexistent",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "file", "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_LFS_SKIP_SMUDGE": "1", "PYTHONDONTWRITEBYTECODE": "1"}


def open_directory(path):
    """Walk absolute paths with dirfds; never follow a model-swapped link."""
    path = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_file(fd, name, budget):
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        info = os.fstat(child)
        require(stat.S_ISREG(info.st_mode), "nonregular_git_input")
        require(info.st_size <= budget[0], "git_input_too_large")
        with os.fdopen(child, "rb", closefd=False) as stream:
            data = stream.read(budget[0] + 1)
        budget[0] -= len(data)
        budget[1] -= 1
        require(budget[0] >= 0 and budget[1] >= 0, "git_input_too_large")
        return data
    finally:
        os.close(child)


def copy_tree(fd, destination, budget, depth=0):
    require(depth < 32, "git_input_too_deep")
    for name in os.listdir(fd):
        budget[1] -= 1
        require(budget[1] >= 0, "git_input_too_large")
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(not stat.S_ISLNK(info.st_mode), "symlink_git_input")
        target = destination / name
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                target.mkdir(exist_ok=True)
                copy_tree(child, target, budget, depth + 1)
            finally:
                os.close(child)
        else:
            data = read_file(fd, name, budget)
            if target.exists():
                require(target.read_bytes() == data, "conflicting_git_objects")
            else:
                target.write_bytes(data)


def import_git(source, view, budget, *, objects_only=False):
    fd = open_directory(source)
    try:
        names = set(os.listdir(fd))
        require(not names & {"commondir", "gitdir", "config.worktree"}, "unsupported_git_layout")
        if "config" in names:
            config = read_file(fd, "config", budget).decode("utf-8")
            require(not re.search(r"(?im)^\s*\[\s*(?:include|includeIf)\b", config), "git_config_include")
        for name in ("objects",) if objects_only else ("HEAD", "refs", "packed-refs", "index", "shallow", "objects"):
            if name not in names:
                continue
            if name in {"objects", "refs"}:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if name == "objects" and "info" in os.listdir(child):
                        info = os.open("info", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=child)
                        try:
                            require(not set(os.listdir(info)) & {"alternates", "http-alternates"}, "git_alternates")
                        finally:
                            os.close(info)
                    (view / name).mkdir(exist_ok=True)
                    copy_tree(child, view / name, budget)
                finally:
                    os.close(child)
            else:
                data = read_file(fd, name, budget)
                if name == "HEAD":
                    value = data.decode("ascii").strip()
                    require(bool(OID.fullmatch(value)) or
                            (value.startswith("ref: ") and valid_ref(value[5:])), "invalid_git_head")
                (view / name).write_bytes(data)
    finally:
        os.close(fd)


class SafeGit:
    """Finite controller Git operations, private source view + fixed bare only."""
    def __init__(self, work, bare, private, executable="/usr/bin/git"):
        self.work, self.bare, self.private = work, bare, private
        self.executable = executable
        self.temporary = tempfile.TemporaryDirectory(prefix="git-view-", dir=private)
        self.view = Path(self.temporary.name)
        try:
            (self.view / "config").write_text("[core]\n bare = true\n", encoding="ascii")
            budget = [256 * 1024 * 1024, 20000]
            import_git(work / ".git", self.view, budget)
            import_git(bare, self.view, budget, objects_only=True)
            # Final check on the immutable private copy closes the race between
            # checking public objects/info and copying that directory.
            require(not any((self.view / "objects" / "info" / name).exists()
                            for name in ("alternates", "http-alternates")), "git_alternates")
            require((self.view / "HEAD").is_file(), "missing_git_head")
            fd = open_directory(work / ".git")
            try:
                source_config = read_file(fd, "config", budget).decode("utf-8")
            finally:
                os.close(fd)
            require(not re.search(r"(?im)^\s*\[\s*(?:include|includeIf)\b", source_config), "git_config_include")
            config = configparser.RawConfigParser(strict=True, allow_no_value=True)
            config.read_string(source_config)
            self.remote_url = config.get('remote "origin"', 'url', fallback=None)
            if self.remote_url and self.remote_url.startswith('"') and self.remote_url.endswith('"'):
                self.remote_url = self.remote_url[1:-1]
        except BaseException:
            self.close()
            raise

    def close(self):
        self.temporary.cleanup()

    def run(self, git_dir, *args, data=None):
        require(git_dir in {self.view, self.bare}, "unknown_git_repository")
        options = ["core.hooksPath=/dev/null", "core.fsmonitor=false", "gc.auto=0",
                   "maintenance.auto=false", "protocol.allow=never", "protocol.file.allow=always",
                   "fetch.recurseSubmodules=false", "push.recurseSubmodules=no",
                   "tag.gpgSign=false", "commit.gpgSign=false", "credential.helper=",
                   "user.name=Synthetic Fixture", "user.email=fixture@example.invalid"]
        command = [self.executable]
        for option in options:
            command += ["-c", option]
        command += ["--git-dir", str(git_dir)]
        if git_dir == self.view:
            command += ["--work-tree", str(self.work)]
        return subprocess.run(command + list(args), cwd=self.work,
                              env=safe_environment(), input=data, capture_output=True,
                              text=True, encoding="utf-8", timeout=30, check=False)

    def checked(self, git_dir, *args, data=None):
        result = self.run(git_dir, *args, data=data)
        require(result.returncode == 0, "trusted_git_operation_failed")
        return result.stdout.strip()

    def __call__(self, *args):
        valid = False
        if args[:1] == ("rev-parse",):
            values = args[2:] if args[1:2] == ("--verify",) else args[1:]
            valid = len(values) == 1 and revision(values[0])
        elif args[:2] == ("merge-base", "--is-ancestor"):
            valid = len(args) == 4 and all(revision(value) for value in args[2:])
        elif args[:3] == ("show-ref", "--verify", "--quiet"):
            valid = len(args) == 4 and args[3].startswith("refs/tags/") and valid_ref(args[3])
        elif args[:2] == ("cat-file", "-t"):
            valid = len(args) == 3 and args[2].startswith("refs/tags/") and valid_ref(args[2])
        elif args[:1] == ("check-ref-format",):
            valid = (len(args) == 2 and valid_ref(args[1])) or (
                len(args) == 3 and args[1] == "--branch" and valid_ref("refs/heads/" + args[2]))
        elif args[:2] == ("tag", "-a"):
            valid = (len(args) == 6 and valid_ref("refs/tags/" + args[2])
                     and revision(args[3]) and args[4] == "-m")
        elif args == ("remote", "get-url", "origin"):
            return subprocess.CompletedProcess(args, 0 if self.remote_url else 2,
                                               (self.remote_url or "") + "\n", "")
        elif args[:2] == ("push", "origin") and len(args) == 3:
            source, separator, target = args[2].partition(":")
            require(separator and revision(source) and valid_ref(target), "invalid_push_refspec")
            require(self.remote_matches(), "source_remote_changed")
            # Every byte of receive-pack is trusted constant code, never argv
            # from the client. Git's receiving side must also suppress hooks.
            receiver = "/usr/bin/git -c core.hooksPath=/dev/null -c core.fsmonitor=false -c receive.autogc=false receive-pack"
            return self.run(self.view, "push", "--no-verify", "--receive-pack=" + receiver,
                            "--", str(self.bare), args[2])
        require(valid, "unsupported_controller_git_command")
        return self.run(self.view, *args)

    def remote_matches(self):
        # Compare as data only. No URL transport, include expansion, credential
        # helper, symlink traversal, or Git remote rewriting is invoked here.
        return bool(self.remote_url) and os.path.normpath(
            os.path.join(str(self.work), self.remote_url)) == str(self.bare)

    def grading_snapshot(self, state, refs=None):
        result = deepcopy(state)
        result.pop("fixture_runtime", None)
        result.pop("fixture_events", None)
        refs = self.refs() if refs is None else refs
        for collection in ("branches", "tags"):
            result["actual_git_" + collection] = {name: ref["ref_oid"] for name, ref in refs[collection].items()}
        symbolic = self.run(self.view, "symbolic-ref", "--quiet", "--short", "HEAD")
        require(symbolic.returncode in (0, 1), "invalid_symbolic_head")
        status = self.run(self.view, "status", "--porcelain=v1", "--untracked-files=all")
        require(status.returncode == 0, "git_status_failed")
        result["local_git"] = {
            "head": self.checked(self.view, "rev-parse", "HEAD"),
            "head_files": self.checked(self.view, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD").splitlines(),
            "branch": symbolic.stdout.strip() if symbolic.returncode == 0 else None,
            "detached": symbolic.returncode == 1,
            "status": status.stdout.splitlines(),
            "remote_url": self.remote_url,
            "remote_url_changed": not self.remote_matches(),
            "shallow": (self.view / "shallow").exists(),
        }
        return result

    def refs(self):
        result = {"branches": {}, "tags": {}}
        text = self.checked(self.bare, "for-each-ref", "--format=%(refname) %(objectname)",
                            "refs/heads/", "refs/tags/")
        for line in text.splitlines():
            ref, oid = line.split()
            require(valid_ref(ref) and OID.fullmatch(oid), "invalid_remote_ref")
            collection = "branches" if ref.startswith("refs/heads/") else "tags"
            target = self.checked(self.bare, "rev-parse", "--verify", oid + "^{commit}")
            require(OID.fullmatch(target), "invalid_remote_target")
            result[collection][ref.split("/", 2)[2]] = {"ref_oid": oid, "target": target}
        return result

    def apply_updates(self, work, updates, env):
        require(work == self.work and isinstance(updates, list), "invalid_hook_updates")
        before = self.refs()
        receipts, commands, seen = [], ["start"], set()
        for update in updates:
            require(set(update) == {"collection", "name", "target"}, "invalid_hook_update")
            collection, name, target = (update[key] for key in ("collection", "name", "target"))
            require(collection in {"branches", "tags"}, "invalid_hook_collection")
            ref = ("refs/heads/" if collection == "branches" else "refs/tags/") + name
            require(valid_ref(ref) and ref not in seen and (target is None or OID.fullmatch(target)), "invalid_hook_target")
            seen.add(ref)
            old = before[collection].get(name, {"ref_oid": None, "target": None})
            oid = target
            if target is not None:
                # All bound commits must have been materialized in the fixed
                # bare repository by the parent, before the model starts.
                require(self.checked(self.bare, "cat-file", "-t", target) == "commit", "missing_bound_commit")
                if collection == "tags":
                    text = f"object {target}\ntype commit\ntag {name}\ntagger Synthetic Fixture <fixture@example.invalid> 0 +0000\n\nSynthetic fixture tag\n"
                    oid = self.checked(self.bare, "mktag", data=text)
                commands.append(f"update {ref} {oid} {old['ref_oid'] or '0' * len(oid)}")
            elif old["ref_oid"] is not None:
                commands.append(f"delete {ref} {old['ref_oid']}")
            receipts.append({"source": "fixture", "collection": collection, "name": name,
                             "before": old, "after": {"ref_oid": oid, "target": target}})
        if updates:
            self.checked(self.bare, "update-ref", "--no-deref", "--stdin",
                         data="\n".join(commands + ["prepare", "commit", ""]))
            after = self.refs()
            for receipt in receipts:
                actual = after[receipt["collection"]].get(receipt["name"], {"ref_oid": None, "target": None})
                require(actual == receipt["after"], "hook_readback_mismatch")
        return receipts


class FixtureBroker:
    def __init__(self, *, work, bare, private, spool_path):
        require(sys.platform == "linux", "linux_filesystem_broker_required")
        self.work, self.bare, self.private = (Path(os.path.abspath(p)) for p in (work, bare, private))
        self.spool_path = Path(os.path.abspath(spool_path))
        require(self.bare == self.work.parent / "remote.git" and self.work.name == "work", "invalid_fixture_layout")
        require(not self.private.is_relative_to(self.work.parent)
                and not self.work.parent.is_relative_to(self.private), "private_controls_overlap_fixture")
        require(self.spool_path == self.work / ".eval" / "broker-io", "invalid_spool_location")
        for path in (self.work, self.bare, self.private, self.spool_path.parent):
            os.close(open_directory(path))
        self.state = self.private / "remote-state.json"
        self.plan = self.private / "fixture-plan.json"
        require(self.state.is_file() and self.plan.is_file() and not self.state.is_symlink()
                and not self.plan.is_symlink(), "missing_private_controls")
        self.sequence = 0

    def journal(self, name, value):
        with (self.private / name).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def dispatch(self, payload, *, message_id):
        require(Path.cwd() == self.work, "broker_cwd_must_be_work")
        self.sequence += 1
        sequence = self.sequence
        observation = {"git_cas": {"before": [], "after": []}}
        safe = None
        try:
            args = parse_request(payload, self.state)
            if args is None:
                # Help contains only interface syntax, never state/plan contents.
                self.journal("requests.jsonl", {"sequence": sequence, "message_id": message_id,
                    "argv": payload["argv"], "complete": True, "observable": False, "exit_code": 0})
                return {"version": 1, "exit_code": 0, "output": {"operations": {
                    operation: sorted(options) for operation, options in OPTIONS.items()}}}
            safe = SafeGit(self.work, self.bare, self.private)
            def observe(phase, state, receipts):
                require(phase in {"before", "before_backend", "after_backend", "after"}
                        and phase not in observation, "invalid_observer_phase")
                checkpoint = {"state": deepcopy(state), "git": safe.refs()}
                observation[phase] = checkpoint
                if phase in {"before_backend", "after"}:
                    observation["git_cas"]["before" if phase == "before_backend" else "after"] = deepcopy(receipts)
                self.journal("checkpoints.jsonl", {"sequence": sequence, "phase": phase,
                                                  "message_id": message_id, "snapshot": checkpoint, "git_receipts": receipts})
            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = controller._execute_bound(args, self.plan, observer=observe,
                    git_runner=safe, git_updates=safe.apply_updates)
            require(set(observation) == {"before", "before_backend", "after_backend", "after", "git_cas"}, "incomplete_observation")
            delivered = json.loads(output.getvalue())
            self.journal("observations.jsonl", {"sequence": sequence, "message_id": message_id, "observation": observation})
            self.journal("requests.jsonl", {"sequence": sequence, "message_id": message_id, "argv": payload["argv"],
                                           "complete": True, "observable": True, "exit_code": exit_code})
            return {"version": 1, "exit_code": exit_code, "output": delivered}
        except (OSError, ValueError, RuntimeError, configparser.Error, subprocess.SubprocessError) as error:
            self.journal("requests.jsonl", {"sequence": sequence, "message_id": message_id, "complete": False,
                                           "error_type": type(error).__name__})
            return {"version": 1, "exit_code": 2, "output": {"error": "fixture_broker_rejected_or_incomplete"}}
        finally:
            if safe is not None:
                safe.close()

    def snapshot(self, *, evidence=False):
        """Parent-only API, never an RPC operation; no journal mutation."""
        safe = SafeGit(self.work, self.bare, self.private)
        try:
            state = controller._read(self.state)
            refs = safe.refs()
            grading = safe.grading_snapshot(state, refs)
            if not evidence:
                return grading
            attribution_state = deepcopy(state)
            attribution_state.pop("fixture_runtime", None)
            return {"grading_state": grading, "attribution_snapshot": {"state": attribution_state, "git": refs}}
        finally:
            safe.close()

    def serve(self, *, max_requests=None, ready_file=None):
        # Serial by design: no global cwd changes or observer cross-talk between
        # request threads. No recursive cleanup of model-controlled paths.
        ready_file = Path(ready_file) if ready_file is not None else self.private / "ready.json"
        require(ready_file.parent == self.private and not ready_file.exists(), "invalid_ready_file")
        self.spool_path.mkdir(exist_ok=True)
        directory = open_directory(self.spool_path)
        accepted = self.private / "accepted"
        accepted.mkdir()  # Reusing a prior broker session requires parent reconciliation.
        stop = self.private / "stop-requested.json"
        stopped = self.private / "stopped.json"
        require(not stopped.exists(), "stale_stopped_marker")
        parent_stop = False
        try:
            with ready_file.open("x", encoding="utf-8") as stream:
                json.dump({"version": 1, "pid": os.getpid(), "transport": "filesystem"}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            count = 0
            seen = set()
            while max_requests is None or count < max_requests:
                if stop.exists():
                    parent_stop = True
                    break
                for name in os.listdir(directory):
                    match = re.fullmatch(r"([0-9a-f]{32})\.request\.json", name)
                    if not match or match[1] in seen:
                        continue
                    # Only the isolated parent can signal stop. Dispatch and
                    # reply delivery are synchronous; never interrupt a write.
                    if stop.exists():
                        parent_stop = True
                        break
                    identifier = match[1]
                    seen.add(identifier)
                    count += 1
                    # Private O_EXCL claim precedes reading or executing any
                    # model request. Even a crash cannot make it replayable.
                    claim = os.open(accepted / identifier, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    os.fsync(claim)
                    os.close(claim)
                    try:
                        payload = read_file(directory, name, [MAX_REQUEST, 1])
                        response = self.dispatch(strict_json(payload), message_id=identifier)
                    except (OSError, ValueError):
                        self.journal("requests.jsonl", {"message_id": identifier, "complete": False,
                                                       "error_type": "invalid_request_frame"})
                        response = {"version": 1, "exit_code": 2, "output": {"error": "fixture_broker_protocol_error"}}
                    encoded = json.dumps(response, ensure_ascii=False).encode() + b"\n"
                    if len(encoded) > MAX_REPLY:
                        encoded = b'{"version":1,"exit_code":2,"output":{"error":"fixture_broker_reply_too_large"}}\n'
                    temporary = "." + identifier + "." + secrets.token_hex(8) + ".reply.tmp"
                    try:
                        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(encoded)
                            stream.flush()
                            os.fsync(stream.fileno())
                        # Replace the directory entry itself, never follow a
                        # model-created response symlink to a private file.
                        os.replace(temporary, identifier + ".response.json", src_dir_fd=directory, dst_dir_fd=directory)
                    except OSError:
                        self.journal("requests.jsonl", {"message_id": identifier, "reply_delivery": "failed"})
                    if max_requests is not None and count >= max_requests:
                        break
                if parent_stop:
                    break
                time.sleep(0.02)
        finally:
            os.close(directory)
        # Not in finally: an exception or forced termination must not look like
        # an acknowledged stop. No dispatch/Git child is pending on this path.
        if parent_stop:
            with stopped.open("x", encoding="utf-8") as stream:
                json.dump({"version": 1, "reason": "parent_stop", "accepted_count": count}, stream)
                stream.flush()
                os.fsync(stream.fileno())


def validate_terminal_records(private: Path) -> dict:
    """Parent-only, after successful server exit; raise on incomplete custody.

    This finite journal check does not replace plan/CAS attribution replay or
    establish process exit itself. Model-writable replies are never consulted.
    """
    private = Path(private)
    def rows(name):
        path = private / name
        return [strict_json(line) for line in path.read_text().splitlines()] if path.exists() else []

    try:
        require((private / "stop-requested.json").is_file(), "stop_not_requested")
        stopped = strict_json((private / "stopped.json").read_text())
        claims = list((private / "accepted").iterdir())
        require(all(re.fullmatch(r"[0-9a-f]{32}", p.name) and p.is_file()
                    and not p.is_symlink() for p in claims), "invalid_accepted_records")
        accepted = {p.name for p in claims}
        require(stopped == {"version": 1, "reason": "parent_stop", "accepted_count": len(accepted)},
                "invalid_stopped_marker")
        require(not (private / "remote-state.lock").exists(), "operation_lock_pending")
        runtime = strict_json((private / "remote-state.json").read_text())["fixture_runtime"]
        require(runtime.get("pending") is None and not runtime.get("errors")
                and not runtime.get("pending_git_updates"), "unfinished_or_failed_runtime")
        terminal = {}
        for row in rows("requests.jsonl"):
            identifier = row["message_id"]
            require(identifier in accepted, "unaccepted_request_record")
            if "reply_delivery" in row:
                require(set(row) == {"message_id", "reply_delivery"}
                        and row["reply_delivery"] == "failed", "invalid_delivery_record")
                continue  # Failed delivery cannot erase a completed backend.
            require(identifier not in terminal and row.get("complete") is True,
                    "incomplete_or_duplicate_request")
            require(type(row.get("observable")) is bool and type(row.get("exit_code")) is int,
                    "invalid_terminal_request")
            terminal[identifier] = row
        require(set(terminal) == accepted, "missing_terminal_request")
        require([row["sequence"] for row in terminal.values()] == list(range(1, len(accepted) + 1)),
                "terminal_sequence_mismatch")
        observable = []
        for row in terminal.values():
            args = parse_request({"version": 1, "argv": row["argv"]}, private / "remote-state.json")
            require(row["observable"] == (args is not None), "terminal_observable_mismatch")
            if row["observable"]:
                observable.append(row)
            else:
                require(row["exit_code"] == 0, "invalid_help_terminal")
        observations, checkpoints = rows("observations.jsonl"), rows("checkpoints.jsonl")
        require(len(observations) == len(observable) == len(runtime["events"]),
                "terminal_observation_count")
        expected_checkpoints = []
        for row, observed, event in zip(observable, observations, runtime["events"]):
            require(observed["message_id"] == row["message_id"]
                    and observed["sequence"] == row["sequence"], "terminal_observation_identity")
            observation = observed["observation"]
            require(set(observation) == {"before", "before_backend", "after_backend", "after", "git_cas"},
                    "incomplete_observation")
            require(event["git_effects"] == observation["git_cas"], "terminal_receipt_mismatch")
            for phase in ("before", "before_backend", "after_backend", "after"):
                receipts = observation["git_cas"]["before" if phase == "before_backend" else "after"] \
                    if phase in {"before_backend", "after"} else []
                expected_checkpoints.append({"sequence": row["sequence"], "message_id": row["message_id"],
                    "phase": phase, "snapshot": observation[phase], "git_receipts": receipts})
        require(checkpoints == expected_checkpoints, "terminal_checkpoint_mismatch")
        return {"version": 1, "status": "quiescent", "accepted": len(accepted), "observable": len(observable)}
    except (OSError, KeyError, TypeError, AttributeError) as error:
        raise ValueError("missing_or_malformed_terminal_records") from error


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def invalid(_value):
        raise ValueError("invalid_json_constant")
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    for option in ("work", "bare", "private", "spool"):
        parser.add_argument("--" + option, type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--snapshot-only", action="store_true")
    mode.add_argument("--snapshot-evidence", action="store_true")
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args(argv)
    broker = FixtureBroker(work=args.work, bare=args.bare, private=args.private, spool_path=args.spool)
    os.environ.clear()
    os.environ.update(safe_environment())
    os.chdir(broker.work)  # Dedicated server process only; never in dispatch.
    if args.snapshot_only or args.snapshot_evidence:
        print(json.dumps(broker.snapshot(evidence=args.snapshot_evidence), ensure_ascii=False))
    else:
        broker.serve(ready_file=args.ready_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
