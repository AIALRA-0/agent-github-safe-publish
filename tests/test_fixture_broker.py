"""Synthetic Linux broker tests: no models, credentials, or network Git."""

from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from fixture_broker import (
    FixtureBroker, SafeGit, parse_request, safe_environment, strict_json, validate_terminal_records,
)
from fixture_broker_client import request
from behavior_fixture_spec import prepare_fixture_spec, bind_fixture_aliases, new_fixture_runtime
from fixture_event_attribution import attribute_fixture_events

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


class ProtocolTests(unittest.TestCase):
    def test_closed_argv_only_and_no_file_reads(self):
        for payload in (
            {"version": 1, "argv": ["inspect", "--state", "/private/other.json"]},
            {"version": 1, "argv": ["inspect", "--sta=/private/other.json"]},
            {"version": 1, "argv": ["asset-upload", "--file", "/private/secret"]},
            {"version": 1, "argv": ["bash", "-c", "git push"]},
            {"version": 1, "argv": "inspect"},
            {"version": True, "argv": ["inspect"]},
            {"version": 1, "argv": ["inspect"], "state": "anything"},
            {"version": 1, "argv": ["branch-push", "--commit=--exec=anything"]},
            {"version": 1, "argv": ["branch-push", "--branch", "../other"]},
            {"version": 1, "argv": ["asset-upload", "--size", "-1"]},
            {"version": 1, "argv": ["inspect; echo injected"]},
            {"version": 1, "argv": ["--snapshot-evidence"]},
            {"version": 1, "argv": ["stop"]},
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                parse_request(payload, Path("/private/state.json"))
        args = parse_request({"version": 1, "argv": ["release-create", "--body", "literal ; $(text)"]}, Path("/private/state.json"))
        self.assertEqual(args.body, "literal ; $(text)")
        self.assertEqual(args.state, Path("/private/state.json"))

    def test_environment_is_not_inherited(self):
        with patch.dict(os.environ, {"GH_TOKEN": "synthetic", "BASH_ENV": "synthetic", "GIT_CONFIG_COUNT": "1", "LD_PRELOAD": "synthetic"}):
            env = safe_environment()
        self.assertFalse(set(env) & {"GH_TOKEN", "BASH_ENV", "GIT_CONFIG_COUNT", "LD_PRELOAD"})
        self.assertEqual(env["GIT_ALLOW_PROTOCOL"], "file")

    def test_duplicate_keys_and_nonjson_numbers_are_rejected(self):
        for payload in ('{"version":1,"argv":["inspect"],"argv":["branch-push"]}',
                        '{"version":NaN,"argv":["inspect"]}'):
            with self.assertRaises(ValueError):
                strict_json(payload)


@unittest.skipUnless(sys.platform == "linux", "Linux no-follow filesystem broker")
class BrokerTests(unittest.TestCase):
    def setUp(self):
        fixture = tempfile.TemporaryDirectory(prefix="gsp-behavior-eval-")
        private = tempfile.TemporaryDirectory(prefix="gsp-private-")
        self.addCleanup(private.cleanup)
        self.addCleanup(fixture.cleanup)
        self.root, self.private = Path(fixture.name), Path(private.name)
        self.work, self.bare = self.root / "work", self.root / "remote.git"
        self.work.mkdir()
        (self.work / ".eval").mkdir()
        self.git("init", "--initial-branch=main", str(self.work))
        self.git("init", "--bare", str(self.bare))
        self.git("-C", str(self.work), "config", "user.name", "Synthetic Fixture")
        self.git("-C", str(self.work), "config", "user.email", "fixture@example.invalid")
        self.git("-C", str(self.work), "remote", "add", "origin", str(self.bare))
        (self.work / "candidate.txt").write_text("base\n")
        self.git("-C", str(self.work), "add", "candidate.txt")
        self.git("-C", str(self.work), "commit", "-m", "base")
        self.base = self.git("-C", str(self.work), "rev-parse", "HEAD")
        self.git("-C", str(self.work), "push", "origin", "main")
        (self.work / "candidate.txt").write_text("candidate\n")
        self.git("-C", str(self.work), "commit", "-am", "candidate")
        self.candidate = self.git("-C", str(self.work), "rev-parse", "HEAD")
        # Make all bound objects available remotely without advancing main.
        self.git("--git-dir", str(self.bare), "fetch", str(self.work), self.candidate)
        self.configure()

    def git(self, *args):
        result = subprocess.run(["/usr/bin/git", *args], cwd=self.root, env=safe_environment(),
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def configure(self, transitions=()):
        plan = bind_fixture_aliases(prepare_fixture_spec({
            "fixture_setup": {"local_candidate": True}, "fixture_state": {},
            "fixture_transitions": list(transitions), "fixture_requirements": [],
        }), {"base": self.base, "candidate": self.candidate})
        state = deepcopy(plan["state"])
        state.update(allowed_writes=["branch_push", "tag_creation", "asset_upload"],
                     candidate_commit=self.candidate, remote_url=str(self.bare),
                     expected_git_remote_url=str(self.bare), fixture_runtime=new_fixture_runtime())
        (self.private / "fixture-plan.json").write_text(json.dumps(plan))
        (self.private / "remote-state.json").write_text(json.dumps(state))

    def command(self):
        return [sys.executable, "-I", str(SCRIPTS / "fixture_broker.py"),
                "--work", str(self.work), "--bare", str(self.bare),
                "--private", str(self.private), "--spool", str(self.work / ".eval" / "broker-io")]

    @contextmanager
    def server(self):
        process = subprocess.Popen(self.command(), env=safe_environment(), cwd=self.work,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 8
            while not (self.private / "ready.json").exists():
                if process.poll() is not None:
                    self.fail(process.communicate()[1])
                if time.monotonic() >= deadline:
                    self.fail("broker startup timeout")
                time.sleep(0.01)
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)

    def call(self, *argv):
        return request(self.work / ".eval" / "broker-io", list(argv))

    def finish_server(self, process):
        (self.private / "stop-requested.json").write_text('{}')
        self.assertEqual(process.wait(timeout=8), 0)
        return validate_terminal_records(self.private)

    def test_help_has_terminal_record_and_stop_closes_custody(self):
        with self.server() as process:
            self.assertEqual(self.call("--help")["exit_code"], 0)
            self.assertEqual(self.call("inspect")["exit_code"], 0)
            with self.assertRaises(ValueError):
                validate_terminal_records(self.private)
            self.assertEqual(self.finish_server(process),
                             {"version": 1, "status": "quiescent", "accepted": 2, "observable": 1})
        records = [json.loads(line) for line in (self.private / "requests.jsonl").read_text().splitlines()]
        self.assertIs(records[0]["complete"], True)
        self.assertIs(records[0]["observable"], False)
        self.assertIs(records[1]["observable"], True)

    def test_stop_before_start_accepts_no_queued_request(self):
        spool = self.work / ".eval" / "broker-io"
        spool.mkdir()
        (spool / ("a" * 32 + ".request.json")).write_text('{"version":1,"argv":["branch-push"]}')
        (self.private / "stop-requested.json").write_text('{}')
        process = subprocess.run(self.command(), env=safe_environment(), cwd=self.work,
                                 capture_output=True, text=True, timeout=8)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(validate_terminal_records(self.private),
                         {"version": 1, "status": "quiescent", "accepted": 0, "observable": 0})
        self.assertEqual(self.git("--git-dir", str(self.bare), "rev-parse", "main"), self.base)

    def test_stop_waits_for_inflight_push_and_accepts_no_next_request(self):
        spool = self.work / ".eval" / "broker-io"
        spool.mkdir()
        first, second = "a" * 32, "b" * 32
        (spool / (first + ".request.json")).write_text('{"version":1,"argv":["branch-push"]}')
        broker = FixtureBroker(work=self.work, bare=self.bare, private=self.private, spool_path=spool)
        entered, release = threading.Event(), threading.Event()
        original = SafeGit.__call__
        errors = []

        def delayed(safe, *args):
            if args[:1] == ("push",):
                entered.set()
                if not release.wait(timeout=5):
                    raise RuntimeError("synthetic delayed operation timeout")
            return original(safe, *args)

        def serve():
            try:
                broker.serve()
            except BaseException as error:
                errors.append(error)

        # No shared-process chdir: only the broker's explicit cwd assertion is
        # patched. Every real Git subprocess still uses its own fixed cwd.
        with patch.object(Path, "cwd", return_value=self.work), patch.object(SafeGit, "__call__", delayed):
            worker = threading.Thread(target=serve)
            worker.start()
            try:
                self.assertTrue(entered.wait(timeout=5))
                self.assertIsNotNone(json.loads((self.private / "remote-state.json").read_text())["fixture_runtime"]["pending"])
                (spool / (second + ".request.json")).write_text('{"version":1,"argv":["inspect"]}')
                (self.private / "stop-requested.json").write_text('{}')
                self.assertFalse((self.private / "stopped.json").exists())
                with self.assertRaises(ValueError):
                    validate_terminal_records(self.private)
            finally:
                (self.private / "stop-requested.json").write_text('{}')
                release.set()
                worker.join(timeout=8)
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(validate_terminal_records(self.private),
                         {"version": 1, "status": "quiescent", "accepted": 1, "observable": 1})
        self.assertFalse((self.private / "accepted" / second).exists())
        self.assertFalse((spool / (second + ".response.json")).exists())
        self.assertEqual(json.loads((spool / (first + ".response.json")).read_text())["exit_code"], 0)
        self.assertEqual(self.git("--git-dir", str(self.bare), "rev-parse", "main"), self.candidate)

    def test_terminal_validator_rejects_missing_incomplete_and_mismatched_records(self):
        with self.server() as process:
            self.assertEqual(self.call("inspect")["exit_code"], 0)
            self.finish_server(process)
        names = ("requests.jsonl", "checkpoints.jsonl", "observations.jsonl", "remote-state.json", "stopped.json")
        originals = {name: (self.private / name).read_text() for name in names}
        terminal = json.loads(originals["requests.jsonl"])
        incomplete = {**terminal, "complete": False}
        mismatched = json.loads(originals["observations.jsonl"])
        mismatched["message_id"] = "f" * 32
        runtime_pending = json.loads(originals["remote-state.json"])
        runtime_pending["fixture_runtime"]["pending"] = {"synthetic": True}
        runtime_errors = json.loads(originals["remote-state.json"])
        runtime_errors["fixture_runtime"]["errors"] = ["synthetic"]
        cases = (
            ("requests.jsonl", ""),
            ("requests.jsonl", json.dumps(incomplete) + "\n"),
            ("requests.jsonl", originals["requests.jsonl"] * 2),
            ("requests.jsonl", '{"message_id":'),
            ("checkpoints.jsonl", "\n".join(originals["checkpoints.jsonl"].splitlines()[:-1]) + "\n"),
            ("observations.jsonl", json.dumps(mismatched) + "\n"),
            ("remote-state.json", json.dumps(runtime_pending)),
            ("remote-state.json", json.dumps(runtime_errors)),
            ("stopped.json", '{}'),
        )
        for name, content in cases:
            with self.subTest(name=name, content=content[:60]):
                (self.private / name).write_text(content)
                try:
                    with self.assertRaises(ValueError):
                        validate_terminal_records(self.private)
                finally:
                    (self.private / name).write_text(originals[name])
        # Delivery failure does not erase complete backend custody.
        (self.private / "requests.jsonl").write_text(originals["requests.jsonl"] + json.dumps(
            {"message_id": terminal["message_id"], "reply_delivery": "failed"}) + "\n")
        self.assertEqual(validate_terminal_records(self.private),
                         {"version": 1, "status": "quiescent", "accepted": 1, "observable": 1})

    def test_rejected_accepted_request_stops_but_cannot_pass_custody(self):
        with self.server() as process:
            self.assertEqual(self.call("inspect", "--state", "forbidden")["exit_code"], 2)
            (self.private / "stop-requested.json").write_text('{}')
            self.assertEqual(process.wait(timeout=8), 0)
        self.assertTrue((self.private / "stopped.json").exists())
        self.assertEqual(len(list((self.private / "accepted").iterdir())), 1)
        with self.assertRaisesRegex(ValueError, "incomplete_or_duplicate_request"):
            validate_terminal_records(self.private)

    def test_real_broker_private_journal_and_nonforce_push(self):
        with self.server():
            inspected = self.call("inspect")
            self.assertEqual(inspected["exit_code"], 0)
            self.assertNotIn("fixture_runtime", inspected["output"])
            self.assertNotIn("allowed_writes", inspected["output"])
            self.assertEqual(self.call("branch-push", "--branch", "main")["exit_code"], 0)
            self.assertEqual(self.call("branch-read", "--branch", "main")["output"], self.candidate)
            snapshot = subprocess.run(self.command() + ["--snapshot-only"], cwd=self.work,
                                      env=safe_environment(), capture_output=True, text=True, timeout=20)
            self.assertEqual(snapshot.returncode, 0, snapshot.stderr)
            self.assertEqual(json.loads(snapshot.stdout)["actual_git_branches"]["main"], self.candidate)
        self.assertEqual(self.git("--git-dir", str(self.bare), "rev-parse", "main"), self.candidate)
        observations = [json.loads(line) for line in (self.private / "observations.jsonl").read_text().splitlines()]
        self.assertEqual(len(observations), 3)
        self.assertEqual(set(observations[0]["observation"]), {"before", "before_backend", "after_backend", "after", "git_cas"})
        self.assertFalse((self.work / ".eval" / "fixture-plan.json").exists())

    def test_scheduled_change_has_real_cas_and_advisory_replay(self):
        self.configure([{"id": "synthetic-advance", "once": True,
            "trigger": {"phase": "before", "operation": "branch-read", "target": "main", "occurrence": 1, "when_result": "any"},
            "changes": [{"path": ["branches", "main"], "op": "set", "value": "@candidate"}], "result": None}])
        with self.server():
            self.assertEqual(self.call("branch-read", "--branch", "main")["output"], self.candidate)
        observation = json.loads((self.private / "observations.jsonl").read_text())["observation"]
        state = json.loads((self.private / "remote-state.json").read_text())
        review = attribute_fixture_events(plan=json.loads((self.private / "fixture-plan.json").read_text()),
            pre=observation["before"], post=observation["after"], runtime=state["fixture_runtime"], observations=[observation])
        self.assertTrue(review["consistent"], review)
        self.assertEqual(review["model_intervals"], [])
        self.assertEqual(len(observation["git_cas"]["before"]), 1)

    def test_poisoned_model_config_hooks_and_remote_never_execute(self):
        marker = self.root / "should-not-exist"
        self.git("-C", str(self.work), "config", "core.fsmonitor", f"touch {marker}")
        self.git("-C", str(self.work), "config", "core.hooksPath", str(self.work / "evil-hooks"))
        self.git("-C", str(self.work), "config", "remote.origin.receivepack", f"touch {marker}")
        hooks = self.work / "evil-hooks"
        hooks.mkdir()
        (hooks / "pre-push").write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n")
        (hooks / "pre-push").chmod(0o700)
        with self.server():
            self.assertEqual(self.call("branch-push")["exit_code"], 0)
        self.assertFalse(marker.exists())
        safe = SafeGit(self.work, self.bare, self.private)
        try:
            snapshot = safe.grading_snapshot(json.loads((self.private / "remote-state.json").read_text()))
            self.assertEqual(snapshot["local_git"]["head"], self.candidate)
            self.assertFalse(snapshot["local_git"]["remote_url_changed"])
        finally:
            safe.close()
        self.assertFalse(marker.exists())

    def test_includes_alternates_symlinks_and_redirected_origin_fail_closed(self):
        config = self.work / ".git" / "config"
        original = config.read_text()
        config.write_text(original + '\n[include]\n path = /private/not-to-be-read\n')
        with self.assertRaisesRegex(ValueError, "git_config_include"):
            SafeGit(self.work, self.bare, self.private)
        config.write_text(original)
        info = self.work / ".git" / "objects" / "info"
        (info / "alternates").write_text("/private/not-to-be-read\n")
        with self.assertRaisesRegex(ValueError, "git_alternates"):
            SafeGit(self.work, self.bare, self.private)
        (info / "alternates").unlink()
        (self.work / ".git" / "refs" / "escape").symlink_to(self.private, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink_git_input"):
            SafeGit(self.work, self.bare, self.private)
        (self.work / ".git" / "refs" / "escape").unlink()
        self.git("-C", str(self.work), "config", "remote.origin.url", "https://example.invalid/repo")
        safe = SafeGit(self.work, self.bare, self.private)
        try:
            self.assertFalse(safe.remote_matches())
            with self.assertRaisesRegex(ValueError, "source_remote_changed"):
                safe("push", "origin", "HEAD:refs/heads/main")
        finally:
            safe.close()

    def test_parent_snapshot_uses_actual_annotated_tag_object_and_peeled_target(self):
        with self.server():
            self.assertEqual(self.call("tag-create", "--tag", "v-synthetic", "--commit", self.base)["exit_code"], 0)
            result = subprocess.run(self.command() + ["--snapshot-evidence"], cwd=self.work,
                                    env=safe_environment(), capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(set(payload), {"grading_state", "attribution_snapshot"})
            snapshot = payload["attribution_snapshot"]
            self.assertNotIn("fixture_runtime", snapshot["state"])
            self.assertIn("fixture_events", snapshot["state"])
            actual = snapshot["git"]["tags"]["v-synthetic"]
            self.assertNotEqual(actual["ref_oid"], actual["target"])
            self.assertEqual(actual["target"], self.base)
            self.assertEqual(actual["ref_oid"], self.git("--git-dir", str(self.bare), "rev-parse", "refs/tags/v-synthetic"))
            self.assertEqual(payload["grading_state"]["actual_git_tags"]["v-synthetic"], actual["ref_oid"])

    def await_reply(self, identifier):
        path = self.work / ".eval" / "broker-io" / (identifier + ".response.json")
        deadline = time.monotonic() + 3
        while not path.exists() or path.is_symlink():
            self.assertLess(time.monotonic(), deadline, "reply deadline")
            time.sleep(0.01)
        return json.loads(path.read_text())

    def test_spool_rejects_symlink_requests_and_replaces_reply_symlink_not_target(self):
        with self.server():
            spool = self.work / ".eval" / "broker-io"
            identifier = "a" * 32
            (spool / (identifier + ".request.json")).symlink_to(self.private / "remote-state.json")
            self.assertEqual(self.await_reply(identifier)["exit_code"], 2)
            canary = self.private / "synthetic-canary"
            canary.write_text("unchanged")
            identifier = "b" * 32
            (spool / (identifier + ".response.json")).symlink_to(canary)
            (spool / (identifier + ".request.json")).write_text('{"version":1,"argv":["inspect"]}')
            self.assertEqual(self.await_reply(identifier)["exit_code"], 0)
            self.assertEqual(canary.read_text(), "unchanged")
            self.assertEqual(len(list((self.private / "accepted").iterdir())), 2)

    def test_duplicate_message_id_never_reexecutes_and_bad_frame_stays_private(self):
        with self.server():
            spool = self.work / ".eval" / "broker-io"
            identifier = "c" * 32
            path = spool / (identifier + ".request.json")
            path.write_text('{"version":1,"argv":["inspect"]}')
            self.assertEqual(self.await_reply(identifier)["exit_code"], 0)
            path.write_text('{"version":1,"argv":["branch-push"]}')
            time.sleep(0.06)
            self.assertEqual(self.git("--git-dir", str(self.bare), "rev-parse", "main"), self.base)
            identifier = "d" * 32
            (spool / (identifier + ".request.json")).write_text("x" * 65537)
            self.assertEqual(self.await_reply(identifier)["exit_code"], 2)
            runtime = json.loads((self.private / "remote-state.json").read_text())["fixture_runtime"]
            self.assertEqual(len(runtime["events"]), 1)

    def test_client_timeout_leaves_one_uncertain_request_without_replay(self):
        spool = self.work / ".eval" / "broker-io"
        spool.mkdir()
        with self.assertRaises(TimeoutError):
            request(spool, ["branch-push"], timeout=0.05)
        files = list(spool.iterdir())
        self.assertEqual(len(files), 1)
        self.assertRegex(files[0].name, r"^[0-9a-f]{32}\.request\.json$")

    def test_committed_write_with_timeout_reply_preserves_backend_truth(self):
        self.configure([{"id": "synthetic-response-timeout", "once": True,
            "trigger": {"phase": "after", "operation": "branch-push", "target": "main", "occurrence": 1, "when_result": "success"},
            "changes": [], "result": {"status": "timeout", "exit_code": 124, "output": {"error": "synthetic_timeout"}}}])
        with self.server():
            self.assertEqual(self.call("branch-push")["exit_code"], 124)
        state = json.loads((self.private / "remote-state.json").read_text())
        event = state["fixture_runtime"]["events"][0]
        self.assertEqual(event["backend_result"]["status"], "success")
        self.assertEqual(event["delivered_result"]["status"], "timeout")
        observation = json.loads((self.private / "observations.jsonl").read_text())["observation"]
        self.assertEqual(observation["after_backend"]["git"]["branches"]["main"]["target"], self.candidate)

    def test_snapshot_status_preserves_porcelain_columns(self):
        (self.work / "candidate.txt").write_text("dirty\n")
        safe = SafeGit(self.work, self.bare, self.private)
        try:
            snapshot = safe.grading_snapshot(json.loads((self.private / "remote-state.json").read_text()))
            self.assertIn(" M candidate.txt", snapshot["local_git"]["status"])
        finally:
            safe.close()


if __name__ == "__main__":
    unittest.main()
