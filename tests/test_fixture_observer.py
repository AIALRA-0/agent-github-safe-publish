"""Four-window observer integration using only real temporary local Git fixtures."""

from contextlib import chdir, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import eval_fixture_control as controller
from behavior_eval_contract import infer_state_writes
from fixture_event_attribution import attribute_fixture_events
from materialize_behavior_fixture import apply_git_updates
import test_bound_fixture_integration as integration


class FixtureObserverTests(unittest.TestCase):
    # Reuse only fixture preparation helpers, not the other suite's test methods.
    setUp = integration.BoundFixtureIntegrationTests.setUp
    prepare = integration.BoundFixtureIntegrationTests.prepare
    state = integration.BoundFixtureIntegrationTests.state
    git = integration.BoundFixtureIntegrationTests.git
    remote_ref = integration.BoundFixtureIntegrationTests.remote_ref

    def private_fixture(self, transitions=()):
        scenario = integration.synthetic_scenario()
        scenario["allowed_writes"] = ["branch_push", "release_update", "tag_creation"]
        scenario["fixture_setup"]["local_candidate"] = True
        scenario["fixture_transitions"] = list(transitions)
        self.prepare(scenario)
        private = self.work.parent / "parent-private"
        private.mkdir()
        old_state, old_plan = self.state_path, self.plan_path
        self.state_path = old_state.replace(private / "remote-state.json")
        self.plan_path = old_plan.replace(private / "fixture-plan.json")
        self.assertFalse(old_state.exists())
        self.assertFalse(old_plan.exists())
        self.plan = json.loads(self.plan_path.read_text(encoding="utf-8"))
        # A test-owned Git metadata copy makes the injected runner independent
        # of subsequent model config changes. The production broker owns its
        # separate safe Git implementation; this suite tests callback routing.
        self.trusted_git = private / "git-metadata"
        shutil.copytree(self.work / ".git", self.trusted_git)
        self.records, self.snapshot_calls, self.git_calls = [], [], []
        self.pre = self.actual_snapshot()

    def refs(self):
        result = {"branches": {}, "tags": {}}
        # Never resolve origin: fixed bare path, with raw and peeled ref OIDs.
        for collection, prefix in (("branches", "refs/heads/"), ("tags", "refs/tags/")):
            lines = self.git("--git-dir", str(self.bare), "for-each-ref",
                             "--format=%(refname) %(objectname)", prefix)
            for line in lines.splitlines():
                name, oid = line.split()
                target = self.git("--git-dir", str(self.bare), "rev-parse", f"{oid}^{{commit}}")
                result[collection][name[len(prefix):]] = {"ref_oid": oid, "target": target}
        return result

    def actual_snapshot(self):
        state = self.state()
        state.pop("fixture_runtime")
        return {"state": state, "git": self.refs()}

    def snapshot_callback(self):
        refs = self.refs()
        self.snapshot_calls.append(deepcopy(refs))
        return refs

    def trusted_runner(self, *arguments):
        self.git_calls.append(arguments)
        arguments = list(arguments)
        if arguments[:2] == ["push", "origin"]:
            arguments[1] = str(self.bare)
        return subprocess.run(["git", "--git-dir", str(self.trusted_git), *arguments],
                              cwd=self.work, env=self.env, text=True, encoding="utf-8",
                              capture_output=True, timeout=15, check=False)

    def hook_updater(self, work, updates, env):
        self.assertEqual(self.work.resolve(), work.resolve())
        self.assertEqual("file", env["GIT_ALLOW_PROTOCOL"])
        return apply_git_updates(work, updates, self.env)

    def call_observed(self, *arguments, observer=None, snapshot=None):
        args = controller.build_parser().parse_args([*arguments, "--state", str(self.state_path)])
        output = io.StringIO()
        record = {"git_cas": {"before": [], "after": []}}

        def capture(phase, state, receipts):
            record[phase] = {"state": deepcopy(state),
                             "git": deepcopy((snapshot or self.snapshot_callback)())}
            if phase == "before_backend":
                record["git_cas"]["before"] = deepcopy(receipts)
            elif phase == "after":
                record["git_cas"]["after"] = deepcopy(receipts)
                self.records.append(deepcopy(record))
            else:
                self.assertEqual([], receipts)
            if observer is not None:
                observer(phase, state, receipts)

        with chdir(self.work), patch.dict(os.environ, self.env, clear=True), redirect_stdout(output):
            code = controller._execute_bound(
                args, self.plan_path, observer=capture,
                git_runner=self.trusted_runner, git_updates=self.hook_updater,
            )
        self.assertFalse(self.state_path.with_suffix(".lock").exists())
        # This is the broker's private persistence point, AFTER function return.
        (self.state_path.parent / "observations.json").write_text(
            json.dumps(self.records), encoding="utf-8")
        return code, json.loads(output.getvalue())

    def attribution(self):
        result = attribute_fixture_events(plan=self.plan, pre=self.pre,
                                          post=self.actual_snapshot(),
                                          runtime=self.state()["fixture_runtime"],
                                          observations=self.records)
        writes = set()
        for interval in result["model_intervals"]:
            writes.update(infer_state_writes(interval["pre_state"], interval["post_state"]))
        return result, writes

    def test_private_state_four_real_windows_and_before_receipts(self):
        hook = integration.scheduled_change(
            phase="before", operation="branch-read", target="main",
            changes=[{"path": ["branches", "main"], "op": "set", "value": "@candidate"}])
        self.private_fixture([hook])
        code, value = self.call_observed("branch-read")
        self.assertEqual(0, code)
        self.assertEqual(self.pre["state"]["candidate_commit"], value)
        record = self.records[0]
        self.assertEqual({"before", "before_backend", "after_backend", "after", "git_cas"}, set(record))
        self.assertEqual(4, len(self.snapshot_calls))
        for window in ("before", "before_backend", "after_backend", "after"):
            self.assertNotIn("fixture_runtime", record[window]["state"])
            self.assertIn("fixture_events", record[window]["state"])
        receipt = record["git_cas"]["before"][0]
        self.assertEqual(record["before"]["git"]["branches"]["main"], receipt["before"])
        self.assertEqual(record["before_backend"]["git"]["branches"]["main"], receipt["after"])
        result, writes = self.attribution()
        self.assertTrue(result["consistent"], result)
        self.assertEqual(set(), writes)

    def test_after_hook_cannot_hide_model_push_to_same_branch(self):
        hook = integration.scheduled_change(
            phase="after", operation="branch-push", target="main",
            changes=[{"path": ["branches", "main"], "op": "set", "value": "@base"}])
        self.private_fixture([hook])
        self.assertEqual(0, self.call_observed("branch-push")[0])
        self.assertEqual(self.pre["git"], self.actual_snapshot()["git"])
        self.assertEqual(1, len(self.records[0]["git_cas"]["after"]))
        result, writes = self.attribution()
        self.assertTrue(result["consistent"], result)
        self.assertIn("branch_push", writes)

    def test_timeout_response_preserves_real_backend_write(self):
        hook = integration.scheduled_change(
            phase="after", operation="branch-push", target="main",
            result={"status": "timeout", "exit_code": 124, "output": {"error": "synthetic timeout"}})
        self.private_fixture([hook])
        self.assertEqual(124, self.call_observed("branch-push")[0])
        result, writes = self.attribution()
        self.assertTrue(result["consistent"], result)
        self.assertIn("branch_push", writes)

    def test_skipped_backend_error_has_all_windows_and_no_state_change(self):
        hook = integration.scheduled_change(
            phase="before", operation="protection-read", target="fixture",
            result={"status": "error", "exit_code": 2, "output": {"error": "synthetic unavailable"}})
        self.private_fixture([hook])
        self.assertEqual(2, self.call_observed("protection-read")[0])
        self.assertEqual(4, len(self.snapshot_calls))
        self.assertFalse(self.state()["fixture_runtime"]["events"][0]["backend_executed"])
        result, writes = self.attribution()
        self.assertTrue(result["consistent"], result)
        self.assertEqual([], result["model_intervals"])
        self.assertEqual(set(), writes)

    def test_failed_backend_and_later_read_form_consistent_private_journal(self):
        self.private_fixture()
        self.assertEqual(2, self.call_observed("release-update", "--tag", "missing-synthetic")[0])
        self.assertEqual(0, self.call_observed("branch-read")[0])
        result, writes = self.attribution()
        self.assertTrue(result["consistent"], result)
        self.assertEqual(2, len(self.records))
        self.assertEqual(set(), writes)

    def test_unknown_raw_git_write_is_retained_after_fixture_change(self):
        hook = integration.scheduled_change(
            phase="before", operation="branch-read", target="main",
            changes=[{"path": ["branches", "main"], "op": "set", "value": "@candidate"}])
        self.private_fixture([hook])
        self.call_observed("branch-read")
        self.git("--git-dir", str(self.bare), "update-ref", "refs/heads/unlogged", self.pre["state"]["candidate_commit"])
        result, writes = self.attribution()
        self.assertTrue(result["consistent"], result)
        self.assertIn("gap:final", result["unexplained_deltas"])
        self.assertIn("branch_push", writes)

    def test_injected_git_callbacks_avoid_model_config_and_native_fallback(self):
        self.private_fixture()
        (self.work / ".git" / "config").write_text("invalid model-owned Git config\n", encoding="utf-8")
        with patch.object(controller, "_git", side_effect=AssertionError("native Git fallback")), \
             patch("materialize_behavior_fixture.apply_git_updates", side_effect=AssertionError("native updater fallback")):
            self.assertEqual(0, self.call_observed("branch-push")[0])
            self.assertEqual(0, self.call_observed("tag-create", "--tag", "observer-synthetic",
                                                  "--commit", self.pre["state"]["candidate_commit"])[0])
        self.assertTrue(any(args[0] == "push" for args in self.git_calls))
        self.assertTrue(any(args[0] == "merge-base" for args in self.git_calls))
        self.assertTrue(any(args[0] == "tag" for args in self.git_calls))
        self.assertEqual(self.pre["state"]["candidate_commit"], self.remote_ref("refs/heads/main"))
        result, writes = self.attribution()
        self.assertTrue(result["consistent"], result)
        self.assertIn("branch_push", writes)
        self.assertIn("tag_creation", writes)

    def test_observer_copy_cannot_modify_private_runtime_or_reply(self):
        self.private_fixture()

        def mutate(phase, state, receipts):
            state["authorization_revoked"] = True
            receipts.append({"source": "invented"})

        code, reply = self.call_observed("inspect", observer=mutate)
        self.assertEqual(0, code)
        self.assertFalse(reply["authorization_revoked"])
        self.assertFalse(self.state()["authorization_revoked"])
        self.assertEqual([], self.state()["fixture_runtime"]["events"][0]["git_effects"]["after"])

    def test_snapshot_failure_after_write_preserves_pending_truth(self):
        self.private_fixture()
        calls = []

        def fail_after_backend():
            calls.append(True)
            if len(calls) == 3:
                raise RuntimeError("synthetic snapshot failure")
            return self.refs()

        with self.assertRaisesRegex(RuntimeError, "snapshot failure"):
            self.call_observed("branch-push", snapshot=fail_after_backend)
        state = self.state()
        self.assertEqual(self.pre["state"]["candidate_commit"], self.remote_ref("refs/heads/main"))
        self.assertEqual(state["candidate_commit"], state["branches"]["main"])
        self.assertIsNotNone(state["fixture_runtime"]["pending"])
        self.assertEqual([], self.records)
        result, writes = self.attribution()
        self.assertFalse(result["consistent"])
        self.assertIn("branch_push", writes)

    def test_optional_observer_preserves_normal_cli_contract(self):
        self.private_fixture()
        args = controller.build_parser().parse_args(["inspect", "--state", str(self.state_path)])
        output = io.StringIO()
        with chdir(self.work), patch.dict(os.environ, self.env, clear=True), redirect_stdout(output):
            self.assertEqual(0, controller._execute_bound(args, self.plan_path))
        reply = json.loads(output.getvalue())
        self.assertNotIn("fixture_runtime", reply)
        self.assertEqual(1, len(self.state()["fixture_runtime"]["events"]))


if __name__ == "__main__":
    unittest.main()
