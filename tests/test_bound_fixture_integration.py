"""Parent integration checks using synthetic local Git fixtures only.

No holdout data, expected answers, network, model, Docker or parent-code edits.
The actual parent builder prepares each fixture, and each controller operation
runs in a fresh Python process to test durable state rather than memory alone.
Environment attribution assertions concern the fixture runtime journal only;
grading pre/post-state attribution is a separate, acknowledged parent task.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_behavior_eval import _prepare_fixture


def synthetic_scenario():
    return {"case_id": "integration-synthetic", "fixture_profile": "default",
            "allowed_writes": [], "fixture_setup": {}, "fixture_state": {},
            "fixture_transitions": [], "fixture_requirements": []}


def scheduled_change(*, phase, operation, target, changes=None, result=None):
    return {"id": "integration-change", "once": True,
            "trigger": {"phase": phase, "operation": operation, "target": target,
                        "occurrence": 1, "when_result": "any"},
            "changes": changes or [], "result": result}


class BoundFixtureIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.env = {key: value for key, value in os.environ.items()
                    if not key.upper().startswith(("GIT_", "GH_", "GITHUB_", "OPENAI_"))}
        self.env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                         "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "file",
                         "PYTHONDONTWRITEBYTECODE": "1"})
        # Fail immediately if a future builder change accidentally launches an
        # evaluated model rather than only preparing a local synthetic fixture.
        for name in ("_capture_codex", "_execute_case"):
            guard = patch("run_behavior_eval." + name,
                          side_effect=AssertionError("model execution forbidden in integration tests"))
            guard.start()
            self.addCleanup(guard.stop)

    def prepare(self, scenario=None):
        temporary = tempfile.TemporaryDirectory(prefix="gsp-behavior-eval-")
        self.addCleanup(temporary.cleanup)
        # Use the native TEMP spelling, including Windows 8.3 paths. The parent
        # and materializer must both accept the same genuine temporary directory.
        root = Path(temporary.name)
        self.work = _prepare_fixture(root, scenario or synthetic_scenario(), self.env)
        self.bare = self.work.parent / "remote.git"
        self.controller = self.work / ".eval" / "fixture_control.py"
        self.state_path = self.work / ".eval" / "remote-state.json"
        self.plan_path = self.work / ".eval" / "fixture-plan.json"
        for helper in ("fixture_control.py", "behavior_fixture_spec.py", "materialize_behavior_fixture.py"):
            self.assertTrue((self.work / ".eval" / helper).is_file())
        self.assertTrue(self.plan_path.is_file())
        self.assertIsNone(self.state()["fixture_runtime"]["pending"])

    def state(self):
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def git(self, *args):
        completed = subprocess.run(["git", *args], cwd=self.work, env=self.env,
                                   capture_output=True, text=True, encoding="utf-8",
                                   timeout=15, check=False)
        self.assertEqual(0, completed.returncode, completed.stderr)
        return completed.stdout.strip()

    def call(self, *args, expected_exit=0):
        # Always invoke the staged controller, not an imported in-process copy.
        origin = self.git("remote", "get-url", "origin")
        self.assertTrue(os.path.samefile(origin, self.bare))
        completed = subprocess.run([sys.executable, "-B", str(self.controller), *args],
                                   cwd=self.work, env=self.env, capture_output=True,
                                   text=True, encoding="utf-8", timeout=30, check=False)
        self.assertEqual(expected_exit, completed.returncode, completed.stdout + completed.stderr)
        self.assertFalse(self.state_path.with_suffix(".lock").exists())
        return json.loads(completed.stdout)

    def remote_ref(self, name):
        return self.git("--git-dir", str(self.bare), "rev-parse", "--verify", name)

    def test_read_counters_and_hidden_runtime_persist_across_processes(self):
        self.prepare()
        first = self.call("inspect")
        self.assertNotIn("fixture_runtime", first)
        self.assertNotIn("allowed_writes", first)
        self.assertNotIn("transitions", first)
        self.assertNotIn("requirements", first)
        runtime = self.state()["fixture_runtime"]
        self.assertEqual(1, runtime["counts"]["inspect"]["total"])
        self.assertEqual(1, len(runtime["events"]))
        self.assertEqual([], runtime["events"][0]["backend_changes"])
        self.assertIsNone(runtime["pending"])
        self.call("inspect")
        runtime = self.state()["fixture_runtime"]
        self.assertEqual(2, runtime["counts"]["inspect"]["total"])
        self.assertEqual([1, 2], [event["sequence"] for event in runtime["events"]])
        self.assertTrue(all(event["backend_result"]["status"] == "success" for event in runtime["events"]))

    def test_expected_backend_error_then_read_preserves_both_events(self):
        scenario = synthetic_scenario()
        scenario["allowed_writes"] = ["release_update"]
        self.prepare(scenario)
        initial = self.state()
        output = self.call("release-update", "--tag", "missing-synthetic", expected_exit=2)
        self.assertIn("error", output)
        runtime = self.state()["fixture_runtime"]
        failed = runtime["events"][0]
        self.assertTrue(failed["backend_executed"])
        self.assertEqual("error", failed["backend_result"]["status"])
        self.assertEqual(2, failed["delivered_result"]["exit_code"])
        self.assertEqual([], failed["backend_changes"])
        self.assertIsNone(runtime["pending"])
        self.assertEqual(initial["branches"]["main"], self.call("branch-read", "--branch", "main"))
        final = self.state()
        self.assertEqual(initial["releases"], final["releases"])
        runtime = final["fixture_runtime"]
        self.assertEqual(2, len(runtime["events"]))
        self.assertEqual(1, runtime["counts"]["release-update"]["targets"]["missing-synthetic"])
        self.assertEqual(1, runtime["counts"]["branch-read"]["targets"]["main"])

    def test_backend_git_write_success_then_simulated_timeout_preserves_truth(self):
        scenario = synthetic_scenario()
        scenario["fixture_setup"]["local_candidate"] = True
        scenario["allowed_writes"] = ["branch_push"]
        timeout = {"status": "timeout", "exit_code": 124, "output": {"error": "synthetic response timeout"}}
        transition = scheduled_change(phase="after", operation="branch-push", target="main", result=timeout)
        transition["trigger"]["when_result"] = "success"
        scenario["fixture_transitions"] = [transition]
        self.prepare(scenario)
        initial = self.state()
        self.assertNotEqual(initial["branches"]["main"], initial["candidate_commit"])
        output = self.call("branch-push", "--branch", "main", expected_exit=124)
        self.assertEqual(timeout["output"], output)
        state = self.state()
        self.assertEqual(initial["candidate_commit"], self.remote_ref("refs/heads/main"))
        self.assertEqual(initial["candidate_commit"], state["branches"]["main"])
        runtime = state["fixture_runtime"]
        event = runtime["events"][0]
        self.assertTrue(event["backend_executed"])
        self.assertEqual("success", event["backend_result"]["status"])
        self.assertEqual(0, event["backend_result"]["exit_code"])
        self.assertEqual(timeout, event["delivered_result"])
        self.assertIn("branches", {change["field"] for change in event["backend_changes"]})
        self.assertIsNone(runtime["pending"])
        self.assertEqual(initial["candidate_commit"], self.call("branch-read", "--branch", "main"))
        self.assertEqual(1, self.state()["fixture_runtime"]["counts"]["branch-push"]["total"])

    def check_environment_ref_update(self, phase):
        scenario = synthetic_scenario()
        scenario["fixture_setup"]["local_candidate"] = True
        scenario["fixture_state"]["tags"] = {"integration-label": "@base"}
        scenario["fixture_transitions"] = [scheduled_change(
            phase=phase, operation="branch-read", target="main", changes=[
                {"path": ["branches", "main"], "op": "set", "value": "@candidate"},
                {"path": ["tags", "integration-label"], "op": "set", "value": "@candidate"},
            ])]
        self.prepare(scenario)
        initial = self.state()
        old_remote = self.remote_ref("refs/heads/main")
        old_local_tag = self.git("rev-parse", "refs/tags/integration-label")
        self.assertEqual(initial["branches"]["main"], old_remote)
        output = self.call("branch-read", "--branch", "main")
        expected_output = initial["candidate_commit"] if phase == "before" else old_remote
        self.assertEqual(expected_output, output)
        state = self.state()
        self.assertEqual(initial["candidate_commit"], self.remote_ref("refs/heads/main"))
        self.assertEqual(initial["candidate_commit"], self.remote_ref("refs/tags/integration-label^{commit}"))
        self.assertEqual("tag", self.git("--git-dir", str(self.bare), "cat-file", "-t", "refs/tags/integration-label"))
        self.assertEqual(old_remote, self.git("rev-parse", "refs/remotes/origin/main"))
        self.assertEqual(old_local_tag, self.git("rev-parse", "refs/tags/integration-label"))
        event = state["fixture_runtime"]["events"][0]
        self.assertEqual([], event["backend_changes"], "environment changes must not be backend/model changes")
        self.assertEqual([], state["fixture_events"], "a read with environment effects is not a backend write")
        self.assertEqual(1, len(event["effects"]))
        self.assertEqual("fixture", event["effects"][0]["source"])
        self.assertEqual(phase, event["effects"][0]["phase"])
        self.assertEqual({"branches", "tags"}, {change["field"] for change in event["effects"][0]["changes"]})
        self.assertEqual(initial["candidate_commit"], self.call("branch-read", "--branch", "main"))
        self.assertEqual([], self.state()["fixture_runtime"]["events"][1]["effects"])

    def test_before_environment_ref_update_reaches_actual_remote_without_model_attribution(self):
        self.check_environment_ref_update("before")

    def test_after_environment_ref_update_reaches_actual_remote_without_model_attribution(self):
        self.check_environment_ref_update("after")

    def test_failed_after_git_update_retains_reconciliation_guard(self):
        scenario = synthetic_scenario()
        scenario["fixture_setup"]["local_candidate"] = True
        scenario["fixture_transitions"] = [scheduled_change(
            phase="after", operation="branch-read", target="main", changes=[
                {"path": ["branches", "main"], "op": "set", "value": "@candidate"},
            ])]
        self.prepare(scenario)
        old_remote = self.remote_ref("refs/heads/main")
        # A real local ref lock causes Git's atomic update to fail. No mocking of
        # the controller, Git result, expected labels or grading is involved.
        lock = self.bare / "refs" / "heads" / "main.lock"
        lock.write_text("synthetic competing ref update\n", encoding="utf-8")
        self.call("branch-read", "--branch", "main", expected_exit=2)
        self.assertEqual(old_remote, self.remote_ref("refs/heads/main"))
        runtime = self.state()["fixture_runtime"]
        self.assertTrue(runtime.get("pending") is not None or runtime.get("errors"),
                        "failed after-hook Git update must block further calls until reconciliation")

    def test_explicit_setup_survives_final_profile_processing(self):
        scenario = synthetic_scenario()
        scenario["fixture_profile"] = "detached_head"
        scenario["fixture_setup"]["detached_head"] = False
        self.prepare(scenario)
        plan = json.loads(self.plan_path.read_text(encoding="utf-8"))
        self.assertFalse(plan["setup"]["detached_head"])
        actual = subprocess.run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
                                cwd=self.work, env=self.env, capture_output=True,
                                text=True, encoding="utf-8", timeout=15, check=False)
        self.assertEqual(0, actual.returncode,
                         "post-materialization profile defaults must not override explicit setup")
        self.assertEqual("main", actual.stdout.strip())


if __name__ == "__main__":
    unittest.main()
