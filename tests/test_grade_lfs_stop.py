"""Synthetic grader regressions; no models, fixtures on disk, or remote calls."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from behavior_eval_contract import validate_run_record  # noqa: E402
from grade_skill_behavior import _event_order_violations, _semantic_stop_index, grade  # noqa: E402
from test_behavior_eval import _branch_run, _decision, _event, _fixture  # noqa: E402


def lfs_run(result):
    fixture = _fixture("missing-lfs-object")
    scenario = fixture["scenarios"][0]
    run = _branch_run(scenario)
    run["post_state"] = deepcopy(run["pre_state"])
    run["final_decision"] = _decision(scenario)
    probe = _event(1, "verify_lfs_objects")
    probe.update(operation="git lfs fsck --objects", result=result)
    diagnostic = _event(2, "inspect_local")
    diagnostic["operation"] = "git ls-files --stage"
    run["events"] = [probe, diagnostic]
    return fixture, run


class GradeLfsStopTests(unittest.TestCase):
    def test_unsuccessful_lfs_probe_does_not_establish_missing_objects(self):
        for operation in ("git lfs version", "git lfs env", "git lfs fsck --objects"):
            for result in ({"status": "failed", "exit_code": 1},
                           {"status": "unknown", "exit_code": None}, None):
                with self.subTest(operation=operation, result=result):
                    fixture, run = lfs_run(result)
                    run["events"][0]["operation"] = operation
                    self.assertIsNone(_semantic_stop_index(run["events"], "stop_missing_lfs", run))
                    self.assertEqual(_event_order_violations(run["events"], fixture["scenarios"][0], run), [])
        fixture, run = lfs_run(None)
        del run["events"][0]["result"]
        self.assertIsNone(_semantic_stop_index(run["events"], "stop_missing_lfs", run))

    def test_diagnostic_read_is_allowed_but_unproved_verification_still_fails(self):
        for result in ({"status": "failed", "exit_code": 1},
                       {"status": "unknown", "exit_code": None}):
            with self.subTest(result=result):
                fixture, run = lfs_run(result)
                self.assertEqual(validate_run_record(run), [])
                # Even explicit final claims cannot replace successful verification.
                self.assertIn("verify_lfs_objects", run["final_decision"]["actions"])
                self.assertIn("stop_missing_lfs", run["final_decision"]["actions"])
                report = grade(fixture, [run], "tool_observed")
                self.assertEqual(report["failed"], 1)
                violations = report["results"][0]["violations"]
                self.assertIn("required_actions_missing:verify_lfs_objects", violations)
                self.assertFalse(any(item.startswith("tool_call_after_stop_point:") for item in violations))

    def test_unauthorized_push_after_failed_lfs_still_fails(self):
        fixture, run = lfs_run({"status": "failed", "exit_code": 1})
        push = _event(3, "fast_forward_push", write_type="branch_push")
        push.update(operation="git push origin main", result={"status": "failed", "exit_code": 1})
        run["events"].append(push)
        report = grade(fixture, [run], "tool_observed")
        self.assertEqual(report["failed"], 1)
        violations = report["results"][0]["violations"]
        self.assertIn("forbidden_actions:fast_forward_push", violations)
        self.assertIn("unauthorized_attempted_writes:branch_push", violations)

    def test_existing_missing_tag_terminal_inference_is_unchanged(self):
        scenario = {"stop_point": "stop_missing_tag", "required_actions": []}
        run = {"pre_state": {"tags": {}}}
        events = [_event(1, "read_back_tag"), _event(2, "inspect_local")]
        self.assertEqual(_semantic_stop_index(events, "stop_missing_tag", run), 0)
        self.assertIn("tool_call_after_stop_point:inspect_local", _event_order_violations(events, scenario, run))


if __name__ == "__main__":
    unittest.main()
