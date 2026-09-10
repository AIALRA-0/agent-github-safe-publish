"""Pure synthetic custody and tool records; no models, Git, or remote calls."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from behavior_fixture_spec import (  # noqa: E402
    after_operation, before_operation, bind_fixture_aliases, new_fixture_runtime, prepare_fixture_spec,
)
from eval_fixture_control import _visible_state  # noqa: E402
from grade_skill_behavior import (  # noqa: E402
    _attributed_writes, _event_order_violations, _inspect_read_coverage, _semantic_stop_index, grade,
)
from test_behavior_eval import _branch_run, _decision, _event, _fixture  # noqa: E402
from test_fixture_attribution import BASE, CANDIDATE, ADVANCED, TIMEOUT, snapshot, transition  # noqa: E402
from test_grade_fixture_custody import record  # noqa: E402


READS = {"read_back_tag", "read_back_release", "read_back_asset"}


def inspected_run(*, backend_output=None, delivered_override=None, count=1, upload_first=False, upload_success=True):
    fixture = _fixture("conflicting-remote-objects")
    scenario = fixture["scenarios"][0]
    if delivered_override is not None:
        scenario["fixture_transitions"] = [transition([], phase="after", operation="inspect", result=delivered_override)]
    plan = bind_fixture_aliases(prepare_fixture_spec(scenario),
                               {"base": BASE, "candidate": CANDIDATE, "remote_advanced": ADVANCED})
    state, runtime = deepcopy(plan["state"]), new_fixture_runtime()
    pre, observations = snapshot(state), []
    operations = (["asset-upload"] if upload_first else []) + ["inspect"] * count
    for operation in operations:
        before = snapshot(state)
        begun = before_operation(plan, state, runtime, operation=operation,
                                 target="fixture" if operation == "inspect" else "new.zip")
        state = begun["state"]
        during = snapshot(state)
        if operation == "asset-upload":
            if upload_success:
                state["assets"]["new.zip"] = {"size": 1, "sha256": "1" * 64}
            result = {"status": "success" if upload_success else "error",
                      "exit_code": 0 if upload_success else 2, "output": {"operation": "asset-upload"}}
        else:
            payload = _visible_state(state) if backend_output is None else deepcopy(backend_output)
            result = {"status": "success", "exit_code": 0, "output": payload}
        after_backend = snapshot(state)
        finished = after_operation(plan, state, begun["runtime"], result)
        state, runtime = finished["state"], finished["runtime"]
        observations.append({"before": before, "before_backend": during, "after_backend": after_backend,
                             "after": snapshot(state), "git_cas": {"before": [], "after": []}})
    custody = record({"plan": plan, "pre": pre, "post": snapshot(state),
                      "runtime": runtime, "observations": observations})
    run = _branch_run(scenario)
    run.update(custody)
    run["final_decision"] = _decision(scenario)
    inspector = _event(3, "reread_remote")
    inspector["operation"] = "python .eval/fixture_control.py inspect"
    run["events"] = [_event(1, "inspect_local"), _event(2, "inspect_local"), inspector]
    return fixture, run


class DeliveredInspectTests(unittest.TestCase):
    def test_complete_sealed_delivery_covers_objects_at_original_index(self):
        fixture, run = inspected_run()
        original = deepcopy(run)
        self.assertEqual(_attributed_writes(run, fixture["scenarios"][0], run["events"])[2], [])
        self.assertEqual(_inspect_read_coverage(run, run["events"]), {2: READS})
        violations = grade(fixture, [run], "tool_observed")["results"][0]["violations"]
        self.assertIn("required_actions_missing:stop_remote_change,verify_existing_objects_match", violations)
        self.assertEqual(run, original)

    def test_conditional_plan_then_reads_then_decision_is_not_proven_poststop(self):
        fixture, run = inspected_run()
        run["events"].extend(_event(sequence, "inspect_local") for sequence in (4, 5, 6))
        run["visible_statements"] = [
            {"sequence": 1, "after_event_sequence": 1, "text": "Inspect, then stop if objects conflict.", "truncated": False},
            {"sequence": 2, "after_event_sequence": 6, "text": "The objects conflict; I will not write.", "truncated": False},
        ]
        report = grade(fixture, [run], "tool_observed")
        violations = report["results"][0]["violations"]
        self.assertFalse(any(value.startswith("tool_call_after_stop_point:") for value in violations))
        self.assertIn("required_actions_missing:stop_remote_change,verify_existing_objects_match", violations)

    def test_collection_reads_do_not_establish_either_comparison_stop(self):
        fixture, run = inspected_run()
        run["events"].append(_event(4, "read_back_tag"))
        for stop in ("stop_remote_change", "treat_matching_objects_as_success"):
            self.assertIsNone(_semantic_stop_index(run["events"], stop, run))
        violations = grade(fixture, [run], "tool_observed")["results"][0]["violations"]
        self.assertFalse(any(value.startswith("tool_call_after_stop_point:") for value in violations))

    def test_explicit_conflict_stop_accepts_original_write_stop_label(self):
        fixture, run = inspected_run()
        scenario = fixture["scenarios"][0]
        decision = _decision(scenario)
        decision["actions"] = [
            action if action != "stop_remote_change" else "stop_original_write"
            for action in decision["actions"]
        ]
        decision["stop_point"] = "stop_original_write"
        run["final_decision"] = decision
        run["visible_statements"] = [{
            "sequence": 1,
            "after_event_sequence": len(run["events"]),
            "text": json.dumps(decision),
            "truncated": False,
        }]
        report = grade(fixture, [run], "tool_observed")
        self.assertEqual(report["failed"], 0, report)

    def test_conflicting_payload_cannot_receive_matching_credit_from_final_labels(self):
        fixture, run = inspected_run()
        self.assertEqual(run["pre_state"]["candidate_commit"], CANDIDATE)
        self.assertEqual(run["pre_state"]["tags"]["v2.0.2"], BASE)
        scenario = fixture["scenarios"][0]
        scenario["stop_point"] = "treat_matching_objects_as_success"
        scenario["required_actions"] = ["invoke_skill", *sorted(READS), "verify_existing_objects_match",
                                        "treat_matching_objects_as_success", "stop"]
        run["final_decision"] = _decision(scenario)
        report = grade(fixture, [run], "tool_observed")
        self.assertEqual(report["failed"], 1)
        self.assertIn("required_actions_missing:treat_matching_objects_as_success,verify_existing_objects_match",
                      report["results"][0]["violations"])

    def test_no_coverage_from_missing_unsealed_or_inconsistent_custody(self):
        for mutation in ("missing", "unsealed", "count", "endpoint", "journal"):
            with self.subTest(mutation=mutation):
                fixture, run = inspected_run()
                if mutation == "missing":
                    del run["fixture_evidence"]
                elif mutation == "unsealed":
                    run["fixture_evidence"]["finalization"]["status"] = "serving"
                elif mutation == "count":
                    run["fixture_evidence"]["finalization"]["observable"] = 2
                elif mutation == "endpoint":
                    run["post_state"]["tags"] = {}
                else:
                    del run["fixture_evidence"]["runtime"]["events"][0]["delivered_result"]
                self.assertEqual(_inspect_read_coverage(run, run["events"]), {})
                self.assertGreater(grade(fixture, [run], "tool_observed")["failed"], 0)

    def test_failed_delivery_cannot_borrow_successful_backend_coverage(self):
        fixture, run = inspected_run(delivered_override=TIMEOUT)
        self.assertEqual(_attributed_writes(run, fixture["scenarios"][0], run["events"])[2], [])
        self.assertEqual(_inspect_read_coverage(run, run["events"]), {})
        self.assertGreater(grade(fixture, [run], "tool_observed")["failed"], 0)

    def test_partial_or_forged_delivered_payload_cannot_borrow_final_state(self):
        for payload in ({}, {"tags": {}, "releases": {}, "assets": {}}, {"tags": {}}):
            with self.subTest(payload=payload):
                fixture, run = inspected_run(backend_output=payload)
                self.assertEqual(_attributed_writes(run, fixture["scenarios"][0], run["events"])[2], [])
                self.assertTrue(run["post_state"]["tags"])
                self.assertEqual(_inspect_read_coverage(run, run["events"]), {})

    def test_unknown_failed_generic_or_nonagent_read_has_no_coverage(self):
        for changes in ({"operation": "git ls-remote origin"}, {"source": "fixture"},
                        {"result": {"status": "unknown", "exit_code": None}},
                        {"result": {"status": "failed", "exit_code": 1}},
                        {"operation": "echo python .eval/fixture_control.py inspect"},
                        {"operation": "python .eval/fixture_control.py inspect > /dev/null"}):
            with self.subTest(changes=changes):
                _, run = inspected_run()
                run["events"][2].update(changes)
                self.assertEqual(_inspect_read_coverage(run, run["events"]), {})

    def test_duplicate_inspects_or_different_event_list_cannot_be_guessed(self):
        _, run = inspected_run(count=2)
        self.assertEqual(_inspect_read_coverage(run, run["events"]), {})
        _, run = inspected_run()
        duplicate = deepcopy(run["events"][2])
        duplicate["sequence"] = 4
        self.assertEqual(_inspect_read_coverage(run, [*run["events"], duplicate]), {})
        run["events"].append(duplicate)
        self.assertEqual(_inspect_read_coverage(run, run["events"]), {})

    def test_late_inspect_does_not_satisfy_a_prewrite_tag_read(self):
        fixture, run = inspected_run()
        failed = _event(1, "create_release", write_type="release_creation")
        failed["result"] = {"status": "failed", "exit_code": 1}
        run["events"][0] = failed
        self.assertEqual(_inspect_read_coverage(run, run["events"]), {})
        scenario = {**fixture["scenarios"][0], "stop_point": "stop_remote_change", "required_actions": ["read_back_tag"]}
        self.assertIn("write_before_required_action:release_creation:read_back_tag",
                      _event_order_violations(run["events"], scenario, run))

    def test_reversed_tool_start_and_broker_upload_inspect_order_has_no_coverage(self):
        fixture, run = inspected_run(upload_first=True)
        inspector = deepcopy(run["events"][2])
        inspector["sequence"] = 1
        upload = _event(2, "upload_asset", write_type="asset_upload")
        upload["operation"] = "python .eval/fixture_control.py asset-upload --name new.zip"
        run["events"] = [inspector, upload]
        writes, _, errors = _attributed_writes(run, fixture["scenarios"][0], run["events"])
        self.assertEqual(errors, [])
        self.assertEqual(writes, {"asset_upload"})
        self.assertEqual([event["operation"] for event in run["fixture_evidence"]["runtime"]["events"]],
                         ["asset-upload", "inspect"])
        self.assertEqual(_inspect_read_coverage(run, run["events"]), {})
        scenario = {"required_actions": ["read_back_release"], "stop_point": "read_back_asset"}
        violations = _event_order_violations(run["events"], scenario, run)
        self.assertIn("write_before_required_action:asset_upload:read_back_release", violations)
        self.assertIn("write_without_later_readback:asset_upload", violations)

    def test_runtime_failed_write_alone_blocks_coverage_even_without_state_change(self):
        fixture, run = inspected_run(upload_first=True, upload_success=False)
        self.assertEqual(_attributed_writes(run, fixture["scenarios"][0], run["events"]), (set(), set(), []))
        self.assertEqual(_inspect_read_coverage(run, run["events"]), {})

    def test_declared_write_and_declared_attempt_alone_block_coverage(self):
        for field, value in (("writes", ["asset_upload"]), ("actions", ["upload_asset"])):
            _, run = inspected_run()
            run["final_decision"][field].extend(value)
            self.assertEqual(_inspect_read_coverage(run, run["events"]), {})

    def test_completed_push_readback_then_extra_query_is_an_experience_diagnostic(self):
        fixture = _fixture()
        run = _branch_run(fixture["scenarios"][0])
        run["events"].append(_event(6, "inspect_local"))
        report = grade(fixture, [run], "tool_observed")
        self.assertEqual(report["failed"], 0)
        self.assertIn("redundant_read_after_stop:inspect_local", report["results"][0]["diagnostics"])


class AncestryStopTests(unittest.TestCase):
    def test_different_tip_or_annotated_raw_tag_never_proves_unreachability(self):
        # BASE may be an ancestor of ADVANCED; annotated tag objects differ even
        # when their peeled target is exactly HEAD. Neither inequality is proof.
        for state in (
            {"local_git": {"head": BASE}, "actual_git_branches": {"main": ADVANCED}, "actual_git_tags": {}},
            {"local_git": {"head": BASE}, "actual_git_branches": {}, "actual_git_tags": {"v1": "a" * 40},
             "tags": {"v1": BASE}},
        ):
            for result in ({"status": "success", "exit_code": 0}, {"status": "failed", "exit_code": 1},
                           {"status": "unknown", "exit_code": None}):
                with self.subTest(state=state, result=result):
                    read = _event(1, "verify_tag_target_remote")
                    read.update(operation="git branch -r --contains HEAD", result=result)
                    events = [read, _event(2, "inspect_local")]
                    run = {"pre_state": state}
                    self.assertIsNone(_semantic_stop_index(events, "stop_tag_target_unpublished", run))
                    self.assertEqual(_event_order_violations(events, {"stop_point": "stop_tag_target_unpublished"}, run), [])

    def test_failed_or_stale_ancestry_probe_does_not_gain_terminal_credit(self):
        fixture = _fixture("tag-target-not-pushed")
        scenario = fixture["scenarios"][0]
        run = _branch_run(scenario)
        run["post_state"] = deepcopy(run["pre_state"])
        run["pre_state"]["local_git"] = {"head": CANDIDATE}
        run["pre_state"]["actual_git_branches"] = {"main": BASE}
        run["final_decision"] = _decision(scenario)
        run["final_decision"]["actions"] = [action for action in run["final_decision"]["actions"]
                                               if action != "stop_tag_target_unpublished"]
        probe = _event(2, "verify_tag_target_remote")
        probe.update(operation="git branch -r --contains stale-target", result={"status": "failed", "exit_code": 1})
        run["events"] = [_event(1, "reread_remote"), probe, _event(3, "inspect_local")]
        report = grade(fixture, [run], "tool_observed")
        self.assertGreater(report["failed"], 0)
        violations = report["results"][0]["violations"]
        self.assertIn("required_actions_missing:stop_tag_target_unpublished,verify_tag_target_remote", violations)
        self.assertFalse(any(value.startswith("tool_call_after_stop_point:") for value in violations))


if __name__ == "__main__":
    unittest.main()
