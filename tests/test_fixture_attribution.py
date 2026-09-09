"""Synthetic attribution evidence only: no Git, model, network, or answer files."""

from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from behavior_fixture_spec import (
    after_operation, before_operation, bind_fixture_aliases, new_fixture_runtime,
    prepare_fixture_spec,
)
from fixture_event_attribution import attribute_fixture_events


BASE, CANDIDATE, ADVANCED = (digit * 40 for digit in "123")
SUCCESS = {"status": "success", "exit_code": 0, "output": {}}
ERROR = {"status": "error", "exit_code": 2, "output": {"error": "synthetic"}}
TIMEOUT = {"status": "timeout", "exit_code": 124, "output": {"error": "timeout"}}


def transition(changes, *, phase="before", operation="branch-read", result=None):
    return {"id": "scheduled-change", "once": True, "changes": changes,
            "trigger": {"phase": phase, "operation": operation, "target": None,
                        "occurrence": 1, "when_result": "any"}, "result": result}


def set_field(path, value):
    return {"path": path, "op": "set", "value": value}


def snapshot(state):
    refs = {}
    for collection in ("branches", "tags"):
        refs[collection] = {}
        for name, target in state[collection].items():
            oid = target if collection == "branches" else {"1": "a", "2": "b", "3": "c"}[target[0]] * 40
            refs[collection][name] = {"ref_oid": oid, "target": target}
    return {"state": deepcopy(state), "git": refs}


def receipts(before, after, updates):
    return [{"source": "fixture", "collection": u["collection"], "name": u["name"],
             "before": deepcopy(before["git"][u["collection"]].get(
                 u["name"], {"ref_oid": None, "target": None})),
             "after": deepcopy(after["git"][u["collection"]].get(
                 u["name"], {"ref_oid": None, "target": None}))} for u in updates]


def evidence(transitions=(), mutate=None, result=None, operation="branch-read", initial=None):
    scenario = {"fixture_setup": {"local_candidate": True, "remote_advanced": True},
                "fixture_state": initial or {}, "fixture_transitions": list(transitions),
                "fixture_requirements": []}
    plan = bind_fixture_aliases(prepare_fixture_spec(scenario),
                               {"base": BASE, "candidate": CANDIDATE, "remote_advanced": ADVANCED})
    pre = snapshot(plan["state"])
    begun = before_operation(plan, pre["state"], new_fixture_runtime(),
                             operation=operation, target="main")
    before_backend = snapshot(begun["state"])
    backend_state = deepcopy(begun["state"])
    if mutate and begun["execute"]:
        mutate(backend_state)
    after_backend = snapshot(backend_state)
    backend_result = (result or SUCCESS) if begun["execute"] else begun["result"]
    finished = after_operation(plan, backend_state, begun["runtime"], backend_result)
    after = snapshot(finished["state"])
    return {"plan": plan, "pre": pre, "post": deepcopy(after),
            "runtime": finished["runtime"], "tool_events": [],
            "observations": [{"before": deepcopy(pre), "before_backend": before_backend,
                              "after_backend": after_backend, "after": after,
                              "git_cas": {"before": receipts(pre, before_backend, begun["git_updates"]),
                                          "after": receipts(after_backend, after, finished["git_updates"])}}]}


def advance():
    return transition([set_field(["branches", "main"], "@remote_advanced")])


def push(state):
    state["branches"]["main"] = CANDIDATE


class FixtureAttributionTests(unittest.TestCase):
    def assert_error(self, case, expected):
        result = attribute_fixture_events(**case)
        self.assertFalse(result["consistent"])
        self.assertIn(expected, result["errors"])
        return result

    def test_read_only_and_empty_runtime(self):
        case = evidence()
        self.assertTrue(attribute_fixture_events(**case)["consistent"])
        case.update(observations=[], runtime=new_fixture_runtime())
        result = attribute_fixture_events(**case)
        self.assertTrue(result["consistent"])
        self.assertEqual(result["model_intervals"], [])

    def test_fixture_branch_change_requires_matched_plan_and_cas(self):
        result = attribute_fixture_events(**evidence([advance()]))
        self.assertTrue(result["consistent"])
        self.assertEqual(result["model_intervals"], [])

    def test_fixture_rules_and_revocation_are_not_model_writes(self):
        hook = transition([set_field(["repository_rules", "requires_pull_request"], True),
                           set_field(["authorization_revoked"], True)])
        result = attribute_fixture_events(**evidence([hook]))
        self.assertTrue(result["consistent"])
        self.assertEqual(result["model_intervals"], [])

    def test_fixture_and_model_write_same_branch(self):
        result = attribute_fixture_events(**evidence([advance()], push))
        self.assertTrue(result["consistent"])
        self.assertEqual(len(result["model_intervals"]), 1)
        interval = result["model_intervals"][0]
        self.assertEqual(interval["pre_state"]["actual_git_branches"]["main"], ADVANCED)
        self.assertEqual(interval["post_state"]["actual_git_branches"]["main"], CANDIDATE)

    def test_after_hook_reversing_model_write_does_not_hide_it(self):
        hook = transition([set_field(["branches", "main"], "@base")], phase="after")
        case = evidence([hook], push)
        self.assertEqual(case["pre"], case["post"])
        result = attribute_fixture_events(**case)
        self.assertTrue(result["consistent"])
        self.assertEqual(result["model_intervals"][0]["post_state"]["branches"]["main"], CANDIDATE)

    def test_reply_timeout_preserves_successful_backend_write(self):
        case = evidence([transition([], phase="after", result=TIMEOUT)], push)
        result = attribute_fixture_events(**case)
        self.assertTrue(result["consistent"])
        self.assertEqual(case["runtime"]["events"][0]["delivered_result"], TIMEOUT)
        self.assertEqual(len(result["model_intervals"]), 1)

    def test_error_after_partial_backend_write_still_counts(self):
        result = attribute_fixture_events(**evidence(mutate=push, result=ERROR))
        self.assertTrue(result["consistent"])
        self.assertEqual(len(result["model_intervals"]), 1)

    def test_unlogged_raw_git_write_survives_without_json_change(self):
        case = evidence([advance()])
        case["post"]["git"]["branches"]["extra"] = {"ref_oid": CANDIDATE, "target": CANDIDATE}
        result = attribute_fixture_events(**case)
        self.assertTrue(result["consistent"])
        self.assertEqual(result["unexplained_deltas"], ["gap:final"])
        self.assertEqual(result["model_intervals"][0]["post_state"]["actual_git_branches"]["extra"], CANDIDATE)

    def test_unlogged_same_branch_write_after_fixture_change(self):
        case = evidence([advance()])
        case["post"]["git"]["branches"]["main"] = {"ref_oid": CANDIDATE, "target": CANDIDATE}
        result = attribute_fixture_events(**case)
        self.assertTrue(result["consistent"])
        self.assertEqual(result["model_intervals"][0]["pre_state"]["actual_git_branches"]["main"], ADVANCED)
        self.assertEqual(result["unexplained_deltas"], ["gap:final"])

    def test_missing_extra_and_duplicate_receipts(self):
        for variant in ([], "extra", "duplicate"):
            with self.subTest(variant=variant):
                case = evidence([advance()])
                entries = case["observations"][0]["git_cas"]["before"]
                if variant == []:
                    entries.clear()
                else:
                    extra = deepcopy(entries[0])
                    if variant == "extra":
                        extra["name"] = "extra"
                    entries.append(extra)
                result = self.assert_error(case, "hook_receipt_count")
                self.assertTrue(result["model_intervals"])

    def test_cas_old_and_new_oid_must_match_observed_refs(self):
        for side in ("before", "after"):
            with self.subTest(side=side):
                case = evidence([advance()])
                case["observations"][0]["git_cas"]["before"][0][side]["ref_oid"] = CANDIDATE
                self.assert_error(case, "hook_cas_" + side + "_mismatch")

    def test_unrelated_ref_change_in_hook_window_is_not_excused(self):
        case = evidence([advance()])
        case["observations"][0]["before_backend"]["git"]["branches"]["extra"] = {
            "ref_oid": CANDIDATE, "target": CANDIDATE}
        result = self.assert_error(case, "unexplained_git_state_delta")
        self.assertIn("extra", result["model_intervals"][0]["post_state"]["actual_git_branches"])

    def test_real_git_backend_change_missing_from_state_is_detected(self):
        case = evidence()
        case["observations"][0]["after_backend"]["git"]["branches"]["main"] = {
            "ref_oid": CANDIDATE, "target": CANDIDATE}
        result = self.assert_error(case, "unexplained_git_state_delta")
        self.assertTrue(result["model_intervals"])

    def test_missing_or_extra_runtime_event(self):
        for extra in (False, True):
            with self.subTest(extra=extra):
                case = evidence([advance()])
                events = case["runtime"]["events"]
                events.append(deepcopy(events[0])) if extra else events.clear()
                self.assert_error(case, "runtime_observation_count")

    def test_backend_delta_cannot_be_deleted_or_relabelled_fixture(self):
        case = evidence(mutate=push)
        event = case["runtime"]["events"][0]
        event["effects"] = [{"source": "fixture", "phase": "before", "transition_id": "invented",
                             "changes": event["backend_changes"]}]
        event["backend_changes"] = []
        result = self.assert_error(case, "runtime_event_mismatch")
        self.assertTrue(result["model_intervals"])

    def test_schedule_phase_occurrence_and_sequence_tampering(self):
        for mutation in ("phase", "counts", "sequence"):
            with self.subTest(mutation=mutation):
                case = evidence([advance()])
                event = case["runtime"]["events"][0]
                if mutation == "phase":
                    event["effects"][0]["phase"] = "after"
                elif mutation == "counts":
                    event["operation_count"] = 9
                else:
                    event["sequence"] = 2
                self.assertFalse(attribute_fixture_events(**case)["consistent"])

    def test_hook_state_change_not_in_plan_is_detected(self):
        case = evidence([advance()])
        case["observations"][0]["before_backend"]["state"]["authorization_revoked"] = True
        self.assert_error(case, "hook_state_mismatch")

    def test_visible_plan_read_candidates_include_failed_commands(self):
        for exit_code in (0, 1):
            with self.subTest(exit_code=exit_code):
                case = evidence()
                case["tool_events"] = [{"command": "Get-Content .eval/fixture-plan.json",
                                        "exit_code": exit_code, "source": "fixture"}]
                result = attribute_fixture_events(**case)
                self.assertEqual(result["plan_read_candidates"], [1])
                self.assertTrue(result["consistent"])
                self.assertTrue(result["advisory"])

    def test_no_access_telemetry_is_required_or_claimed(self):
        case = evidence()
        del case["tool_events"]
        result = attribute_fixture_events(**case)
        self.assertTrue(result["consistent"])
        self.assertTrue(result["advisory"])
        self.assertIn("tool_json_does_not_establish_structural_privacy", result["limitations"])

    def test_controller_recorded_git_effects_match_observations(self):
        case = evidence([advance()])
        case["runtime"]["events"][0]["git_effects"] = deepcopy(case["observations"][0]["git_cas"])
        self.assertTrue(attribute_fixture_events(**case)["consistent"])
        case["runtime"]["events"][0]["git_effects"]["before"] = []
        self.assert_error(case, "recorded_git_effects_mismatch")

    def test_only_final_snapshots_do_not_fabricate_operation_checkpoints(self):
        case = evidence(mutate=push)
        del case["observations"]
        result = self.assert_error(case, "operation_checkpoints_missing")
        self.assertTrue(result["advisory"])
        self.assertEqual(result["model_intervals"][0]["post_state"]["actual_git_branches"]["main"], CANDIDATE)

    def test_cas_source_label_is_not_used_as_authority(self):
        case = evidence([advance()])
        case["observations"][0]["git_cas"]["before"][0]["source"] = "model-supplied-label"
        self.assertTrue(attribute_fixture_events(**case)["consistent"])
        case["observations"][0]["git_cas"]["before"][0]["after"]["target"] = CANDIDATE
        self.assert_error(case, "hook_cas_after_mismatch")

    def test_annotated_tag_ref_oid_and_peeled_target_are_both_checked(self):
        hook = transition([set_field(["tags", "v-synthetic"], "@candidate")])
        case = evidence([hook], initial={"tags": {"v-synthetic": "@base"}})
        self.assertTrue(attribute_fixture_events(**case)["consistent"])
        case["observations"][0]["git_cas"]["before"][0]["after"]["ref_oid"] = "f" * 40
        self.assert_error(case, "hook_cas_after_mismatch")

    def test_fixture_ref_deletion_is_matched(self):
        hook = transition([{"path": ["tags", "v-synthetic"], "op": "delete"}])
        result = attribute_fixture_events(**evidence([hook], initial={"tags": {"v-synthetic": "@base"}}))
        self.assertTrue(result["consistent"])
        self.assertEqual(result["model_intervals"], [])

    def test_pending_runtime_and_missing_checkpoint_fail(self):
        case = evidence()
        case["runtime"]["pending"] = {"operation": "branch-read"}
        self.assert_error(case, "unfinished_or_failed_runtime")
        case = evidence()
        del case["observations"][0]["after_backend"]
        self.assert_error(case, "malformed_attribution_evidence")

    def test_missing_checkpoint_retains_visible_git_write(self):
        case = evidence(mutate=push)
        del case["observations"][0]["after_backend"]
        result = self.assert_error(case, "malformed_attribution_evidence")
        self.assertEqual(result["model_intervals"][0]["post_state"]["actual_git_branches"]["main"], CANDIDATE)

    def test_unlogged_write_before_hook_cannot_be_laundered_by_cas(self):
        case = evidence([advance()])
        observation = case["observations"][0]
        # An unlogged push races ahead of the fixture. Its receipt faithfully
        # captures the real old ref, which disagrees with the controller state.
        real_old = {"ref_oid": CANDIDATE, "target": CANDIDATE}
        observation["before"]["git"]["branches"]["main"] = deepcopy(real_old)
        observation["git_cas"]["before"][0]["before"] = deepcopy(real_old)
        result = self.assert_error(case, "unexplained_git_state_delta")
        self.assertEqual(result["model_intervals"][0]["post_state"]["actual_git_branches"]["main"], CANDIDATE)
        self.assertIn("gap:1", result["unexplained_deltas"])

    def test_same_target_tag_object_rewrite_is_not_a_fixture_effect(self):
        case = evidence([advance()], initial={"tags": {"v-synthetic": "@base"}})
        case["observations"][0]["before_backend"]["git"]["tags"]["v-synthetic"]["ref_oid"] = "f" * 40
        result = self.assert_error(case, "unexplained_hook_git_delta")
        self.assertEqual(result["model_intervals"][0]["post_state"]["actual_git_tags"]["v-synthetic"], "f" * 40)

    def test_inputs_are_not_modified(self):
        case = evidence([advance()], push)
        original = deepcopy(case)
        attribute_fixture_events(**case)
        self.assertEqual(case, original)


if __name__ == "__main__":
    unittest.main()
