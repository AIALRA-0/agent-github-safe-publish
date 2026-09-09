"""Synthetic unit checks only; no private cases, processes, network or Git IO."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from behavior_fixture_spec import (
    FixtureSpecError,
    SPEC_FIELDS,
    after_operation,
    before_operation,
    bind_fixture_aliases,
    fixture_schema_properties,
    new_fixture_runtime,
    prepare_fixture_spec,
    validate_fixture_spec,
    validate_materialized_fixture,
)
from generate_behavior_holdout import (
    _schema,
    validate_calibration_preserves_content,
    validate_holdout_semantics,
)


BASE = "1" * 40
CANDIDATE = "2" * 40
ADVANCED = "3" * 40
COMMITS = {"base": BASE, "candidate": CANDIDATE, "remote_advanced": ADVANCED}
OK = {"status": "success", "exit_code": 0, "output": {"ok": True}}
ERROR = {"status": "error", "exit_code": 2, "output": {"error": "synthetic"}}
TIMEOUT = {"status": "timeout", "exit_code": 124, "output": {"error": "synthetic_timeout"}}


def scenario() -> dict:
    return {"fixture_profile": "default", "fixture_setup": {}, "fixture_state": {},
            "fixture_transitions": [], "fixture_requirements": []}


def requirement(path, value=None, *, kind="equals", at="initial") -> dict:
    result = {"at": at, "kind": kind, "path": path}
    if kind == "equals":
        result["value"] = value
    return result


def transition(*, phase="after", operation="inspect", target=None, occurrence=1,
               once=True, changes=None, result=None, when_result="any", name="changeA") -> dict:
    return {"id": name, "trigger": {"phase": phase, "operation": operation,
                                    "target": target, "occurrence": occurrence,
                                    "when_result": when_result},
            "once": once, "changes": changes or [], "result": result}


def bound(value=None):
    return bind_fixture_aliases(prepare_fixture_spec(value or scenario()), COMMITS)


def observed(plan):
    return {"state": deepcopy(plan["state"]), "local_branches": deepcopy(plan["local_branches"]),
            "remote_branches": deepcopy(plan["state"]["branches"]),
            "remote_tags": deepcopy(plan["state"]["tags"]),
            "current_branch": None if plan["setup"].get("detached_head") else plan["setup"].get("current_branch", "main"),
            "detached": plan["setup"].get("detached_head", False)}


class FixtureSchemaTests(unittest.TestCase):
    def test_generation_schema_and_validator_share_fields(self):
        generated = _schema()["properties"]["scenarios"]["items"]
        self.assertTrue(set(SPEC_FIELDS) <= set(generated["required"]))
        for key, value in fixture_schema_properties().items():
            self.assertEqual(value, generated["properties"][key])
        self.assertFalse(generated["additionalProperties"])

    def test_legacy_records_fail_without_being_filled_or_changed(self):
        original = {"case_id": "public-synthetic", "fixture_profile": "existing_tag"}
        saved = deepcopy(original)
        self.assertTrue(validate_fixture_spec(original))
        with self.assertRaises(FixtureSpecError):
            prepare_fixture_spec(original)
        self.assertEqual(saved, original)

    def test_unknown_unimplemented_fields_and_premises_fail(self):
        for field, addition in (("fixture_setup", {"scanner_result": "clean"}),
                                ("fixture_state", {"tag_signature": "verified"}),
                                ("fixture_state", {"allowed_writes": ["branch_push"]})):
            value = scenario()
            value[field].update(addition)
            self.assertTrue(validate_fixture_spec(value))
        value = scenario()
        value["fixture_requirements"] = [requirement(["unknown_scanner"], True)]
        self.assertIn("requirements[0]:unsupported_premise", validate_fixture_spec(value))

    def test_aliases_bind_real_refs_and_not_free_text(self):
        value = scenario()
        value["fixture_setup"] = {"local_candidate": True, "commit_aliases": {"selected": "candidate"},
                                   "local_branches": {"topic-example": "@selected"},
                                   "current_branch": "topic-example"}
        value["fixture_state"] = {"branches": {"main": "@base", "topic-example": "@selected"},
                                   "tags": {"release-example": "@selected"},
                                   "repository_metadata": {"description": "@selected"}}
        value["fixture_requirements"] = [requirement(["tags", "release-example"], "@candidate")]
        saved = deepcopy(value)
        plan = bound(value)
        self.assertEqual(plan["state"]["tags"]["release-example"], CANDIDATE)
        self.assertEqual(plan["local_branches"]["topic-example"], CANDIDATE)
        self.assertEqual(plan["state"]["repository_metadata"]["description"], "@selected")
        self.assertEqual(plan["requirements"][0]["value"], CANDIDATE)
        self.assertEqual([], validate_materialized_fixture(plan, observed(plan)))
        self.assertEqual(saved, value)

    def test_missing_invalid_or_unsupported_binding_is_not_accepted(self):
        for target in ("@unknown", "deadbeef", "@remote_advanced", "@remote_candidate"):
            value = scenario()
            value["fixture_state"]["tags"] = {"example": target}
            self.assertTrue(validate_fixture_spec(value))
        plan = prepare_fixture_spec(scenario())
        with self.assertRaises(FixtureSpecError):
            bind_fixture_aliases(plan, {"base": BASE})
        with self.assertRaises(FixtureSpecError):
            bind_fixture_aliases(plan, {"base": BASE, "candidate": "pretend"})

    def test_explicit_state_wins_over_profile(self):
        value = scenario()
        value["fixture_profile"] = "existing_release"
        value["fixture_state"] = {"tags": {"example": "@base"}, "releases": {
            "example": {"tag": "example", "title": "Example", "body": "Fixture data",
                        "draft": False, "prerelease": False}}}
        self.assertEqual({"example": BASE}, bound(value)["state"]["tags"])
        value["fixture_profile"] = "protected_branch"
        value["fixture_state"]["repository_rules"] = {"requires_pull_request": False, "admins_enforced": True}
        self.assertFalse(bound(value)["state"]["repository_rules"]["requires_pull_request"])

    def test_named_objects_must_have_real_relationships(self):
        value = scenario()
        value["fixture_state"]["releases"] = {"example": {
            "tag": "missing", "title": "Example", "body": "", "draft": False, "prerelease": False}}
        self.assertIn("state:release_tag_missing", validate_fixture_spec(value))
        value = scenario()
        value["fixture_state"]["pull_requests"] = {"41": {
            "head": "missing", "base": "main", "title": "Example", "body": "",
            "merged": False, "state": "open"}}
        self.assertIn("state:pr_branch_missing", validate_fixture_spec(value))

    def test_initial_requirements_check_absence_and_exact_values(self):
        value = scenario()
        value["fixture_requirements"] = [requirement(["tags", "missing"], kind="exists")]
        self.assertTrue(validate_fixture_spec(value))
        value["fixture_requirements"] = [requirement(["tags", "missing"], kind="absent")]
        self.assertEqual([], validate_fixture_spec(value))
        value["fixture_requirements"] = [requirement(["authorization_revoked"], True)]
        self.assertTrue(validate_fixture_spec(value))

    def test_materialization_must_match_actual_git_not_just_json(self):
        value = scenario()
        value["fixture_state"]["tags"] = {"example": "@base"}
        plan = bound(value)
        facts = observed(plan)
        facts["remote_tags"] = {}
        self.assertIn("materialized:mismatch:remote_tags", validate_materialized_fixture(plan, facts))
        facts = observed(plan)
        facts["remote_branches"]["unexpected"] = CANDIDATE
        self.assertIn("materialized:mismatch:remote_branches", validate_materialized_fixture(plan, facts))
        self.assertTrue(validate_materialized_fixture(prepare_fixture_spec(value), facts))

    def test_paths_and_refs_cannot_escape_preparation(self):
        for path in ("../outside", "C:/outside", "/outside", ".git/config", ".eval/state", "NUL", "dir/../file"):
            value = scenario()
            value["fixture_setup"]["candidate_files"] = {path: "synthetic"}
            self.assertIn("setup:unsafe_path", validate_fixture_spec(value))
        for ref in ("--bad", "a..b", "bad.lock", "refs//bad", "a\nb"):
            value = scenario()
            value["fixture_state"]["branches"] = {ref: "@base"}
            self.assertIn("setup:invalid_ref", validate_fixture_spec(value))

    def test_bool_is_not_an_attempt_number_and_non_json_rejected(self):
        value = scenario()
        value["fixture_transitions"] = [transition(occurrence=True)]
        self.assertTrue(validate_fixture_spec(value))
        value = scenario()
        value["fixture_state"]["repository_metadata"] = {"nan": float("nan")}
        self.assertEqual(["spec:not_json"], validate_fixture_spec(value))

    def test_no_private_values_in_errors_and_no_labels_in_plan(self):
        value = scenario()
        value["fixture_setup"]["DO_NOT_ECHO_THIS"] = "PRIVATE_SENTINEL"
        rendered = json.dumps(validate_fixture_spec(value))
        self.assertNotIn("DO_NOT_ECHO_THIS", rendered)
        self.assertNotIn("PRIVATE_SENTINEL", rendered)
        value = scenario()
        value.update({"request": "PRIVATE_SENTINEL", "required_actions": ["PRIVATE_SENTINEL"],
                      "stop_point": "PRIVATE_SENTINEL", "environment": ["PRIVATE_SENTINEL"]})
        self.assertNotIn("PRIVATE_SENTINEL", json.dumps(prepare_fixture_spec(value)))

    def test_library_does_not_call_process_network_or_filesystem(self):
        with patch("subprocess.run", side_effect=AssertionError("process forbidden")), \
             patch("socket.socket", side_effect=AssertionError("network forbidden")), \
             patch("builtins.open", side_effect=AssertionError("file IO forbidden")):
            plan = bound()
            before = before_operation(plan, plan["state"], new_fixture_runtime(), operation="inspect", target="repository")
            after_operation(plan, before["state"], before["runtime"], OK)


class FixtureTransitionTests(unittest.TestCase):
    def call(self, plan, state, runtime, *, operation="inspect", target="repository", result=OK):
        before = before_operation(plan, state, runtime, operation=operation, target=target)
        return after_operation(plan, before["state"], before["runtime"], result if before["execute"] else before["result"])

    def test_before_once_changes_state_and_persists_across_json_roundtrip(self):
        value = scenario()
        value["fixture_transitions"] = [transition(phase="before", occurrence=None, changes=[
            {"op": "set", "path": ["authorization_revoked"], "value": True}])]
        plan = bound(value)
        runtime = new_fixture_runtime()
        original_state, original_runtime = deepcopy(plan["state"]), deepcopy(runtime)
        first = self.call(plan, plan["state"], runtime)
        self.assertTrue(first["state"]["authorization_revoked"])
        self.assertEqual(1, len(first["event"]["effects"]))
        first = json.loads(json.dumps(first))
        second = self.call(plan, first["state"], first["runtime"])
        self.assertEqual([], second["event"]["effects"])
        self.assertEqual(2, len(second["runtime"]["events"]))
        self.assertEqual(original_state, plan["state"])
        self.assertEqual(original_runtime, runtime)

    def test_before_failure_skips_backend_and_records_attempt(self):
        value = scenario()
        value["fixture_transitions"] = [transition(phase="before", operation="asset-upload", result=TIMEOUT)]
        plan = bound(value)
        first = self.call(plan, plan["state"], new_fixture_runtime(), operation="asset-upload", target="example.zip")
        self.assertEqual(TIMEOUT, first["result"])
        self.assertFalse(first["event"]["backend_executed"])
        self.assertIsNone(first["event"]["backend_result"])
        self.assertEqual([], first["event"]["backend_changes"])
        self.assertIsNone(first["runtime"]["pending"])

    def test_committed_write_and_timeout_preserve_actual_success(self):
        value = scenario()
        value["fixture_transitions"] = [transition(operation="asset-upload", result=TIMEOUT, when_result="success")]
        plan = bound(value)
        before = before_operation(plan, plan["state"], new_fixture_runtime(), operation="asset-upload", target="example.zip")
        committed = deepcopy(before["state"])
        committed["assets"]["example.zip"] = {"size": 9, "sha256": "a" * 64}
        final = after_operation(plan, committed, before["runtime"], OK)
        self.assertEqual(TIMEOUT, final["result"])
        self.assertEqual(OK, final["event"]["backend_result"])
        self.assertIn("example.zip", final["state"]["assets"])
        self.assertEqual("assets", final["event"]["backend_changes"][0]["field"])
        restored = json.loads(json.dumps(final))
        self.assertEqual(final, restored)

    def test_after_read_changes_have_environment_attribution_and_git_updates(self):
        value = scenario()
        value["fixture_setup"]["remote_advanced"] = True
        value["fixture_transitions"] = [transition(changes=[
            {"path": ["branches", "main"], "op": "set", "value": "@remote_advanced"}])]
        value["fixture_requirements"] = [requirement(["branches", "main"], "@remote_advanced", at="changeA")]
        plan = bound(value)
        final = self.call(plan, plan["state"], new_fixture_runtime())
        self.assertEqual([], final["event"]["backend_changes"])
        self.assertEqual("fixture", final["event"]["effects"][0]["source"])
        self.assertEqual([{"collection": "branches", "name": "main", "target": ADVANCED}], final["git_updates"])

    def test_exact_target_occurrence_and_wildcard_count_differ(self):
        value = scenario()
        value["fixture_transitions"] = [transition(target="wanted", occurrence=2, changes=[
            {"path": ["authorization_revoked"], "op": "set", "value": True}])]
        plan = bound(value)
        state, runtime = plan["state"], new_fixture_runtime()
        for target, expected in (("other", False), ("wanted", False), ("other", False), ("wanted", True)):
            final = self.call(plan, state, runtime, target=target)
            state, runtime = final["state"], final["runtime"]
            self.assertIs(expected, state["authorization_revoked"])
        self.assertEqual(4, final["event"]["operation_count"])
        self.assertEqual(2, final["event"]["target_count"])

    def test_repeat_failure_result_and_success_condition_do_not_consume_once(self):
        value = scenario()
        value["fixture_transitions"] = [transition(occurrence=None, when_result="success", result=TIMEOUT)]
        plan = bound(value)
        first = self.call(plan, plan["state"], new_fixture_runtime(), result=ERROR)
        self.assertEqual([], first["runtime"]["applied"])
        second = self.call(plan, first["state"], first["runtime"])
        self.assertEqual(TIMEOUT, second["result"])
        third = self.call(plan, second["state"], second["runtime"])
        self.assertEqual(OK, third["result"])

    def test_legacy_failure_list_has_repeat_semantics_without_duplicate_backend_failure(self):
        value = scenario()
        value["fixture_state"]["fail_operations"] = ["inspect"]
        plan = bound(value)
        self.assertNotIn("fail_operations", plan["state"])
        first = self.call(plan, plan["state"], new_fixture_runtime())
        second = self.call(plan, first["state"], first["runtime"])
        self.assertFalse(second["event"]["backend_executed"])
        self.assertEqual(2, second["event"]["operation_count"])

    def test_pending_or_finished_operations_cannot_be_replayed(self):
        plan = bound()
        before = before_operation(plan, plan["state"], new_fixture_runtime(), operation="inspect", target="repository")
        with self.assertRaisesRegex(FixtureSpecError, "pending_requires_reconciliation"):
            before_operation(plan, before["state"], before["runtime"], operation="inspect", target="repository")
        final = after_operation(plan, before["state"], before["runtime"], OK)
        with self.assertRaisesRegex(FixtureSpecError, "no_pending_call"):
            after_operation(plan, final["state"], final["runtime"], OK)

    def test_skipped_backend_cannot_smuggle_changes(self):
        value = scenario()
        value["fixture_transitions"] = [transition(phase="before", result=ERROR)]
        plan = bound(value)
        before = before_operation(plan, plan["state"], new_fixture_runtime(), operation="inspect", target="repository")
        changed = deepcopy(before["state"])
        changed["authorization_revoked"] = True
        with self.assertRaisesRegex(FixtureSpecError, "skipped_backend_changed"):
            after_operation(plan, changed, before["runtime"], ERROR)

    def test_transition_schema_rejects_unknown_operations_paths_and_fabricated_success(self):
        mutations = [transition(operation="arbitrary-shell"), transition(phase="before", result=OK),
                     transition(changes=[{"path": ["allowed_writes"], "op": "set", "value": []}]),
                     transition(phase="before", when_result="success")]
        for item in mutations:
            value = scenario()
            value["fixture_transitions"] = [item]
            self.assertTrue(validate_fixture_spec(value))

    def test_invalid_after_hook_preserves_backend_result_and_stops_future_calls(self):
        value = scenario()
        value["fixture_transitions"] = [transition(operation="asset-upload")]
        value["fixture_requirements"] = [requirement(["authorization_revoked"], True, at="changeA")]
        plan = bound(value)
        before = before_operation(plan, plan["state"], new_fixture_runtime(), operation="asset-upload", target="example.zip")
        state = deepcopy(before["state"])
        state["assets"]["example.zip"] = {"size": 1, "sha256": "b" * 64}
        final = after_operation(plan, state, before["runtime"], OK)
        self.assertTrue(final["fixture_errors"])
        self.assertEqual(OK, final["event"]["backend_result"])
        self.assertIn("example.zip", final["state"]["assets"])
        self.assertIsNone(final["runtime"]["pending"])
        with self.assertRaisesRegex(FixtureSpecError, "fixture_requires_reconciliation"):
            before_operation(plan, final["state"], final["runtime"], operation="inspect", target="repository")

    def test_malformed_collection_change_is_rejected_without_crashing(self):
        value = scenario()
        value["fixture_transitions"] = [transition(changes=[{"path": ["branches"], "op": "set", "value": None}])]
        self.assertTrue(validate_fixture_spec(value))

    def test_after_override_cannot_turn_backend_failure_into_success(self):
        value = scenario()
        value["fixture_transitions"] = [transition(result=OK)]
        plan = bound(value)
        final = self.call(plan, plan["state"], new_fixture_runtime(), result=ERROR)
        self.assertIn("transition:cannot_fabricate_backend_success", final["fixture_errors"])
        self.assertEqual(ERROR, final["event"]["backend_result"])


class GeneratorPreservationTests(unittest.TestCase):
    def candidate(self):
        item = scenario()
        item.update({"case_id": "holdout-synthetic-unit", "request": "Synthetic request",
                     "environment": ["Synthetic initial state"], "should_invoke": True,
                     "path": "ordinary", "required_actions": ["invoke_skill", "stop"],
                     "forbidden_actions": [], "allowed_writes": [], "stop_point": "stop",
                     "rationale": "Synthetic rationale"})
        item["fixture_requirements"] = [requirement(["authorization_revoked"], False)]
        return {"schema_version": "2.0.2", "status": "candidate", "purpose": "Unit check", "scenarios": [item]}

    def test_only_execution_fields_may_change_during_calibration(self):
        original = self.candidate()
        updated = deepcopy(original)
        updated["scenarios"][0]["fixture_setup"]["shallow"] = True
        self.assertEqual([], validate_calibration_preserves_content(original, updated))
        for field in ("request", "environment", "required_actions", "allowed_writes", "stop_point", "fixture_profile"):
            changed = deepcopy(updated)
            changed["scenarios"][0][field] = "changed"
            self.assertEqual(["calibration_content_changed"], validate_calibration_preserves_content(original, changed))

    def test_duplicate_labels_stay_failures_without_mutation(self):
        fixture = self.candidate()
        fixture["scenarios"][0]["required_actions"].append("invoke_skill")
        original = deepcopy(fixture)
        self.assertTrue(any("duplicate_required_actions" in e for e in validate_holdout_semantics(fixture)))
        self.assertEqual(original, fixture)

    def test_real_object_precondition_does_not_depend_on_profile_name(self):
        fixture = self.candidate()
        item = fixture["scenarios"][0]
        item["required_actions"] = ["invoke_skill", "create_release", "read_back_release", "stop"]
        item["allowed_writes"] = ["release_creation"]
        self.assertTrue(any("required_object_not_prepared" in e for e in validate_holdout_semantics(fixture)))
        item["fixture_state"]["tags"] = {"example": "@base"}
        item["fixture_requirements"] = [requirement(["tags", "example"], "@base")]
        self.assertEqual([], validate_holdout_semantics(fixture))


if __name__ == "__main__":
    unittest.main()
