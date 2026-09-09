"""Declarative scanner capability only; no scanner, model, or runtime execution."""

from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from behavior_fixture_spec import (
    FixtureSpecError, bind_fixture_aliases, fixture_schema_properties,
    prepare_fixture_spec, validate_fixture_spec,
)


def scenario():
    return {"fixture_setup": {}, "fixture_state": {},
            "fixture_transitions": [], "fixture_requirements": []}


class ScannerAvailableFixtureTests(unittest.TestCase):
    def test_schema_declares_optional_boolean_without_default(self):
        setup = fixture_schema_properties()["fixture_setup"]
        self.assertEqual(setup["properties"]["scanner_available"], {"type": "boolean"})
        self.assertNotIn("scanner_available", setup.get("required", []))

    def test_explicit_values_survive_preparation_and_binding_without_state_changes(self):
        for available in (False, True):
            with self.subTest(available=available):
                value = scenario()
                value["fixture_setup"]["scanner_available"] = available
                original = deepcopy(value)
                plan = prepare_fixture_spec(value)
                bound = bind_fixture_aliases(plan, {"base": "1" * 40, "candidate": "2" * 40})
                self.assertIs(plan["setup"]["scanner_available"], available)
                self.assertIs(bound["setup"]["scanner_available"], available)
                self.assertEqual(plan["state"], prepare_fixture_spec(scenario())["state"])
                self.assertNotIn("scanner_available", bound["state"])
                self.assertEqual(value, original)

    def test_non_booleans_are_rejected_without_coercion(self):
        for invalid in (None, 0, 1, "false", "true", [], {}):
            with self.subTest(invalid=invalid):
                value = scenario()
                value["fixture_setup"]["scanner_available"] = invalid
                self.assertTrue(validate_fixture_spec(value))
                with self.assertRaises(FixtureSpecError):
                    prepare_fixture_spec(value)

    def test_omission_does_not_infer_availability_from_case_id_or_labels(self):
        for case_id in ("auto-scanner-unavailable", "required-scanner-unavailable", "mirror-history-migration"):
            with self.subTest(case_id=case_id):
                value = scenario()
                value.update(case_id=case_id, path="required_scan_choice",
                             required_actions=["scanner_unavailable"], environment=["No scanner is installed."])
                plan = prepare_fixture_spec(value)
                bound = bind_fixture_aliases(plan, {"base": "1" * 40, "candidate": "2" * 40})
                self.assertNotIn("scanner_available", plan["setup"])
                self.assertNotIn("scanner_available", bound["setup"])

    def test_explicit_boolean_is_not_overridden_by_case_identity(self):
        for case_id, available in (("auto-scanner-unavailable", True), ("mirror-history-migration", False)):
            with self.subTest(case_id=case_id):
                value = scenario()
                value["case_id"] = case_id
                value["fixture_setup"]["scanner_available"] = available
                self.assertIs(prepare_fixture_spec(value)["setup"]["scanner_available"], available)

    def test_only_three_public_cases_explicitly_declare_availability(self):
        path = Path(__file__).resolve().parents[1] / "evals/candidate/publication-behavior-v2.0.2.json"
        cases = json.loads(path.read_text(encoding="utf-8"))["scenarios"]
        self.assertEqual(len(cases), 38)
        actual = {case["case_id"]: case["fixture_setup"]["scanner_available"]
                  for case in cases if "scanner_available" in case["fixture_setup"]}
        self.assertEqual(actual, {"auto-scanner-unavailable": False,
                                  "required-scanner-unavailable": False,
                                  "mirror-history-migration": True})
        for case in cases:
            self.assertEqual(validate_fixture_spec(case), [], case["case_id"])


if __name__ == "__main__":
    unittest.main()
