"""Transport-only synthetic tests: no models, private fixtures, Git or network."""

from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import generate_behavior_holdout as subject


def fixture():
    return {"schema_version": "2.0.2", "status": "candidate", "purpose": "synthetic transport test",
            "scenarios": [{"case_id": f"holdout-synthetic-{index}", "request": "Synthetic text task",
                           "environment": [], "should_invoke": False, "path": "not_applicable",
                           "required_actions": [], "forbidden_actions": [], "allowed_writes": [],
                           "stop_point": "no_skill_invocation", "rationale": "Synthetic transport only",
                           "fixture_profile": "default", "fixture_setup": {}, "fixture_state": {},
                           "fixture_transitions": [], "fixture_requirements": []} for index in range(8)]}


def encoded(payload):
    result = deepcopy(payload)
    for scenario in result["scenarios"]:
        for field in subject.SPEC_FIELDS:
            scenario[field] = json.dumps(scenario[field], ensure_ascii=False)
    return result


class HoldoutTransportTests(unittest.TestCase):
    def test_output_schema_is_recursively_strict_and_only_spec_fields_are_encoded(self):
        def strict(schema):
            self.assertTrue(schema)
            if "anyOf" in schema:
                for child in schema["anyOf"]:
                    strict(child)
                return
            self.assertIn("type", schema)
            if schema["type"] == "object":
                self.assertIs(schema["additionalProperties"], False)
                self.assertEqual(set(schema["properties"]), set(schema["required"]))
                for child in schema["properties"].values():
                    strict(child)
            if schema["type"] == "array":
                strict(schema["items"])

        output = subject._schema()
        strict(output)
        case = output["properties"]["scenarios"]["items"]["properties"]
        self.assertEqual(case["fixture_encoding"], {"type": "string", "const": "native-v1"})
        self.assertEqual(case["fixture_setup"]["type"], "object")
        self.assertEqual(case["fixture_state"]["type"], "object")
        self.assertEqual(case["fixture_transitions"]["type"], "array")
        self.assertEqual(case["fixture_requirements"]["type"], "array")
        for field in ("required_actions", "forbidden_actions", "allowed_writes", "environment"):
            self.assertEqual(case[field]["type"], "array")
        self.assertEqual(case["should_invoke"]["type"], "boolean")

    def test_encoded_and_canonical_roundtrip_without_mutation(self):
        canonical = fixture()
        canonical["scenarios"][0]["fixture_setup"] = {"candidate_files": {"unicode.txt": "中文\ntext"}}
        for source in (canonical, encoded(canonical)):
            before = deepcopy(source)
            self.assertEqual(subject._decode_fixture_transport(source), canonical)
            self.assertEqual(source, before)

    def test_native_transport_roundtrip_covers_maps_optional_fields_and_arbitrary_values(self):
        canonical = fixture()
        scenario = canonical["scenarios"][0]
        scenario["fixture_setup"] = {
            "candidate_files": {"unicode.txt": "中文\ntext"},
            "local_tags": {"v2.0.2": "@candidate"},
        }
        scenario["fixture_state"] = {
            "branches": {"main": "@base"},
            "repository_rules": {"requires_pull_request": True, "admins_enforced": False},
        }
        scenario["fixture_requirements"] = [
            {"at": "initial", "kind": "equals", "path": ["repository_rules"],
             "value": {"requires_pull_request": True, "admins_enforced": False}},
        ]
        native = subject._encode_fixture_transport(canonical)
        self.assertEqual(subject._decode_fixture_transport(native), canonical)
        self.assertEqual(native["scenarios"][0]["fixture_encoding"], "native-v1")
        self.assertIsInstance(native["scenarios"][0]["fixture_setup"], dict)
        self.assertIsInstance(native["scenarios"][0]["fixture_requirements"], list)

    def test_malformed_duplicate_and_nonfinite_json_rejected_at_both_layers(self):
        bad = ('{', '{} {}', '{"x":1,"x":2}', '{"nested":{"x":1,"x":2}}',
               '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}', '{"x":1e999}')
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    subject._strict_json_loads(text)
                payload = encoded(fixture())
                payload["scenarios"][0]["fixture_state"] = text
                with self.assertRaises(ValueError):
                    subject._decode_fixture_transport(payload)

    def test_wrong_container_missing_fields_and_double_encoding_rejected(self):
        for field in subject.SPEC_FIELDS:
            for bad in (None, True, 1, 'null', 'true', '1', '"{}"',
                        '[]' if field in ("fixture_setup", "fixture_state") else '{}'):
                with self.subTest(field=field, bad=bad):
                    payload = encoded(fixture())
                    payload["scenarios"][0][field] = bad
                    with self.assertRaises(ValueError):
                        subject._decode_fixture_transport(payload)
            payload = fixture()
            del payload["scenarios"][0][field]
            with self.assertRaises(ValueError):
                subject._decode_fixture_transport(payload)
        for bad in ([], {}, {"scenarios": {}}, {"scenarios": [None]}):
            with self.assertRaises(ValueError):
                subject._decode_fixture_transport(bad)

    def test_transport_recovers_only_redundant_trailing_structural_closers(self):
        payload = encoded(fixture())
        payload["scenarios"][0]["fixture_requirements"] += "}]}"
        self.assertEqual(subject._decode_fixture_transport(payload), fixture())
        for trailing in (" second", " []", " {}", ",", "]x", "]" * 9):
            with self.subTest(trailing=trailing):
                malformed = encoded(fixture())
                malformed["scenarios"][0]["fixture_requirements"] += trailing
                with self.assertRaises(ValueError):
                    subject._decode_fixture_transport(malformed)

    def run_main(self, root, generated, calibrated, *, resume=False):
        public = root / "public.json"
        public.write_text('{"scenarios": []}', encoding="utf-8")
        skill = root / "skill.txt"
        skill.write_text("Synthetic skill", encoding="utf-8")
        raw, final = root / "raw", root / "final.json"
        args = ["--public-cases", str(public), "--skill", str(skill),
                "--raw-output-dir", str(raw), "--holdout-output", str(final)]
        texts = {"generation": json.dumps(generated), "calibration": json.dumps(calibrated)}
        if resume:
            for flag, label in (("--generated-candidate", "generation"),
                                ("--calibrated-candidate", "calibration")):
                path = root / (label + ".json")
                path.write_text(texts[label], encoding="utf-8")
                args.extend([flag, str(path)])

        def fake_call(**kwargs):
            # Prompt reference is the full original DSL, not the strict transport schema.
            prompt = kwargs["prompt"]
            reference = prompt.split("<fixture_schema_reference>\n", 1)[1].split(
                "\n</fixture_schema_reference>", 1)[0]
            self.assertEqual(json.loads(reference), subject.fixture_schema_properties())
            self.assertIn("native-v1 transport required by the output schema", prompt)
            self.assertIn("schema maps use arrays of unique key/value entries", prompt)
            self.assertIn("only unconstrained leaf values are JSON-encoded strings", prompt)
            if kwargs["label"] == "calibration":
                candidate = prompt.split("<candidate_holdout>\n", 1)[1].split("\n</candidate_holdout>", 1)[0]
                self.assertEqual(subject._decode_fixture_transport(json.loads(candidate)),
                                 subject._decode_fixture_transport(generated))
            kwargs["output_path"].write_text(texts[kwargs["label"]], encoding="utf-8")
            return 0

        with mock.patch.object(subject, "_run_codex", side_effect=fake_call) as call, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = subject.main(args)
        if resume:
            call.assert_not_called()
        elif code == 0:
            self.assertEqual(call.call_count, 2)
        for label, name in (("generation", "generated"), ("calibration", "calibrated")):
            saved = raw / (name + "-candidate.private.json")
            if saved.exists():
                self.assertEqual(saved.read_bytes(), texts[label].encode("utf-8"))
        return code, final, output.getvalue()

    def test_main_encoded_and_canonical_resume_keep_raw_and_output_original_format(self):
        for resume in (False, True):
            with self.subTest(resume=resume), tempfile.TemporaryDirectory() as directory:
                canonical = fixture()
                source = canonical if resume else encoded(canonical)
                code, final, _ = self.run_main(Path(directory), source, source, resume=resume)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(final.read_text(encoding="utf-8")), canonical)

    def test_calibration_change_outside_spec_is_still_rejected_after_decode(self):
        original = encoded(fixture())
        changed = deepcopy(original)
        changed["scenarios"][0]["request"] += " changed"
        with tempfile.TemporaryDirectory() as directory:
            code, final, output = self.run_main(Path(directory), original, changed)
            self.assertEqual(code, 1)
            self.assertFalse(final.exists())
            self.assertIn("invalid_calibrated_holdout", output)

    def test_existing_dsl_validation_rejects_unknown_decoded_fields(self):
        source = fixture()
        source["scenarios"][0]["fixture_setup"]["unimplemented"] = True
        source = encoded(source)
        with tempfile.TemporaryDirectory() as directory:
            code, final, output = self.run_main(Path(directory), source, source)
            self.assertEqual(code, 1)
            self.assertFalse(final.exists())
            self.assertIn("invalid_generated_holdout", output)

    def test_invalid_transport_status_does_not_echo_input(self):
        for stage in ("generation", "calibration"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                original = encoded(fixture())
                bad = deepcopy(original)
                bad["scenarios"][0]["fixture_state"] = '{"HIDDEN_INPUT": NaN}'
                generated, calibrated = (bad, original) if stage == "generation" else (original, bad)
                code, final, output = self.run_main(Path(directory), generated, calibrated)
                self.assertEqual(code, 1)
                self.assertFalse(final.exists())
                self.assertNotIn("HIDDEN", output)
                self.assertIn("invalid_generated_transport" if stage == "generation"
                              else "invalid_calibrated_transport", output)


if __name__ == "__main__":
    unittest.main()
