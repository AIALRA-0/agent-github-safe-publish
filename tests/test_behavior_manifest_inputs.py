"""Critical custody, executor, schema and generator inputs must be bound."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_behavior_evidence_manifest import INPUTS  # noqa: E402
import verify_behavior_evidence as verifier  # noqa: E402


CRITICAL_INPUTS = {
    "scripts/fixture_broker.py",
    "scripts/fixture_broker_client.py",
    "scripts/fixture_broker_runtime.py",
    "scripts/fixture_event_attribution.py",
    "scripts/run_github_e2e.py",
    "scripts/generate_behavior_holdout.py",
    "evals/schema/final-decision-v2.0.2.schema.json",
    "evals/schema/behavior-run-v2.0.2.schema.json",
}


class BehaviorManifestInputTests(unittest.TestCase):
    def test_builder_and_verifier_bind_all_critical_inputs(self):
        self.assertTrue(CRITICAL_INPUTS <= set(INPUTS))
        self.assertTrue(CRITICAL_INPUTS <= verifier.EVALUATED_INPUTS)
        self.assertEqual(set(INPUTS), verifier.EVALUATED_INPUTS)
        self.assertEqual(len(INPUTS), len(set(INPUTS)))
        root = Path(__file__).resolve().parents[1]
        for relative in CRITICAL_INPUTS:
            with self.subTest(input=relative):
                self.assertTrue((root / relative).is_file())

    def test_verifier_rejects_each_omitted_critical_input(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            for omitted in sorted(CRITICAL_INPUTS):
                with self.subTest(input=omitted):
                    manifest.write_text(json.dumps({
                        "schema_version": "2.0.2", "evaluated_commit": "a" * 40,
                        "evaluated_inputs": {relative: "b" * 64 for relative in INPUTS if relative != omitted},
                        "evidence_outputs": {},
                    }), encoding="utf-8")
                    # Isolate input-set enforcement; no Git or evidence reports are read.
                    with mock.patch.object(verifier, "_git", return_value=subprocess.CompletedProcess([], 0, b"")), \
                         mock.patch.object(verifier, "_repository_file", return_value=None):
                        errors = verifier.verify(manifest, required=True)
                    self.assertIn("evaluated_input_set_mismatch", errors)


if __name__ == "__main__":
    unittest.main()
