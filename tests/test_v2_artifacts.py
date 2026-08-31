from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from github_safe_publish.detectors import inspect_tree  # noqa: E402
from github_safe_publish.model import RemediationAction  # noqa: E402
from github_safe_publish.policy import default_policy  # noqa: E402
from github_safe_publish.transformers import transform_candidate  # noqa: E402


class ArtifactTransformerTests(unittest.TestCase):
    def test_database_notebook_archive_and_optional_binary_are_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = "private-" + "artifact-value"
            database = sqlite3.connect(root / "records.sqlite")
            database.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, value TEXT)")
            database.execute("INSERT INTO contacts(value) VALUES (?)", (marker,))
            database.commit()
            database.close()
            notebook = {
                "cells": [{"cell_type": "code", "source": [f'owner = "{marker}"\n'], "outputs": [{"text": marker}], "execution_count": 1}],
                "metadata": {"author": marker},
                "nbformat": 4,
                "nbformat_minor": 5,
            }
            (root / "analysis.ipynb").write_text(json.dumps(notebook), encoding="utf-8")
            with zipfile.ZipFile(root / "samples.zip", "w") as archive:
                archive.writestr("sample.txt", f"token={marker}\n")
            (root / "opaque.bin").write_bytes(marker.encode())
            policy = default_policy()
            policy["sensitive_entities"] = [{"id": "private.marker", "kind": "literal", "value": marker, "category": "private-identity"}]
            policy["synthetic_mappings"] = [{"entity_id": "private.marker", "replacement": "ExampleValue"}]
            policy["degradation_policy"]["optional_paths"] = ["opaque.bin"]
            actions = [
                RemediationAction("a1", "f1", "synthesize", "records.sqlite"),
                RemediationAction("a2", "f2", "regenerate", "analysis.ipynb"),
                RemediationAction("a3", "f3", "repack", "samples.zip"),
                RemediationAction("a4", "f4", "remove-and-stub", "opaque.bin"),
            ]
            _, removed = transform_candidate(root, actions, policy)
            self.assertIn("opaque.bin", removed)
            connection = sqlite3.connect(root / "records.sqlite")
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM contacts").fetchone()[0])
            connection.close()
            sanitized_notebook = json.loads((root / "analysis.ipynb").read_text(encoding="utf-8"))
            self.assertEqual([], sanitized_notebook["cells"][0]["outputs"])
            self.assertEqual({}, sanitized_notebook["metadata"])
            with zipfile.ZipFile(root / "samples.zip") as archive:
                self.assertNotIn(marker, archive.read("sample.txt").decode())
            findings, _ = inspect_tree(root, policy)
            self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
