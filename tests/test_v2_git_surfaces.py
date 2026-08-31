from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from github_safe_publish.detectors import inspect_tree  # noqa: E402
from github_safe_publish.planner import remediation_plan  # noqa: E402
from github_safe_publish.policy import default_policy  # noqa: E402
from github_safe_publish.transformers import transform_candidate  # noqa: E402


class GitSurfaceTests(unittest.TestCase):
    def test_lfs_pointer_and_submodule_are_removed_only_when_optional(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pointer = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 123\n"
            (root / "model.bin").write_text(pointer, encoding="utf-8")
            (root / ".gitattributes").write_text("model.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8")
            (root / ".gitmodules").write_text('[submodule "private"]\n\tpath = private\n\turl = ssh://private.invalid/repo\n', encoding="utf-8")
            policy = default_policy()
            policy["degradation_policy"]["optional_paths"] = ["model.bin", ".gitmodules"]
            findings, _ = inspect_tree(root, policy)
            actions, needs_input = remediation_plan(findings, policy)
            self.assertFalse(needs_input)
            transform_candidate(root, actions, policy)
            self.assertFalse((root / "model.bin").exists())
            self.assertFalse((root / ".gitmodules").exists())
            self.assertNotIn("filter=lfs", (root / ".gitattributes").read_text(encoding="utf-8"))

    def test_legal_match_requires_owner_decision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "LICENSE").write_text("Copyright Private Person\n", encoding="utf-8")
            policy = default_policy()
            policy["sensitive_entities"] = [
                {"id": "private.owner", "kind": "literal", "value": "Private Person", "category": "private-identity"}
            ]
            findings, _ = inspect_tree(root, policy)
            _, needs_input = remediation_plan(findings, policy)
            self.assertEqual(["legal.protected-content"], [item.rule_id for item in needs_input])

    def test_oversized_object_is_not_loaded_as_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "large.dat").write_bytes(b"x" * 1024)
            policy = default_policy()
            policy["security_runtime"]["maximum_object_bytes"] = 128
            findings, _ = inspect_tree(root, policy)
            self.assertEqual(["artifact.oversized"], [item.rule_id for item in findings])


if __name__ == "__main__":
    unittest.main()
