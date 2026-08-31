from __future__ import annotations

from pathlib import Path
import copy
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from github_safe_publish.detectors import inspect_tree  # noqa: E402
from github_safe_publish.policy import default_policy, migrate_policy, policy_sha256, validate_policy  # noqa: E402


class PolicyV4Tests(unittest.TestCase):
    def test_default_policy_has_every_required_section(self) -> None:
        policy = validate_policy(default_policy())
        self.assertEqual(4, policy["schema_version"])
        self.assertEqual("minor", policy["degradation_policy"]["maximum_automatic"])

    def test_version_three_migrates_in_memory(self) -> None:
        legacy = {
            "schema_version": 3,
            "identifiers": [{"id": "owner", "kind": "literal", "value": "Private Person"}],
            "replacements": [{"rule_id": "owner", "replacement": "Example Person"}],
            "approved_locations": [],
            "blocked_paths": ["private.db"],
            "binary_approvals": [],
            "exceptions": [],
            "risk_acceptances": [],
        }
        migrated = validate_policy(legacy)
        self.assertEqual(4, migrated["schema_version"])
        self.assertEqual("private.db", migrated["object_rules"][0]["path"])
        self.assertEqual(3, legacy["schema_version"])

    def test_versions_one_and_two_migrate_to_version_four_in_memory(self) -> None:
        for version in (1, 2):
            with self.subTest(version=version):
                legacy = {
                    "schema_version": version,
                    "identifiers": [{"id": "owner", "kind": "literal", "value": "Synthetic Owner"}],
                    "replacements": [{"rule_id": "owner", "replacement": "Example Owner"}],
                    "blocked_paths": ["private.bin"],
                }
                migrated = validate_policy(legacy)
                self.assertEqual(4, migrated["schema_version"])
                self.assertEqual("private.bin", migrated["object_rules"][0]["path"])
                self.assertEqual(version, legacy["schema_version"])

    def test_major_automatic_degradation_is_rejected(self) -> None:
        policy = default_policy()
        policy["degradation_policy"]["maximum_automatic"] = "major"
        with self.assertRaises(ValueError):
            validate_policy(policy)

    def test_retention_evidence_binds_one_object_policy_scanners_and_expiry(self) -> None:
        policy = default_policy()
        binding_document = copy.deepcopy(policy)
        binding_document["retention_rules"] = []
        policy["retention_rules"] = [{
            "action": "retain-public",
            "object": "README.md",
            "sha256": "a" * 64,
            "scanner_ids": ["github-safe-publish-2.0.0-rc.1"],
            "tool_version": "2.0.0-rc.1",
            "policy_sha256": policy_sha256(binding_document),
            "issued_by": "information-owner",
            "issued_at": "2026-08-31T00:00:00Z",
            "expires_at": "2099-01-01T00:00:00Z",
            "review_trigger": "content-policy-scanner-or-expiry-change",
        }]
        self.assertEqual("README.md", validate_policy(policy)["retention_rules"][0]["object"])
        policy["retention_rules"][0]["object"] = "*.md"
        with self.assertRaisesRegex(ValueError, "exact object"):
            validate_policy(policy)

    def test_object_rules_and_optional_paths_cannot_escape_the_candidate(self) -> None:
        for field, value in (
            ("object", {"path": "../../outside", "action": "remove"}),
            ("rename", {"path": "safe.txt", "action": "rename", "target": "../outside"}),
        ):
            with self.subTest(field=field):
                policy = default_policy()
                policy["object_rules"] = [value]
                with self.assertRaisesRegex(ValueError, "repository-relative"):
                    validate_policy(policy)
        policy = default_policy()
        policy["degradation_policy"]["optional_paths"] = ["../outside"]
        with self.assertRaisesRegex(ValueError, "repository-relative"):
            validate_policy(policy)

    def test_public_url_is_an_observation_not_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text("See https://example.invalid for AIALRA\n", encoding="utf-8")
            findings, observations = inspect_tree(root, default_policy())
            self.assertEqual([], findings)
            self.assertEqual({"public.url", "public.brand"}, {item.rule_id for item in observations})

    def test_unknown_policy_version_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            migrate_policy({"schema_version": 99})


if __name__ == "__main__":
    unittest.main()
