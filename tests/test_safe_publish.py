from __future__ import annotations

import io
import gzip
import bz2
import json
import lzma
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import zipfile
from contextlib import redirect_stdout, redirect_stderr


# Import the repository helper directly so the tests exercise the published file.
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))
import safe_publish as subject  # noqa: E402


def synthetic_policy() -> dict[str, object]:
    """Return a complete policy containing only synthetic identifiers."""
    return {
        "schema_version": 1,
        "identifiers": [
            {"id": "private.brand", "kind": "literal", "value": "AIALRA", "severity": "block"},
            {"id": "private.contact", "kind": "literal", "value": "owner@" + "private.test", "severity": "block"},
        ],
        "replacements": [
            {"identifier_id": "private.brand", "replacement": "ExampleOrg"},
            {"identifier_id": "private.contact", "replacement": "owner@example.invalid"},
        ],
        "approved_locations": [],
        "blocked_paths": ["*.sqlite3", "private/**"],
        "binary_approvals": [],
        "exceptions": [],
    }


def policy_with_bound_approvals(policy: dict[str, object], object_text: dict[str, str]) -> dict[str, object]:
    migrated = subject.migrate_policy(policy)
    scanner_sha256 = subject.sha256_file(Path(subject.__file__))
    for approval in migrated["approved_locations"]:
        approval.update(
            {
                "object_sha256": subject.sha256_bytes(object_text[approval["object"]].encode("utf-8")),
                "scanner_sha256": scanner_sha256,
                "policy_sha256": "0" * 64,
                "issued_at": "2026-01-01T00:00:00+00:00",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "review_trigger": "content-policy-scanner-or-expiry-change",
            }
        )
    policy_sha256 = subject.approval_policy_fingerprint(migrated)
    for approval in migrated["approved_locations"]:
        approval["policy_sha256"] = policy_sha256
    return subject.validate_policy(migrated)


class PatternTests(unittest.TestCase):
    def test_large_text_without_address_has_bounded_runtime(self) -> None:
        # Long address-like and unbroken lines previously exposed unbounded regex backtracking.
        text = "42 " + ("ExampleSegment " * 100_000) + ("A" * 1_500_000)
        state = subject.ScanState("synthetic", subject.empty_policy())
        started = time.monotonic()
        subject.scan_text(state, text, surface="working-tree", object_id="working-tree:large.txt", display_path="large.txt")
        self.assertLess(time.monotonic() - started, 5.0)

    def test_synthetic_corpus_covers_required_text_categories(self) -> None:
        # Every marker is synthetic and is safe to place in a public regression fixture.
        text = "\n".join(
            [
                "password=SYNTHETIC_ONLY_42",
                "SYNTHETIC postgres://demo:SYNTHETIC_DB_PASS@db.internal:5432/app",
                "SYNTHETIC Contact owner@private.test or +1 (555) 010-1234",
                "SYNTHETIC uid=user-private-0042 device_id=device-private-0088",
                "AIALRA and AΙALRA",
                "北京市海淀区示例街道42号",
                "42 Example Street",
                "SYNTHETIC http://" + "10." + "24.1.8:8080/private",
                "SYNTHETIC AA:BB:CC:DD:EE:FF",
                "C:\\" + "Users\\PrivateUser\\Documents\\notes.txt",
                "/" + "home/private-user/notes.txt",
            ]
        )
        state = subject.ScanState("synthetic", subject.validate_policy(synthetic_policy()), collect_raw=True)
        subject.scan_text(state, text, surface="working-tree", object_id="working-tree:fixture.txt", display_path="fixture.txt")
        rule_ids = {finding.rule_id for finding in state.findings}
        required = {
            "credential.assignment",
            "credential.database-uri",
            "identity.email",
            "identity.phone",
            "identity.uid",
            "identity.aialra-confusable",
            "identity.address-cn",
            "identity.address-us",
            "infrastructure.ipv4",
            "infrastructure.mac",
            "infrastructure.windows-path",
            "infrastructure.unix-home",
            "infrastructure.url",
            "private.brand",
            "private.contact",
        }
        self.assertTrue(required.issubset(rule_ids))

    def test_public_findings_never_contain_raw_markers_or_hashes(self) -> None:
        marker = "SYNTHETIC_ONLY_DO_NOT_LOG_9472"
        state = subject.ScanState("synthetic", subject.empty_policy(), collect_raw=True)
        subject.scan_text(
            state,
            f"password={marker}",
            surface="working-tree",
            object_id="working-tree:secret.txt",
            display_path="secret.txt",
        )
        public_json = json.dumps(subject.sorted_findings(state), sort_keys=True)
        self.assertNotIn(marker, public_json)
        self.assertNotIn(subject.sha256_bytes(marker.encode("utf-8")), public_json)
        self.assertEqual(state.raw_candidates[0]["raw_value"], marker)

    def test_example_invalid_is_an_approved_synthetic_domain(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            state,
            "owner@example.invalid https://example.invalid/path",
            surface="working-tree",
            object_id="working-tree:example.txt",
            display_path="example.txt",
        )
        self.assertEqual([], state.findings)

    def test_invalid_network_shapes_and_documentation_addresses_are_not_reported(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            state,
            "fragment abcd:1234:ef00 range dead:beef/64 docs 192.0.2.44 192.0.2.0/24 2001:db8::42 2001:db8::/32",
            surface="working-tree",
            object_id="working-tree:network-examples.txt",
            display_path="network-examples.txt",
        )
        network_rules = {
            finding.rule_id
            for finding in state.findings
            if finding.rule_id in {"infrastructure.ipv4", "infrastructure.ipv6", "infrastructure.cidr"}
        }
        self.assertEqual(set(), network_rules)

    def test_json_double_colon_keys_and_dependency_versions_are_not_networks(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            state,
            '"actions-artifact-content::checked": 12\nopencv-python==4.14.0.94',
            surface="working-tree",
            object_id="working-tree:public-summary",
            display_path="requirements-gate.txt",
        )
        network_rules = {
            finding.rule_id
            for finding in state.findings
            if finding.rule_id in {"infrastructure.ipv4", "infrastructure.ipv6", "infrastructure.cidr"}
        }
        self.assertEqual(set(), network_rules)

    def test_explicit_synthetic_examples_are_visible_noncritical_findings(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            state,
            "SYNTHETIC postgres://demo:SYNTHETIC_PASS@db.internal:5432/app\n"
            "SYNTHETIC Contact owner@private.test or +1 (555) 010-1234\n"
            "SYNTHETIC uid=user-private-0042\n"
            "SYNTHETIC " + "10." + "24.1.8 AA:BB:CC:DD:EE:FF",
            surface="working-tree",
            object_id="working-tree:synthetic-fixture",
            display_path="tests/test_fixture.py",
        )
        self.assertTrue(state.findings)
        self.assertTrue(all(subject.finding_risk_level(finding) == "noncritical" for finding in state.findings))
        self.assertEqual("allow_with_risk", subject.publication_decision_for(state))

    def test_unmarked_test_literals_remain_critical(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            state,
            "postgres://service:"
            + "REAL_TEST_LITERAL_9472"
            + "@db.internal"
            + ":5432/app "
            + "10."
            + "24.1.8",
            surface="working-tree",
            object_id="working-tree:unmarked-fixture",
            display_path="tests/test_fixture.py",
        )
        self.assertTrue(any(subject.finding_risk_level(finding) == "critical" for finding in state.findings))
        self.assertEqual("deny", subject.publication_decision_for(state))

    def test_github_noreply_metadata_is_public_noncritical_attribution(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            state,
            "author Example User <12345+example@users.noreply.github.com>",
            surface="git-metadata",
            object_id="git-commit:synthetic",
            display_path="git-commit:synthetic",
        )
        self.assertEqual({"identity.email-public-attribution"}, {finding.rule_id for finding in state.findings})
        self.assertEqual("allow_with_risk", subject.publication_decision_for(state))

    def test_valid_private_network_literals_remain_critical(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        private_network_text = "host 10." + "24.1.8 network 10." + "24.0.0/16 ipv6 fd00:" + "1234:" + "5678:" + ":42"
        subject.scan_text(
            state,
            private_network_text,
            surface="working-tree",
            object_id="working-tree:private-network.txt",
            display_path="private-network.txt",
        )
        network_rules = {finding.rule_id for finding in state.findings}
        self.assertTrue({"infrastructure.ipv4", "infrastructure.ipv6", "infrastructure.cidr"}.issubset(network_rules))
        self.assertEqual("deny", subject.publication_decision_for(state))

    def test_code_references_are_reported_without_blocking_literal_credentials(self) -> None:
        reference_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            reference_state,
            'password = settings["webui"]["password"]\ntoken = os.environ.get("SERVICE_TOKEN")',
            surface="working-tree",
            object_id="working-tree:source.py",
            display_path="src/source.py",
        )
        self.assertEqual(
            {"credential.assignment-reference"},
            {finding.rule_id for finding in reference_state.findings},
        )
        self.assertEqual("allow_with_risk", subject.publication_decision_for(reference_state))

        literal_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            literal_state,
            'password="REAL_LITERAL_VALUE_9472"',
            surface="working-tree",
            object_id="working-tree:config.py",
            display_path="src/config.py",
        )
        self.assertEqual({"credential.assignment"}, {finding.rule_id for finding in literal_state.findings})
        self.assertEqual("deny", subject.publication_decision_for(literal_state))

        fixture_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            fixture_state,
            'password="RUNTIME_GENERATED_FIXTURE_9472"',
            surface="working-tree",
            object_id="working-tree:test-fixture",
            display_path="tests/test_config.py",
        )
        self.assertEqual(
            {"credential.assignment"},
            {finding.rule_id for finding in fixture_state.findings},
        )
        self.assertEqual("deny", subject.publication_decision_for(fixture_state))

        example_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            example_state,
            'password: "remote-only-change-me"',
            surface="working-tree",
            object_id="working-tree:example-config",
            display_path="config.example.yaml",
        )
        self.assertEqual({"credential.assignment"}, {finding.rule_id for finding in example_state.findings})
        self.assertEqual("deny", subject.publication_decision_for(example_state))

    def test_test_signed_urls_are_noncritical_but_runtime_signed_urls_block(self) -> None:
        marker = "https://storage.invalid/object?signature=SYNTHETIC_SIGNATURE_9472"
        test_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            test_state,
            marker,
            surface="working-tree",
            object_id="working-tree:test-url",
            display_path="tests/test_download.py",
        )
        self.assertIn("credential.signed-url-example", {finding.rule_id for finding in test_state.findings})
        self.assertEqual("allow_with_risk", subject.publication_decision_for(test_state))

        runtime_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            runtime_state,
            marker,
            surface="working-tree",
            object_id="working-tree:runtime-url",
            display_path="config/runtime.txt",
        )
        self.assertIn("credential.signed-url", {finding.rule_id for finding in runtime_state.findings})
        self.assertEqual("deny", subject.publication_decision_for(runtime_state))

    def test_svg_geometry_and_powershell_static_members_do_not_masquerade_as_private_values(self) -> None:
        geometry_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            geometry_state,
            '<path d="M0 410 C240 330 360 510 610 420 C830 340 1080 430 1440 350 V520 H0Z"/>',
            surface="working-tree",
            object_id="working-tree:hero.svg",
            display_path="docs/hero.svg",
        )
        self.assertNotIn("identity.phone", {finding.rule_id for finding in geometry_state.findings})

        phone_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            phone_state,
            '<text>555-' + '010-9472</text>',
            surface="working-tree",
            object_id="working-tree:contact.svg",
            display_path="docs/contact.svg",
        )
        self.assertIn("identity.phone", {finding.rule_id for finding in phone_state.findings})

        powershell_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            powershell_state,
            "$sha = [System.Security.Cryptography.SHA256]::Create()",
            surface="working-tree",
            object_id="working-tree:script.ps1",
            display_path="tools/script.ps1",
        )
        self.assertNotIn("infrastructure.ipv6", {finding.rule_id for finding in powershell_state.findings})

    def test_working_tree_objects_are_bound_to_content_digests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text("https://public.example/project\n", encoding="utf-8")
            state = subject.ScanState("synthetic", subject.empty_policy())
            subject._scan_working_tree_slice(state, root)
            finding = next(item for item in state.findings if item.rule_id == "infrastructure.url")
            expected_digest = subject.sha256_bytes((root / "README.md").read_bytes())
            self.assertEqual(f"working-tree:{expected_digest}:README.md", finding.object)


class PolicyTests(unittest.TestCase):
    def test_v1_and_v2_policies_migrate_to_v3_in_memory(self) -> None:
        original = synthetic_policy()
        validated = subject.validate_policy(original)
        self.assertEqual(1, original["schema_version"])
        self.assertEqual(3, validated["schema_version"])
        self.assertEqual(["nfkc"], validated["identifiers"][0]["normalization"])
        self.assertEqual([], validated["risk_acceptances"])

        version_two = dict(validated)
        version_two["schema_version"] = 2
        version_two.pop("risk_acceptances")
        migrated = subject.validate_policy(version_two)
        self.assertEqual(3, migrated["schema_version"])
        self.assertEqual([], migrated["risk_acceptances"])

    def test_unicode_zero_width_and_encoded_private_literals_are_detected(self) -> None:
        policy = subject.validate_policy(synthetic_policy())
        policy["identifiers"][0]["normalization"] = ["nfkc", "casefold", "zero-width", "confusable"]
        state = subject.ScanState("synthetic", policy)
        subject.scan_text(state, "AI\u200bALRA QUlBTFJB", surface="working-tree", object_id="working-tree:encoded.txt", display_path="encoded.txt")
        matches = [item for item in state.findings if item.rule_id == "private.brand"]
        self.assertGreaterEqual(len(matches), 2)

    def test_exact_approved_location_is_allowed(self) -> None:
        policy = synthetic_policy()
        policy["approved_locations"] = [
            {
                "rule_id": "private.brand",
                "object": "metadata:owner",
                "approved_by": "information-owner",
                "reason": "Public repository owner",
            }
        ]
        state = subject.ScanState("synthetic", policy_with_bound_approvals(policy, {"metadata:owner": "AIALRA"}))
        subject.scan_text(state, "AIALRA", surface="repository-metadata", object_id="metadata:owner", display_path="owner")
        private_findings = [item for item in state.findings if item.rule_id == "private.brand"]
        self.assertEqual("approved", private_findings[0].status)

    def test_legal_record_requires_an_exact_information_owner_approval(self) -> None:
        # Legal records stay in review until the information owner approves the exact rule and object location.
        unapproved_state = subject.ScanState("synthetic", subject.validate_policy(synthetic_policy()))
        subject.scan_text(
            unapproved_state,
            "AIALRA",
            surface="working-tree",
            object_id="working-tree:LICENSE",
            display_path="LICENSE",
        )
        unapproved_findings = [item for item in unapproved_state.findings if item.rule_id == "private.brand"]
        self.assertEqual("review", unapproved_findings[0].status)

        # An exact approval records completed human review without allowing a replacement or wildcard exception.
        approved_policy = synthetic_policy()
        approved_policy["approved_locations"] = [
            {
                "rule_id": "private.brand",
                "object": "working-tree:LICENSE",
                "approved_by": "information-owner",
                "reason": "Preserve reviewed public legal provenance",
            }
        ]
        approved_state = subject.ScanState(
            "synthetic",
            policy_with_bound_approvals(approved_policy, {"working-tree:LICENSE": "AIALRA"}),
        )
        subject.scan_text(
            approved_state,
            "AIALRA",
            surface="working-tree",
            object_id="working-tree:LICENSE",
            display_path="LICENSE",
        )
        approved_findings = [item for item in approved_state.findings if item.rule_id == "private.brand"]
        self.assertEqual("approved", approved_findings[0].status)
        self.assertTrue(approved_findings[0].legal_protected)

    def test_wildcard_approval_is_rejected(self) -> None:
        policy = synthetic_policy()
        policy["approved_locations"] = [
            {"rule_id": "private.brand", "object": "working-tree:*", "approved_by": "owner", "reason": "Too broad"}
        ]
        with self.assertRaises(ValueError):
            subject.validate_policy(policy)

    def test_exact_bracketed_object_is_allowed(self) -> None:
        policy = synthetic_policy()
        policy["approved_locations"] = [
            {
                "rule_id": "private.brand",
                "object": "working-tree:docs/Error [TransformError].md",
                "approved_by": "owner",
                "reason": "The object is matched by exact string equality",
            }
        ]
        validated = subject.validate_policy(policy)
        self.assertEqual("working-tree:docs/Error [TransformError].md", validated["approved_locations"][0]["object"])

    def test_risk_acceptance_rejects_wildcards_and_critical_rules(self) -> None:
        base = {
            "repository": "ExampleOrg/example",
            "rule_id": "infrastructure.url",
            "object": "working-tree:README.md",
            "object_sha256": "1" * 64,
            "scanner_sha256": "2" * 64,
            "approved_by": "information-owner",
            "reason": "Reviewed public documentation address",
            "expires_at": "2099-01-01T00:00:00Z",
            "review_trigger": "content-or-scanner-change",
        }
        wildcard_policy = subject.empty_policy()
        wildcard_policy["risk_acceptances"] = [{**base, "object": "working-tree:*"}]
        with self.assertRaises(ValueError):
            subject.validate_policy(wildcard_policy)

        bracketed_policy = subject.empty_policy()
        bracketed_policy["risk_acceptances"] = [{**base, "object": "working-tree:docs/Error [TransformError].md"}]
        self.assertEqual(
            "working-tree:docs/Error [TransformError].md",
            subject.validate_policy(bracketed_policy)["risk_acceptances"][0]["object"],
        )

        critical_policy = subject.empty_policy()
        critical_policy["risk_acceptances"] = [{**base, "rule_id": "credential.assignment"}]
        with self.assertRaises(ValueError):
            subject.validate_policy(critical_policy)

    def test_missing_and_oversized_action_secret_fail_closed(self) -> None:
        old_value = os.environ.pop("SAFE_PUBLISH_POLICY_B64", None)
        try:
            with self.assertRaises(ValueError):
                subject.load_policy_from_env("SAFE_PUBLISH_POLICY_B64")
            # Windows caps environment variables below GitHub's documented 48 KB limit, so mock the read boundary.
            with mock.patch.object(subject.os.environ, "get", return_value="A" * (subject.MAX_SECRET_BYTES + 1)):
                with self.assertRaises(ValueError):
                    subject.load_policy_from_env("SAFE_PUBLISH_POLICY_B64")
        finally:
            if old_value is None:
                os.environ.pop("SAFE_PUBLISH_POLICY_B64", None)
            else:
                os.environ["SAFE_PUBLISH_POLICY_B64"] = old_value


class PublicationDecisionTests(unittest.TestCase):
    def _url_state(self) -> tuple[subject.ScanState, subject.Finding]:
        state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
        subject.scan_text(
            state,
            "Documentation https://docs.example.com/guide",
            surface="working-tree",
            object_id="working-tree:README.md",
            display_path="README.md",
        )
        finding = next(item for item in state.findings if item.rule_id == "infrastructure.url")
        return state, finding

    def _accept_url(self, state: subject.ScanState, finding: subject.Finding, **updates: str) -> None:
        acceptance = {
            "repository": state.repository,
            "rule_id": finding.rule_id,
            "object": finding.object,
            "object_sha256": state.object_sha256[finding.object],
            "scanner_sha256": state.scanner_sha256,
            "approved_by": "information-owner",
            "reason": "Reviewed public documentation address",
            "expires_at": "2099-01-01T00:00:00Z",
            "review_trigger": "content-or-scanner-change",
        }
        acceptance.update(updates)
        state.policy["risk_acceptances"] = [acceptance]

    def test_public_url_allows_with_risk_without_manual_acceptance_but_strict_profile_denies(self) -> None:
        state, finding = self._url_state()
        self.assertEqual("review", subject.decision_for(state))
        self.assertEqual("allow_with_risk", subject.publication_decision_for(state))
        self._accept_url(state, finding)
        self.assertEqual("allow_with_risk", subject.publication_decision_for(state))
        self.assertEqual("deny", subject.publication_decision_for(state, release_profile="strict"))

    def test_expired_changed_object_or_changed_scanner_keeps_noncritical_risk_visible(self) -> None:
        cases = (
            {"expires_at": "2000-01-01T00:00:00Z"},
            {"object_sha256": "1" * 64},
            {"scanner_sha256": "2" * 64},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                state, finding = self._url_state()
                self._accept_url(state, finding, **changes)
                self.assertEqual("allow_with_risk", subject.publication_decision_for(state))

    def test_critical_findings_and_critical_coverage_always_deny(self) -> None:
        secret_state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
        subject.scan_text(
            secret_state,
            "password=SYNTHETIC_ONLY_42",
            surface="working-tree",
            object_id="working-tree:secret.txt",
            display_path="secret.txt",
        )
        self.assertEqual("block", subject.decision_for(secret_state))
        self.assertEqual("deny", subject.publication_decision_for(secret_state))

        coverage_state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
        coverage_state.add_coverage("working-tree", "unreadable", "synthetic-read-failure")
        self.assertEqual("incomplete", subject.decision_for(coverage_state))
        self.assertEqual("deny", subject.publication_decision_for(coverage_state))

    def test_noncritical_auxiliary_coverage_allows_with_risk(self) -> None:
        state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
        state.add_coverage("actions-logs", "tool_failed", "synthetic-optional-tool-failure")
        self.assertEqual("incomplete", subject.decision_for(state))
        self.assertEqual("allow_with_risk", subject.publication_decision_for(state))

    def test_public_brand_is_reported_but_does_not_block_permissive_publication(self) -> None:
        state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
        subject.scan_text(
            state,
            "Public project brand: AIALRA",
            surface="working-tree",
            object_id="working-tree:README.md",
            display_path="README.md",
        )
        self.assertEqual("review", subject.decision_for(state))
        self.assertEqual("allow_with_risk", subject.publication_decision_for(state))

    def test_exact_approval_can_produce_clean_allow(self) -> None:
        policy = subject.empty_policy()
        policy["approved_locations"] = [
            {
                "rule_id": "infrastructure.url",
                "object": "working-tree:README.md",
                "approved_by": "information-owner",
                "reason": "Reviewed public project homepage",
            }
        ]
        state = subject.ScanState(
            "ExampleOrg/example",
            policy_with_bound_approvals(policy, {"working-tree:README.md": "Homepage https://docs.example.com/guide"}),
        )
        subject.scan_text(
            state,
            "Homepage https://docs.example.com/guide",
            surface="working-tree",
            object_id="working-tree:README.md",
            display_path="README.md",
        )
        self.assertEqual("pass", subject.decision_for(state))
        self.assertEqual("allow", subject.publication_decision_for(state))

    def test_gate_report_keeps_both_decisions_and_redacts_raw_values(self) -> None:
        marker = "SYNTHETIC_ONLY_DO_NOT_LOG_8821"
        state = subject.ScanState("ExampleOrg/example", subject.empty_policy(), collect_raw=True)
        subject.scan_text(
            state,
            "password=" + marker,
            surface="working-tree",
            object_id="working-tree:secret.txt",
            display_path="secret.txt",
        )
        report = subject.gate_report(state, REPOSITORY_ROOT, state.policy)
        encoded = json.dumps(report, sort_keys=True)
        self.assertEqual("block", report["decision"])
        self.assertEqual("deny", report["publication_decision"])
        self.assertEqual("permissive-noncritical", report["release_profile"])
        self.assertEqual(
            {"count_source", "match_reason", "publication_effect", "next_step", "strict_audit_context"},
            set(report["result_explanation"]),
        )
        self.assertIn("must stop", report["result_explanation"]["publication_effect"])
        self.assertNotIn(marker, encoded)
        self.assertNotIn(subject.sha256_bytes(marker.encode("utf-8")), encoded)

    def test_gate_command_exit_and_public_summary_follow_publication_decision(self) -> None:
        content = "Documentation https://docs.example.com/guide"
        object_id = "working-tree:README.md"
        policy = subject.empty_policy()
        policy["risk_acceptances"] = [
            {
                "repository": "ExampleOrg/example",
                "rule_id": "infrastructure.url",
                "object": object_id,
                "object_sha256": subject.sha256_bytes(content.encode("utf-8")),
                "scanner_sha256": subject.sha256_bytes((REPOSITORY_ROOT / "scripts" / "safe_publish.py").read_bytes()),
                "approved_by": "information-owner",
                "reason": "Reviewed public documentation address",
                "expires_at": "2099-01-01T00:00:00Z",
                "review_trigger": "content-or-scanner-change",
            }
        ]

        def scan_working_tree(state: subject.ScanState, source: Path, **kwargs: object) -> None:
            subject.scan_text(state, content, surface="working-tree", object_id=object_id, display_path="README.md")
            state.add_coverage("working-tree", "checked", object_count=1)

        def checked_surface(name: str):
            def scanner(state: subject.ScanState, source: Path, *args: object, **kwargs: object) -> None:
                state.add_coverage(name, "not_present")

            return scanner

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            codex_home = root / "codex-home"
            report_path = codex_home / "private" / "github-safe-publish" / "gate.private.json"
            public_path = root / "gate.public.json"
            args = subject.argparse.Namespace(
                source=str(source),
                repository="ExampleOrg/example",
                policy=str(root / "policy.private.json"),
                policy_b64_env=None,
                generic_only=False,
                release_asset=[],
                gitleaks_path=None,
                release_profile="permissive-noncritical",
                report=str(report_path),
                public_summary=str(public_path),
            )
            standard_output = io.StringIO()
            with (
                mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}),
                mock.patch.object(subject, "load_policy", return_value=subject.validate_policy(policy)),
                mock.patch.object(subject, "scan_working_tree", side_effect=scan_working_tree),
                mock.patch.object(subject, "scan_git_history", side_effect=checked_surface("git-history")),
                mock.patch.object(subject, "scan_submodules", side_effect=checked_surface("submodules")),
                mock.patch.object(subject, "scan_lfs", side_effect=checked_surface("git-lfs")),
                mock.patch.object(subject, "run_gitleaks", side_effect=checked_surface("gitleaks")),
                redirect_stdout(standard_output),
            ):
                exit_code = subject.command_gate(args)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            public = json.loads(public_path.read_text(encoding="utf-8"))
            self.assertEqual(0, exit_code)
            self.assertEqual("review", report["decision"])
            self.assertEqual("allow_with_risk", report["publication_decision"])
            self.assertNotIn("findings", report)
            self.assertEqual(1, report["finding_pages"]["record_count"])
            self.assertEqual("allow_with_risk", public["publication_decision"])
            self.assertIn("count_source", public["result_explanation"])
            self.assertIn("may continue", public["result_explanation"]["publication_effect"])
            command_result = json.loads(standard_output.getvalue().splitlines()[-1])
            self.assertIn("result_explanation", command_result)
            public_text = public_path.read_text(encoding="utf-8")
            self.assertNotIn("README.md", public_text)
            self.assertNotIn("infrastructure.url", public_text)
            self.assertNotIn("docs.example.com", public_text)

    def test_gate_defers_later_surfaces_until_worktree_slice_resumes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            codex_home = root / "codex-home"
            report_path = codex_home / "private" / "github-safe-publish" / "gate.private.json"
            args = subject.argparse.Namespace(
                source=str(source),
                repository="ExampleOrg/example",
                policy=str(root / "policy.private.json"),
                policy_b64_env=None,
                generic_only=False,
                release_asset=[],
                gitleaks_path=None,
                release_profile="permissive-noncritical",
                report=str(report_path),
                public_summary=None,
            )

            def timed_out_worktree(state: subject.ScanState, source_path: Path, **kwargs: object) -> None:
                state.add_coverage("working-tree", "tool_failed", "working-tree-time-limit-exceeded")

            with (
                mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}),
                mock.patch.object(subject, "load_policy", return_value=subject.empty_policy()),
                mock.patch.object(subject, "scan_working_tree", side_effect=timed_out_worktree),
                mock.patch.object(subject, "scan_git_history") as history,
                mock.patch.object(subject, "scan_submodules") as submodules,
                mock.patch.object(subject, "scan_lfs") as lfs,
                mock.patch.object(subject, "run_gitleaks") as gitleaks,
            ):
                self.assertEqual(3, subject.command_gate(args))

            history.assert_not_called()
            submodules.assert_not_called()
            lfs.assert_not_called()
            gitleaks.assert_not_called()
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual("incomplete", report["decision"])
            self.assertEqual("deny", report["publication_decision"])


class ArtifactTests(unittest.TestCase):
    def test_single_file_compressed_streams_are_bounded_and_scanned_without_tar_false_positive(self) -> None:
        streams = {
            ".gz": gzip.compress(b"password=SYNTHETIC_GZIP_SECRET"),
            ".bz2": bz2.compress(b"password=SYNTHETIC_BZIP_SECRET"),
            ".xz": lzma.compress(b"password=SYNTHETIC_XZ_SECRET"),
        }
        for suffix, payload in streams.items():
            with self.subTest(suffix=suffix):
                state = subject.ScanState("synthetic", subject.empty_policy())
                subject.scan_bytes(
                    state,
                    payload,
                    surface="working-tree",
                    object_id=f"working-tree:sample.txt{suffix}",
                    display_path=f"sample.txt{suffix}",
                )
                self.assertIn("credential.assignment", {item.rule_id for item in state.findings})
                self.assertFalse(any(item.reason.startswith("invalid-tar:") for item in state.coverage))

        with mock.patch.object(subject, "MAX_ARCHIVE_EXPANDED_BYTES", 8):
            limited = subject.ScanState("synthetic", subject.empty_policy())
            subject.scan_bytes(
                limited,
                streams[".gz"],
                surface="working-tree",
                object_id="working-tree:limited.txt.gz",
                display_path="limited.txt.gz",
            )
        self.assertTrue(any(item.reason.startswith("archive-expansion-limit:") for item in limited.coverage))

    def test_compressed_tar_keeps_member_scanning(self) -> None:
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
            content = b"password=SYNTHETIC_TAR_SECRET"
            info = tarfile.TarInfo("nested.txt")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(
            state,
            archive_buffer.getvalue(),
            surface="working-tree",
            object_id="working-tree:sample.tar.gz",
            display_path="sample.tar.gz",
        )
        self.assertIn("credential.assignment", {item.rule_id for item in state.findings})

    def test_text_beyond_one_mib_is_scanned_within_the_file_limit(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(
            state,
            b"A" * (1024 * 1024 + 1) + b"\npassword=SYNTHETIC_LARGE_TEXT_SECRET",
            surface="working-tree",
            object_id="working-tree:large.txt",
            display_path="large.txt",
        )
        self.assertIn("credential.assignment", {item.rule_id for item in state.findings})
        self.assertFalse(any(item.reason.startswith("oversized-text-object:") for item in state.coverage))

    def test_text_beyond_the_file_limit_fails_closed(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        with mock.patch.object(subject, "DEFAULT_MAX_FILE_BYTES", 100):
            subject.scan_bytes(
                state,
                b"A" * 101,
                surface="working-tree",
                object_id="working-tree:too-large.txt",
                display_path="too-large.txt",
            )
        self.assertTrue(any(item.reason.startswith("oversized-object:") for item in state.coverage))
        self.assertEqual("incomplete", subject.decision_for(state))
        self.assertEqual("deny", subject.publication_decision_for(state))

    def test_barcode_result_normalizes_three_and_four_value_opencv_abis(self) -> None:
        self.assertEqual(["SYNTHETIC-CODE"], subject.normalized_barcode_values(("SYNTHETIC-CODE", "CODE128", None)))
        self.assertEqual(
            ["SYNTHETIC-A", "SYNTHETIC-B"],
            subject.normalized_barcode_values((True, ["SYNTHETIC-A", "SYNTHETIC-B"], ["CODE128", "QR"], None)),
        )
        self.assertEqual([], subject.normalized_barcode_values((False, [], [], None)))

    def test_numpy_arrays_are_scanned_without_pickle(self) -> None:
        import numpy as np

        string_buffer = io.BytesIO()
        np.save(string_buffer, np.array(["password=SYNTHETIC_ARRAY_SECRET"], dtype="U40"), allow_pickle=False)
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(
            state,
            string_buffer.getvalue(),
            surface="working-tree",
            object_id="working-tree:values.npy",
            display_path="values.npy",
        )
        self.assertIn("credential.assignment", {item.rule_id for item in state.findings})
        self.assertTrue(any(item.reason.startswith("numpy-array:") and item.status == "checked" for item in state.coverage))

        object_buffer = io.BytesIO()
        np.save(object_buffer, np.array([{"secret": "SYNTHETIC"}], dtype=object), allow_pickle=True)
        object_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(
            object_state,
            object_buffer.getvalue(),
            surface="working-tree",
            object_id="working-tree:objects.npy",
            display_path="objects.npy",
        )
        self.assertTrue(any(item.reason.startswith("numpy-pickle-forbidden-or-invalid:") for item in object_state.coverage))

    def test_numpy_archive_enforces_member_limit_before_loading(self) -> None:
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            for index in range(subject.MAX_ARRAY_MEMBERS + 1):
                archive.writestr(f"member-{index}.npy", b"synthetic")
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(
            state,
            archive_buffer.getvalue(),
            surface="working-tree",
            object_id="working-tree:many.npz",
            display_path="many.npz",
        )
        self.assertTrue(any(item.reason.startswith("numpy-member-limit:") for item in state.coverage))

    def test_image_ocr_budget_exhaustion_fails_closed(self) -> None:
        from PIL import Image

        image_buffer = io.BytesIO()
        Image.new("RGB", (13, 17), color=(17, 31, 47)).save(image_buffer, format="PNG")
        state = subject.ScanState("synthetic", subject.validate_policy(synthetic_policy()))
        state.image_ocr_budget_seconds = 0
        state.image_ocr_started_at = time.monotonic() - 1
        subject.scan_image_content(
            state,
            image_buffer.getvalue(),
            surface="working-tree",
            object_id="working-tree:budget.png",
            display_path="budget.png",
        )
        self.assertTrue(
            any(item.reason.startswith("image-ocr-budget-exceeded") for item in state.coverage)
        )
        self.assertEqual("incomplete", subject.decision_for(state))

    def test_media_metadata_declares_absent_extractable_layers(self) -> None:
        metadata = json.dumps({"format": {"tags": {"comment": "AIALRA"}}, "streams": []})
        completed = subprocess.CompletedProcess(["ffprobe"], 0, stdout=metadata, stderr="")
        state = subject.ScanState("synthetic", subject.validate_policy(synthetic_policy()))
        with mock.patch.object(subject, "run", return_value=completed):
            subject.scan_media_content(
                state,
                b"synthetic-media-container",
                surface="working-tree",
                object_id="working-tree:sample.mp3",
                display_path="sample.mp3",
            )
        self.assertIn("private.brand", {item.rule_id for item in state.findings})
        statuses = {(item.surface, item.status) for item in state.coverage}
        self.assertIn(("working-tree", "checked"), statuses)
        self.assertIn(("media-subtitles", "not_present"), statuses)
        self.assertIn(("media-cover-art", "not_present"), statuses)
        self.assertIn(("media-attachments", "not_present"), statuses)

    def test_office_and_notebook_content_is_scanned(self) -> None:
        # Build a minimal Office Open XML container with synthetic document metadata.
        office_buffer = io.BytesIO()
        with zipfile.ZipFile(office_buffer, "w") as archive:
            archive.writestr("docProps/core.xml", "<creator>owner@" + "private.test</creator>")
            archive.writestr("word/document.xml", "<text>AIALRA</text>")
        state = subject.ScanState("synthetic", subject.validate_policy(synthetic_policy()))
        subject.scan_bytes(
            state,
            office_buffer.getvalue(),
            surface="working-tree",
            object_id="working-tree:sample.docx",
            display_path="sample.docx",
        )
        notebook = json.dumps({"cells": [{"cell_type": "code", "outputs": [{"text": "password=SYNTHETIC_NOTEBOOK"}]}]}).encode()
        subject.scan_bytes(
            state,
            notebook,
            surface="working-tree",
            object_id="working-tree:sample.ipynb",
            display_path="sample.ipynb",
        )
        rule_ids = {finding.rule_id for finding in state.findings}
        self.assertIn("private.contact", rule_ids)
        self.assertIn("private.brand", rule_ids)
        self.assertIn("credential.assignment", rule_ids)

    def test_unapproved_binary_and_unsupported_archive_are_incomplete(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(state, b"synthetic image bytes", surface="working-tree", object_id="working-tree:image.png", display_path="image.png")
        subject.scan_bytes(state, b"synthetic archive bytes", surface="working-tree", object_id="working-tree:data.7z", display_path="data.7z")
        self.assertTrue(any(item.reason.startswith("invalid-image") for item in state.coverage))
        self.assertTrue(any(item.reason.startswith("unsupported-archive") for item in state.coverage))
        self.assertEqual("incomplete", subject.decision_for(state))

    def test_database_artifact_blocks_when_coverage_is_complete(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(state, b"CREATE TABLE example(id INTEGER);", surface="working-tree", object_id="working-tree:data.sql", display_path="data.sql")
        state.add_coverage("working-tree", "checked", object_count=1)
        self.assertEqual("block", subject.decision_for(state))

    def test_lfs_pointer_with_opaque_suffix_is_scanned_as_text(self) -> None:
        # A pointer is text metadata, so a .bin filename must not create a binary-review coverage gap.
        pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + (b"a" * 64) + b"\nsize 4\n"
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(state, pointer, surface="working-tree", object_id="working-tree:large.bin", display_path="large.bin")
        self.assertFalse(any(item.reason.startswith("binary-review-required") for item in state.coverage))

    def test_svg_source_is_scanned_as_text(self) -> None:
        # SVG attributes and text nodes can contain secrets even though the file is displayed as an image.
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><text>password=SYNTHETIC_SVG_SECRET</text></svg>'
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(state, svg, surface="working-tree", object_id="working-tree:diagram.svg", display_path="diagram.svg")
        self.assertIn("credential.assignment", {finding.rule_id for finding in state.findings})
        self.assertNotIn("infrastructure.url", {finding.rule_id for finding in state.findings})
        self.assertFalse(any(item.reason.startswith("binary-review-required") for item in state.coverage))

    def test_invalid_svg_and_embedded_raster_fail_closed(self) -> None:
        # Invalid XML and embedded raster data both leave an explicit coverage gap.
        invalid_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(invalid_state, b"<svg>", surface="working-tree", object_id="working-tree:invalid.svg", display_path="invalid.svg")
        self.assertTrue(any(item.reason.startswith("invalid-svg") for item in invalid_state.coverage))

        approved_svg = b"<svg>"
        approved_policy = subject.empty_policy()
        approved_policy["binary_approvals"].append(
            {
                "object": "working-tree:approved-invalid.svg",
                "sha256": subject.sha256_bytes(approved_svg),
                "approved_by": "InformationOwner",
                "reason": "Exact malformed synthetic fixture reviewed",
                "inspection_layers": ["manual", "digest"],
                "tool_versions": {"github-safe-publish": subject.TOOL_VERSION},
                "review_trigger": "object digest or scanner version changes",
            }
        )
        approved_state = subject.ScanState("synthetic", approved_policy)
        subject.scan_bytes(
            approved_state,
            approved_svg,
            surface="working-tree",
            object_id="working-tree:approved-invalid.svg",
            display_path="approved-invalid.svg",
        )
        self.assertFalse(any(item.reason.startswith("invalid-svg") for item in approved_state.coverage))

        changed_state = subject.ScanState("synthetic", approved_policy)
        subject.scan_bytes(
            changed_state,
            b"<svg changed>",
            surface="working-tree",
            object_id="working-tree:approved-invalid.svg",
            display_path="approved-invalid.svg",
        )
        self.assertTrue(any(item.reason.startswith("invalid-svg") for item in changed_state.coverage))

        embedded_state = subject.ScanState("synthetic", subject.empty_policy())
        embedded_svg = b'<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,c3ludGhldGlj"/></svg>'
        subject.scan_bytes(embedded_state, embedded_svg, surface="working-tree", object_id="working-tree:embedded.svg", display_path="embedded.svg")
        self.assertTrue(any(item.reason.startswith("invalid-image") for item in embedded_state.coverage))

    def test_invalid_zip_exact_approval_and_digest_change(self) -> None:
        invalid_zip = b"PK\x03\x04legacy-encoded-synthetic-archive"
        object_id = "working-tree:legacy.zip"
        unapproved_state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(
            unapproved_state,
            invalid_zip,
            surface="working-tree",
            object_id=object_id,
            display_path="legacy.zip",
        )
        self.assertTrue(any(item.reason.startswith("invalid-zip") for item in unapproved_state.coverage))

        approved_policy = subject.empty_policy()
        approved_policy["binary_approvals"].append(
            {
                "object": object_id,
                "sha256": subject.sha256_bytes(invalid_zip),
                "approved_by": "InformationOwner",
                "reason": "Exact legacy archive reviewed with an independent parser",
                "inspection_layers": ["manual", "digest", "independent-archive-parser"],
                "tool_versions": {"github-safe-publish": subject.TOOL_VERSION},
                "review_trigger": "object digest, parser, or scanner version changes",
            }
        )
        approved_state = subject.ScanState("synthetic", approved_policy)
        subject.scan_bytes(
            approved_state,
            invalid_zip,
            surface="working-tree",
            object_id=object_id,
            display_path="legacy.zip",
        )
        self.assertFalse(any(item.reason.startswith("invalid-zip") for item in approved_state.coverage))

        changed_state = subject.ScanState("synthetic", approved_policy)
        subject.scan_bytes(
            changed_state,
            invalid_zip + b"changed",
            surface="working-tree",
            object_id=object_id,
            display_path="legacy.zip",
        )
        self.assertTrue(any(item.reason.startswith("invalid-zip") for item in changed_state.coverage))

    def test_office_embedded_media_and_macro_are_not_skipped(self) -> None:
        # Embedded media and macro payloads must enter a supported scanner or produce an explicit gap.
        office_buffer = io.BytesIO()
        with zipfile.ZipFile(office_buffer, "w") as archive:
            archive.writestr("word/media/image.png", b"not-a-valid-png")
            archive.writestr("word/vbaProject.bin", b"MZ password=SYNTHETIC_MACRO_ONLY")
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_bytes(state, office_buffer.getvalue(), surface="working-tree", object_id="working-tree:macro.docm", display_path="macro.docm")
        self.assertTrue(any(item.reason.startswith("invalid-image") for item in state.coverage))
        self.assertIn("credential.assignment", {item.rule_id for item in state.findings})


class RepositoryTests(unittest.TestCase):
    def test_worktree_hard_timeout_returns_a_recoverable_critical_gap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            codex_home = root / "codex-home"
            checkpoint = codex_home / "private" / "github-safe-publish" / "worktree.private.json"
            state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
            real_run = subject.run

            def timeout_worker(command: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess:
                if "_scan-worktree-worker" in command:
                    raise subprocess.TimeoutExpired("worker", 1)
                return real_run(command, *args, **kwargs)

            with (
                mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}),
                mock.patch.object(subject, "run", side_effect=timeout_worker),
            ):
                subject.scan_working_tree(
                    state,
                    repository,
                    time_limit_seconds=1,
                    checkpoint_path=checkpoint,
                    checkpoint_interval=1,
                )
            self.assertTrue(any(item.reason == "working-tree-hard-time-limit-exceeded" for item in state.coverage))
            self.assertEqual("incomplete", subject.decision_for(state))
            self.assertEqual("deny", subject.publication_decision_for(state))

    def test_git_history_hard_timeout_returns_a_stable_issue_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            codex_home = root / "codex-home"
            checkpoint = codex_home / "private" / "github-safe-publish" / "history.private.json"
            state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
            real_run = subject.run

            def timeout_worker(command: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess:
                if "_scan-git-history-worker" in command:
                    raise subprocess.TimeoutExpired("worker", 1)
                return real_run(command, *args, **kwargs)

            with (
                mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}),
                mock.patch.object(subject, "run", side_effect=timeout_worker),
            ):
                subject.scan_git_history(
                    state,
                    repository,
                    time_limit_seconds=1,
                    checkpoint_path=checkpoint,
                    checkpoint_interval=1,
                )
            self.assertTrue(any(item.reason == "git-history-hard-time-limit-exceeded" for item in state.coverage))
            self.assertEqual(["GIT_HISTORY_TIMEOUT"], subject.coverage_issue_codes(state.coverage))
            self.assertEqual("incomplete", subject.decision_for(state))
            self.assertEqual("deny", subject.publication_decision_for(state))

    def test_git_history_worker_failure_is_reported_as_scanner_crash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            codex_home = root / "codex-home"
            state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
            failed = subprocess.CompletedProcess([], 4, "", "")
            real_run = subject.run

            def fail_worker(command: list[str], *args: object, **kwargs: object) -> subprocess.CompletedProcess:
                if "_scan-git-history-worker" in command:
                    return failed
                return real_run(command, *args, **kwargs)

            with (
                mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}),
                mock.patch.object(subject, "run", side_effect=fail_worker),
            ):
                subject.scan_git_history(state, repository, time_limit_seconds=5)
            self.assertTrue(any(item.reason == "git-history-worker-failed" for item in state.coverage))
            self.assertEqual(["SCANNER_CRASHED"], subject.coverage_issue_codes(state.coverage))

    def test_git_history_worker_completes_a_bounded_slice_and_returns_findings(self) -> None:
        marker = "SYNTHETIC_HISTORY_WORKER_SECRET_4821"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Synthetic User"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)
            (repository / "fixture.txt").write_text(f"password={marker}\n", encoding="utf-8")
            subprocess.run(["git", "add", "fixture.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "add synthetic history fixture"], cwd=repository, check=True, capture_output=True)
            codex_home = root / "codex-home"
            checkpoint = codex_home / "private" / "github-safe-publish" / "history.private.json"
            state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
            with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                subject.scan_git_history(
                    state,
                    repository,
                    time_limit_seconds=30,
                    checkpoint_path=checkpoint,
                    checkpoint_interval=1,
                )
            self.assertEqual("complete", state.history_progress["status"])
            self.assertTrue(any(item.rule_id == "credential.assignment" for item in state.findings))
            self.assertFalse(any(item.status not in {"checked", "not_present"} for item in state.coverage))
            serialized = json.dumps(subject.sorted_findings(state), sort_keys=True)
            self.assertNotIn(marker, serialized)
            self.assertNotIn(subject.sha256_bytes(marker.encode("utf-8")), serialized)

    def test_repository_associated_budget_records_every_unfinished_auxiliary_surface(self) -> None:
        state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
        with mock.patch.object(subject.time, "monotonic", side_effect=[0.0, 1.0]):
            subject.audit_repository_associated_surfaces(
                state,
                "ExampleOrg",
                "example",
                {},
                time_limit_seconds=1,
            )
        covered = {item.surface for item in state.coverage}
        self.assertEqual(subject.REPOSITORY_ASSOCIATED_SURFACES, covered)
        self.assertTrue(all(item.reason == "repository-associated-time-limit-exceeded" for item in state.coverage))
        self.assertTrue(all(subject.coverage_risk_level(item) == "noncritical" for item in state.coverage))
        self.assertEqual("allow_with_risk", subject.publication_decision_for(state))

    def test_remote_download_timeout_returns_tool_failure_without_output(self) -> None:
        process = mock.Mock()
        process.communicate.side_effect = [subprocess.TimeoutExpired("gh", 60), (None, b"")]
        with mock.patch.object(subject.subprocess, "Popen", return_value=process):
            data, error = subject.gh_download("synthetic/download")
        process.kill.assert_called_once_with()
        self.assertIsNone(data)
        self.assertEqual("tool_failed", error)

    def test_release_asset_budget_records_unfinished_assets_without_downloading_them(self) -> None:
        releases = [{
            "id": 1,
            "assets": [
                {"name": "one.zip", "url": "synthetic/one", "size": 10},
                {"name": "two.zip", "url": "synthetic/two", "size": 10},
            ],
        }]
        state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(subject, "gh_json", return_value=(releases, None)),
            mock.patch.object(subject.time, "monotonic", side_effect=[0.0, 1.0]),
            mock.patch.object(subject, "gh_download") as download,
        ):
            subject.download_release_assets(
                "ExampleOrg",
                "example",
                state,
                Path(temporary),
                time_limit_seconds=1,
            )
        download.assert_not_called()
        gap = next(item for item in state.coverage if item.reason == "release-asset-time-limit-exceeded")
        self.assertEqual(2, gap.object_count)
        self.assertEqual("incomplete", subject.decision_for(state))

    @unittest.skipUnless(os.name == "nt", "Windows validation exit propagation")
    def test_windows_validation_propagates_native_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary)
            failed = subject.run_validation_command('cmd.exe /d /s /c "exit 7"', cwd, 30)
            passed = subject.run_validation_command('cmd.exe /d /s /c "exit 0"', cwd, 30)
            powershell_failed = subject.run_validation_command(
                "Write-Error 'synthetic validation failure'",
                cwd,
                30,
            )

        self.assertEqual("fail", failed["status"])
        self.assertEqual(7, failed["exit_code"])
        self.assertEqual("pass", passed["status"])
        self.assertEqual(0, passed["exit_code"])
        self.assertEqual("fail", powershell_failed["status"])
        self.assertEqual(1, powershell_failed["exit_code"])

    def test_gitleaks_object_binding_uses_stable_blob_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Synthetic User"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)
            (repository / "fixture.txt").write_text("synthetic fixture\n", encoding="utf-8")
            subprocess.run(["git", "add", "fixture.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "first"], cwd=repository, check=True, capture_output=True)
            first = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True).stdout.strip()
            (repository / "unrelated.txt").write_text("second commit\n", encoding="utf-8")
            subprocess.run(["git", "add", "unrelated.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "second"], cwd=repository, check=True, capture_output=True)
            second = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True).stdout.strip()

            first_object = subject.stable_gitleaks_object_id(repository, first, "fixture.txt")
            second_object = subject.stable_gitleaks_object_id(repository, second, "fixture.txt")

        self.assertEqual(first_object, second_object)
        self.assertRegex(first_object or "", r"^gitleaks-blob:[0-9a-f]{40,64}:fixture\.txt$")

    def test_doctor_requires_numpy_only_when_repository_contains_array_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
            (root / "values.npy").write_bytes(b"synthetic")
            requirements = subject.doctor_requirements(root)

        self.assertIn("numpy", requirements)
        self.assertNotIn("libmagic", requirements)

    def test_managed_publish_audit_binds_candidate_without_remote_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            remote = root / "remote.git"
            codex_home = root / "codex-home"
            private = codex_home / "private" / "github-safe-publish" / "managed"
            policy_path = codex_home / "private" / "github-safe-publish" / "policy.private.json"
            source.mkdir()
            subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
            subprocess.run(["git", "init", "-b", "main"], cwd=source, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Synthetic User"], cwd=source, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=source, check=True)
            subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=source, check=True)
            (source / "README.md").write_text("safe\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=source, check=True)
            subprocess.run(["git", "commit", "-m", "initial"], cwd=source, check=True, capture_output=True)
            subprocess.run(["git", "push", "-u", "origin", "main"], cwd=source, check=True, capture_output=True)
            base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source, check=True, capture_output=True, text=True).stdout.strip()
            (source / "README.md").write_text("verified candidate\n", encoding="utf-8")
            policy_path.parent.mkdir(parents=True)
            policy_path.write_text(json.dumps(synthetic_policy()), encoding="utf-8")
            args = type(
                "Args",
                (),
                {
                    "source": str(source), "repository": "ExampleOrg/example", "base_commit": base, "base_branch": "main",
                    "policy": str(policy_path), "private_output_dir": str(private), "checkpoint": None,
                    "public_summary": None, "readme_auditor": None, "validation_command": [],
                    "validation_timeout_seconds": 30, "checks_timeout_seconds": 30, "intent": "audit", "branch": None,
                    "commit_message": "chore: synthetic managed publication", "pr_title": "Synthetic", "pr_body": "Synthetic",
                    "release_asset": [], "gitleaks_path": None, "release_profile": "permissive-noncritical", "resume": False,
                },
            )()
            old_codex_home = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(codex_home)

            def fake_gate(gate_args: object) -> int:
                report = {
                    "publication_decision": "allow", "scanner_versions": {"safe_publish_sha256": "a" * 64},
                    "policy_fingerprint": "b" * 64, "report_fingerprint": "c" * 64,
                }
                subject.write_json(Path(gate_args.report), report)
                return 0

            try:
                with (
                    mock.patch.object(subject, "remote_branch_commit", return_value=base),
                    mock.patch.object(subject, "doctor_report", return_value={"decision": "pass", "fingerprint": "d" * 64}),
                    mock.patch.object(subject, "ensure_gitleaks", return_value=root / "gitleaks"),
                    mock.patch.object(subject, "command_gate", side_effect=fake_gate),
                ):
                    exit_code = subject.command_managed_publish(args)
            finally:
                if old_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = old_codex_home

            checkpoint = json.loads((private / "checkpoint.private.json").read_text(encoding="utf-8"))
            first_candidate_commit = checkpoint["candidate_commit"]
            repeated_private = codex_home / "private" / "github-safe-publish" / "managed-repeat"
            args.private_output_dir = str(repeated_private)
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                with (
                    mock.patch.object(subject, "remote_branch_commit", return_value=base),
                    mock.patch.object(subject, "doctor_report", return_value={"decision": "pass", "fingerprint": "d" * 64}),
                    mock.patch.object(subject, "ensure_gitleaks", return_value=root / "gitleaks"),
                    mock.patch.object(subject, "command_gate", side_effect=fake_gate),
                ):
                    repeated_exit_code = subject.command_managed_publish(args)
            finally:
                if old_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = old_codex_home
            repeated_checkpoint = json.loads((repeated_private / "checkpoint.private.json").read_text(encoding="utf-8"))
            missing_private = codex_home / "private" / "github-safe-publish" / "managed-missing"
            args.private_output_dir = str(missing_private)
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                with (
                    mock.patch.object(subject, "remote_branch_commit", return_value=base),
                    mock.patch.object(subject, "doctor_report", return_value={"decision": "pass", "fingerprint": "d" * 64}),
                    mock.patch.object(subject, "ensure_gitleaks", return_value=root / "gitleaks"),
                    mock.patch.object(subject, "command_gate", return_value=0),
                ):
                    missing_exit_code = subject.command_managed_publish(args)
            finally:
                if old_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = old_codex_home
            missing_checkpoint = json.loads((missing_private / "checkpoint.private.json").read_text(encoding="utf-8"))

            crashed_private = codex_home / "private" / "github-safe-publish" / "managed-crashed"
            args.private_output_dir = str(crashed_private)
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                with (
                    mock.patch.object(subject, "remote_branch_commit", return_value=base),
                    mock.patch.object(subject, "doctor_report", return_value={"decision": "pass", "fingerprint": "d" * 64}),
                    mock.patch.object(subject, "ensure_gitleaks", return_value=root / "gitleaks"),
                    mock.patch.object(subject, "command_gate", side_effect=RuntimeError("synthetic crash")),
                ):
                    crashed_exit_code = subject.command_managed_publish(args)
            finally:
                if old_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = old_codex_home
            crashed_checkpoint = json.loads((crashed_private / "checkpoint.private.json").read_text(encoding="utf-8"))
            remote_branches = subprocess.run(
                ["git", "for-each-ref", "--format=%(refname)", "refs/heads"],
                cwd=remote,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()

        self.assertEqual(0, exit_code)
        self.assertEqual(0, repeated_exit_code)
        self.assertEqual(4, missing_exit_code)
        self.assertEqual(["GATE_REPORT_MISSING"], missing_checkpoint["issue_codes"])
        self.assertEqual("incomplete", missing_checkpoint["state"])
        self.assertEqual(4, crashed_exit_code)
        self.assertEqual(["SCANNER_CRASHED"], crashed_checkpoint["issue_codes"])
        self.assertEqual("incomplete", crashed_checkpoint["state"])
        self.assertEqual("gated", checkpoint["state"])
        self.assertEqual(first_candidate_commit, repeated_checkpoint["candidate_commit"])
        self.assertRegex(checkpoint["candidate_tree_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(checkpoint["patch_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(["refs/heads/main"], remote_branches)

    def test_rendered_pages_follow_only_same_origin_resources(self) -> None:
        root = b'<html><img src="/asset.txt"><a href="https://outside.example/skip">x</a></html>'
        asset = b"AIALRA"
        state = subject.ScanState("synthetic", subject.validate_policy(synthetic_policy()))
        with mock.patch.object(
            subject,
            "fetch_public_url",
            side_effect=[(root, None, "text/html"), (asset, None, "text/plain")],
        ) as fetch:
            subject.audit_rendered_pages(state, "https://pages.example.invalid/")
        self.assertEqual(2, fetch.call_count)
        self.assertIn("private.brand", {item.rule_id for item in state.findings})
        self.assertFalse(any("outside.example" in call.args[0] for call in fetch.call_args_list))

    def test_nested_repositories_are_mapped_by_remote_full_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "group" / "renamed-local-folder"
            nested.mkdir(parents=True)
            subprocess.run(["git", "init", "-b", "main"], cwd=nested, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "git@github.com:ExampleOrg/example-repo.git"], cwd=nested, check=True)
            discovered = subject.discover_git_repositories([root])
            self.assertEqual(nested.resolve(), discovered["exampleorg/example-repo"])

    def test_git_ref_tag_and_note_surfaces_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "metadata"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Example User"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)
            (repository / "file.txt").write_text("safe\n", encoding="utf-8")
            subprocess.run(["git", "add", "file.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "safe"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "branch", "u" + "id=user-private-0042"], cwd=repository, check=True)
            subprocess.run(["git", "tag", "-a", "fixture", "-m", "password=SYNTHETIC_TAG"], cwd=repository, check=True)
            subprocess.run(["git", "notes", "add", "-m", "owner@" + "private.test"], cwd=repository, check=True)
            state = subject.ScanState("synthetic", subject.validate_policy(synthetic_policy()))
            subject.scan_git_history(state, repository)
            rules = {item.rule_id for item in state.findings}
            self.assertIn("identity.uid", rules)
            self.assertIn("credential.assignment", rules)
            self.assertIn("private.contact", rules)

    def test_local_audit_streams_sessions_resumes_and_keeps_raw_output_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            codex_home = root / "codex-home"
            session_dir = codex_home / "sessions" / "2026" / "08"
            project = root / "project"
            session_dir.mkdir(parents=True)
            project.mkdir()
            marker = "SYNTHETIC_SESSION_ONLY_9274"
            records = [
                {"type": "session_meta", "payload": {"id": "session-1"}},
                {"type": "response_item", "payload": {"text": "password=" + marker}},
            ]
            (session_dir / "session.jsonl").write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")
            (project / "safe.txt").write_text("safe\n", encoding="utf-8")
            (codex_home / ".codex-global-state.json").write_text(json.dumps({"electron-saved-workspace-roots": [str(project)], "local-projects": {}}), encoding="utf-8")
            private = codex_home / "private" / "github-safe-publish"
            args = type("Args", (), {
                "policy": None,
                "output": str(private / "local-report.private.json"),
                "candidates_output": str(private / "candidates.private.json"),
                "checkpoint": str(private / "local-checkpoint.private.json"),
                "public_summary": str(root / "summary.json"),
                "resume": True,
            })()
            old_codex_home = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(codex_home)
            stdout = io.StringIO()
            stderr = io.StringIO()
            try:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    first = subject.command_audit_local(args)
                    second = subject.command_audit_local(args)
            finally:
                if old_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = old_codex_home
            self.assertIn(first, {0, 2, 4})
            self.assertIn(second, {0, 2, 4})
            self.assertNotIn(marker, stdout.getvalue() + stderr.getvalue() + (root / "summary.json").read_text(encoding="utf-8"))
            report = json.loads((private / "local-report.private.json").read_text(encoding="utf-8"))
            self.assertEqual(1, report["session_count"])

    def test_local_audit_resume_keeps_committed_candidates_and_all_session_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            codex_home = root / "codex-home"
            session_dir = codex_home / "sessions"
            session_dir.mkdir(parents=True)
            marker = "SYNTHETIC_RESUME_ONLY_4821"
            records = [
                {"type": "session_meta", "payload": {"id": "session-first"}},
                {"type": "response_item", "payload": {"text": "password=" + marker}},
                {"type": "session_meta", "payload": {"id": "session-second"}},
            ]
            (session_dir / "session.jsonl").write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")
            (codex_home / ".codex-global-state.json").write_text(json.dumps({"electron-saved-workspace-roots": [], "local-projects": {}}), encoding="utf-8")
            private = codex_home / "private" / "github-safe-publish"
            args = type("Args", (), {
                "policy": None,
                "output": str(private / "local-report.private.json"),
                "candidates_output": str(private / "candidates.private.json"),
                "checkpoint": str(private / "local-checkpoint.private.json"),
                "public_summary": str(root / "summary.json"),
                "resume": True,
            })()
            old_codex_home = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                with mock.patch.object(subject.PrivateCandidateStore, "remove_database", return_value=None):
                    first_result = subject.command_audit_local(args)
                Path(args.candidates_output).unlink()
                result = subject.command_audit_local(args)
            finally:
                if old_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = old_codex_home
            self.assertIn(first_result, {0, 2, 4})
            self.assertIn(result, {0, 2, 4})
            report = json.loads((private / "local-report.private.json").read_text(encoding="utf-8"))
            candidates = json.loads((private / "candidates.private.json").read_text(encoding="utf-8"))
            self.assertEqual(2, report["session_count"])
            self.assertTrue(any(item["raw_value"] == marker for item in candidates["candidates"]))

    def test_raw_candidate_limit_fails_closed(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy(), collect_raw=True)
        with mock.patch.object(subject, "MAX_RAW_CANDIDATES_PER_STATE", 1):
            subject.scan_text(
                state,
                "password=SYNTHETIC_FIRST_1234\npassword=SYNTHETIC_SECOND_5678",
                surface="working-tree",
                object_id="working-tree:fixture.txt",
                display_path="fixture.txt",
            )
        self.assertEqual(1, len(state.raw_candidates))
        self.assertTrue(any(item.reason == "raw-candidate-limit-exceeded" and item.status == "tool_failed" for item in state.coverage))

    def test_local_session_worker_crash_is_isolated_and_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            codex_home = root / "codex-home"
            session_dir = codex_home / "sessions"
            session_dir.mkdir(parents=True)
            (session_dir / "session.jsonl").write_text(json.dumps({"type": "session_meta", "payload": {"id": "session-crash"}}) + "\n", encoding="utf-8")
            (codex_home / ".codex-global-state.json").write_text(json.dumps({"electron-saved-workspace-roots": [], "local-projects": {}}), encoding="utf-8")
            private = codex_home / "private" / "github-safe-publish"
            args = type("Args", (), {
                "policy": None,
                "output": str(private / "local-report.private.json"),
                "candidates_output": str(private / "candidates.private.json"),
                "checkpoint": str(private / "local-checkpoint.private.json"),
                "public_summary": str(root / "summary.json"),
                "resume": False,
            })()
            old_codex_home = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                crashed = type("Completed", (), {"returncode": 0xC0000005})()
                real_run = subprocess.run

                def run_with_worker_crash(command: object, *positional: object, **keywords: object) -> object:
                    if isinstance(command, list) and "_audit-local-session-worker" in command:
                        return crashed
                    return real_run(command, *positional, **keywords)

                with mock.patch.object(subject.subprocess, "run", side_effect=run_with_worker_crash):
                    result = subject.command_audit_local(args)
            finally:
                if old_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = old_codex_home
            report = json.loads((private / "local-report.private.json").read_text(encoding="utf-8"))
            self.assertEqual(4, result)
            self.assertEqual("incomplete", report["decision"])
            self.assertEqual("unreadable", report["sessions"][0]["status"])

    def test_full_history_submodule_and_missing_lfs_are_enumerated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "history"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Example User"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)

            # Commit a synthetic credential, then rename and delete it so only full-history scanning can recover it.
            (repository / "old.txt").write_text("password=SYNTHETIC_DELETED_HISTORY\n", encoding="utf-8")
            subprocess.run(["git", "add", "old.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "add historical fixture"], cwd=repository, check=True, capture_output=True)
            first_commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "branch", "fixture-branch", first_commit], cwd=repository, check=True)
            subprocess.run(["git", "tag", "fixture-tag", first_commit], cwd=repository, check=True)
            subprocess.run(["git", "mv", "old.txt", "renamed.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "rename fixture"], cwd=repository, check=True, capture_output=True)
            (repository / "renamed.txt").unlink()
            subprocess.run(["git", "add", "-u"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "delete fixture"], cwd=repository, check=True, capture_output=True)

            # Add a Git submodule pointer without contacting an external repository.
            (repository / ".gitmodules").write_text('[submodule "vendor/demo"]\n\tpath = vendor/demo\n\turl = https://example.invalid/demo.git\n', encoding="utf-8")
            subprocess.run(["git", "add", ".gitmodules"], cwd=repository, check=True)
            subprocess.run(["git", "update-index", "--add", "--cacheinfo", f"160000,{first_commit},vendor/demo"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "add synthetic gitlink"], cwd=repository, check=True, capture_output=True)

            # Add an LFS pointer whose entity is intentionally missing to verify fail-closed coverage.
            (repository / ".gitattributes").write_text("large.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8")
            (repository / "large.bin").write_text(
                "version https://git-lfs.github.com/spec/v1\n" + "oid sha256:" + ("a" * 64) + "\nsize 4\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", ".gitattributes", "large.bin"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "add missing lfs fixture"], cwd=repository, check=True, capture_output=True)

            state = subject.ScanState("synthetic", subject.empty_policy())
            subject.scan_working_tree(state, repository)
            subject.scan_git_history(state, repository)
            subject.scan_submodules(state, repository)
            subject.scan_lfs(state, repository)
            self.assertTrue(any(item.rule_id == "credential.assignment" for item in state.findings))
            self.assertTrue(any(item.surface == "submodules" and item.object_count >= 1 for item in state.coverage))
            self.assertTrue(any(item.surface == "git-lfs" and item.status == "unreadable" for item in state.coverage))
            self.assertFalse(any(item.reason.startswith("file-unreadable:working-tree:vendor/demo") for item in state.coverage))

            # Private candidate generation includes deleted history rather than only the current working tree.
            codex_home = Path(temporary) / "candidate-home"
            candidate_output = codex_home / "private" / "github-safe-publish" / "candidates.private.json"
            old_codex_home = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                candidate_args = type("Args", (), {"source": str(repository), "repository": "synthetic", "output": str(candidate_output)})()
                self.assertEqual(4, subject.command_policy_candidates(candidate_args))
            finally:
                if old_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = old_codex_home
            candidate_document = json.loads(candidate_output.read_text(encoding="utf-8"))
            historical_paths = ("old.txt", "renamed.txt")
            self.assertTrue(
                any(
                    item["rule_id"] == "credential.assignment" and any(path in item["object"] for path in historical_paths)
                    for item in candidate_document["candidates"]
                )
            )

            # Fleet auditing records a bounded failure instead of claiming unscanned history is clean.
            bounded_state = subject.ScanState("synthetic", subject.empty_policy())
            bounded_home = Path(temporary) / "bounded-home"
            with mock.patch.dict(os.environ, {"CODEX_HOME": str(bounded_home)}):
                subject.scan_git_history(bounded_state, repository, time_limit_seconds=0)
            self.assertTrue(any(item.reason == "git-history-time-limit-exceeded" for item in bounded_state.coverage))
            self.assertEqual("incomplete", subject.decision_for(bounded_state))

    def test_full_history_checkpoint_resumes_and_rejects_changed_bindings(self) -> None:
        marker = "SYNTHETIC_CHECKPOINT_SECRET_7391"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "history"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Example User"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)
            (repository / "secret.txt").write_text("password=" + marker + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "secret.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "add resumable fixture"], cwd=repository, check=True, capture_output=True)

            codex_home = root / "cold"
            checkpoint = codex_home / "private" / "github-safe-publish" / "history.private.json"
            previous_codex_home = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                partial = subject.ScanState("ExampleOrg/history", subject.empty_policy())
                subject.scan_git_history(
                    partial,
                    repository,
                    time_limit_seconds=0,
                    checkpoint_path=checkpoint,
                    checkpoint_interval=1,
                )
                self.assertEqual("incomplete", subject.decision_for(partial))
                self.assertEqual("deny", subject.publication_decision_for(partial))
                self.assertTrue(checkpoint.is_file())
                checkpoint_text = checkpoint.read_text(encoding="utf-8")
                self.assertNotIn(marker, checkpoint_text)
                self.assertNotIn(subject.sha256_bytes(marker.encode("utf-8")), checkpoint_text)

                resumed = subject.ScanState("ExampleOrg/history", subject.empty_policy())
                subject.scan_git_history(
                    resumed,
                    repository,
                    checkpoint_path=checkpoint,
                    checkpoint_interval=1,
                )
                self.assertEqual("complete", resumed.history_progress["status"])
                self.assertTrue(resumed.history_progress["resumed"])
                self.assertTrue(any(item.rule_id == "credential.assignment" for item in resumed.findings))
                self.assertFalse(any(item.reason == "git-history-time-limit-exceeded" for item in resumed.coverage))

                one_shot = subject.ScanState("ExampleOrg/history", subject.empty_policy())
                subject.scan_git_history(one_shot, repository)
                normalized = lambda state: sorted(
                    (item.surface, item.object, item.location, item.rule_id, item.status) for item in state.findings
                )
                self.assertEqual(normalized(one_shot), normalized(resumed))

                reused = subject.ScanState("ExampleOrg/history", subject.empty_policy())
                subject.scan_git_history(reused, repository, checkpoint_path=checkpoint)
                self.assertEqual(normalized(resumed), normalized(reused))
                self.assertEqual("complete", reused.history_progress["status"])

                (repository / "changed.txt").write_text("changed\n", encoding="utf-8")
                subprocess.run(["git", "add", "changed.txt"], cwd=repository, check=True)
                subprocess.run(["git", "commit", "-m", "change binding"], cwd=repository, check=True, capture_output=True)
                stale = subject.ScanState("ExampleOrg/history", subject.empty_policy())
                subject.scan_git_history(stale, repository, checkpoint_path=checkpoint)
                self.assertTrue(any(item.reason == "git-history-checkpoint-binding-mismatch" for item in stale.coverage))
                self.assertEqual("incomplete", subject.decision_for(stale))
                self.assertEqual("deny", subject.publication_decision_for(stale))
            finally:
                if previous_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = previous_codex_home

    def test_gitleaks_detects_a_runtime_generated_credential(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary) / "gitleaks"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Example User"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)
            generated_marker = "gh" + "p_" + "7H4G2J9K5M8N3P6Q1R4S7T0V2W5X8Y6Z9B3C"
            (repository / "credential.txt").write_text("GITHUB_TOKEN=" + generated_marker + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "credential.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "runtime credential fixture"], cwd=repository, check=True, capture_output=True)
            state = subject.ScanState("synthetic", subject.empty_policy())
            subject.run_gitleaks(state, repository)
            self.assertTrue(any(item.rule_id.startswith("gitleaks.") for item in state.findings))
            self.assertNotIn(generated_marker, json.dumps(subject.sorted_findings(state), sort_keys=True))

    def test_gitleaks_runtime_canary_fails_closed_on_silent_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "gitleaks"
            binary.write_bytes(b"synthetic-binary")
            state = subject.ScanState("synthetic", subject.empty_policy())
            subject.VERIFIED_GITLEAKS.clear()
            silent = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            with mock.patch.object(subject, "run", return_value=silent):
                subject.run_gitleaks(state, root, binary)
            self.assertTrue(any(item.reason == "gitleaks-runtime-canary-not-detected" for item in state.coverage))

    def test_gitleaks_process_timeout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "gitleaks"
            binary.write_bytes(b"synthetic-binary")
            key = f"{binary.resolve()}:{subject.sha256_bytes(binary.read_bytes())}"
            state = subject.ScanState("synthetic", subject.empty_policy())
            subject.VERIFIED_GITLEAKS.add(key)
            try:
                with mock.patch.object(subject, "run", side_effect=subprocess.TimeoutExpired(["gitleaks"], 330)):
                    subject.run_gitleaks(state, root, binary)
            finally:
                subject.VERIFIED_GITLEAKS.discard(key)
            self.assertTrue(any(item.reason == "gitleaks-process-timeout" and item.status == "tool_failed" for item in state.coverage))
            self.assertEqual("incomplete", subject.decision_for(state))

    def test_prepare_changes_only_disposable_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "publication"
            codex_home = root / "codex-home"
            policy_path = codex_home / "private" / "github-safe-publish" / "policy.private.json"
            report_path = codex_home / "private" / "github-safe-publish" / "prepare-report.json"
            source.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=source, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Example User"], cwd=source, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=source, check=True)
            (source / "sample.txt").write_text("AIALRA owner@" + "private.test\n", encoding="utf-8")
            subprocess.run(["git", "add", "sample.txt"], cwd=source, check=True)
            subprocess.run(["git", "commit", "-m", "synthetic fixture"], cwd=source, check=True, capture_output=True)
            # Add a synthetic gitlink so clean-root mode must preserve its exact tree semantics.
            submodule_commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source, check=True, capture_output=True, text=True).stdout.strip()
            (source / ".gitmodules").write_text('[submodule "vendor/demo"]\n\tpath = vendor/demo\n\turl = https://example.invalid/demo.git\n', encoding="utf-8")
            subprocess.run(["git", "add", ".gitmodules"], cwd=source, check=True)
            subprocess.run(["git", "update-index", "--add", "--cacheinfo", f"160000,{submodule_commit},vendor/demo"], cwd=source, check=True)
            subprocess.run(["git", "commit", "-m", "add synthetic gitlink"], cwd=source, check=True, capture_output=True)
            policy_path.parent.mkdir(parents=True)
            policy_path.write_text(json.dumps(synthetic_policy()), encoding="utf-8")
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source, check=True, capture_output=True, text=True).stdout.strip()
            old_codex_home = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                args = type(
                    "Args",
                    (),
                    {
                        "source": str(source),
                        "destination": str(destination),
                        "policy": str(policy_path),
                        "commit": commit,
                        "mode": "clean-root",
                        "report": str(report_path),
                    },
                )()
                self.assertEqual(0, subject.command_prepare(args))
            finally:
                if old_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = old_codex_home
            self.assertEqual("AIALRA owner@" + "private.test\n", (source / "sample.txt").read_text(encoding="utf-8"))
            self.assertEqual("ExampleOrg owner@example.invalid\n", (destination / "sample.txt").read_text(encoding="utf-8"))
            staged = subprocess.run(["git", "ls-files", "--stage", "vendor/demo"], cwd=destination, check=True, capture_output=True, text=True).stdout
            self.assertTrue(staged.startswith(f"160000 {submodule_commit} 0\tvendor/demo"))

    def test_prepare_missing_lfs_writes_incomplete_report_and_removes_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "publication"
            codex_home = root / "codex-home"
            policy_path = codex_home / "private" / "github-safe-publish" / "policy.private.json"
            report_path = codex_home / "private" / "github-safe-publish" / "prepare-report.json"
            source.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=source, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Example User"], cwd=source, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=source, check=True)
            (source / ".gitattributes").write_text("large.bin filter=lfs diff=lfs merge=lfs -text\n", encoding="utf-8")
            (source / "large.bin").write_text("version https://git-lfs.github.com/spec/v1\n" + "oid sha256:" + ("a" * 64) + "\nsize 4\n", encoding="utf-8")
            subprocess.run(["git", "add", ".gitattributes", "large.bin"], cwd=source, check=True)
            subprocess.run(["git", "commit", "-m", "missing LFS fixture"], cwd=source, check=True, capture_output=True)
            policy_path.parent.mkdir(parents=True)
            policy_path.write_text(json.dumps(synthetic_policy()), encoding="utf-8")
            commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=source, check=True, capture_output=True, text=True).stdout.strip()
            old_codex_home = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                args = type("Args", (), {"source": str(source), "destination": str(destination), "policy": str(policy_path), "commit": commit, "mode": "clean-root", "report": str(report_path)})()
                self.assertEqual(4, subject.command_prepare(args))
            finally:
                if old_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = old_codex_home
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual("incomplete", report["decision"])
            self.assertFalse(destination.exists())

    def test_same_content_and_policy_produce_same_decision(self) -> None:
        policy = subject.validate_policy(synthetic_policy())
        decisions = []
        findings = []
        for _ in range(2):
            state = subject.ScanState("synthetic", policy)
            subject.scan_text(state, "AIALRA password=SYNTHETIC_REPEAT", surface="working-tree", object_id="working-tree:repeat.txt", display_path="repeat.txt")
            state.add_coverage("working-tree", "checked", object_count=1)
            decisions.append(subject.decision_for(state))
            findings.append(subject.sorted_findings(state))
        self.assertEqual(decisions[0], decisions[1])
        self.assertEqual(findings[0], findings[1])


class ResumeAndPaginationTests(unittest.TestCase):
    def test_artifact_worker_reuses_an_open_ocr_checkpoint(self) -> None:
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><text>synthetic</text></svg>'
        with tempfile.TemporaryDirectory() as temporary:
            codex_home = Path(temporary) / "codex-home"
            checkpoint = codex_home / "private" / "github-safe-publish" / "ocr.private.sqlite"
            binding = {"schema": 1, "repository": "ExampleOrg/example", "source_commit": "b" * 40}
            with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                store = subject.OcrCheckpointStore(checkpoint, binding)
                state = subject.ScanState("ExampleOrg/example", subject.empty_policy(), ocr_store=store)
                subject.scan_bytes_bounded(
                    state,
                    svg,
                    surface="working-tree",
                    object_id="working-tree:diagram.svg",
                    display_path="diagram.svg",
                )
                subject.ARTIFACT_PROCESS_RUNNER.close()
                store.close()
            self.assertFalse(any(item.reason.startswith("artifact-worker-failed") for item in state.coverage))
            self.assertFalse(any(item.reason.startswith("artifact-unit-timeout") for item in state.coverage))

    def test_worktree_worker_completes_a_bounded_slice_and_returns_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Example User"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)
            (repository / "secret.txt").write_text("password=SYNTHETIC_WORKTREE_WORKER\n", encoding="utf-8")
            subprocess.run(["git", "add", "secret.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "add bounded worker fixture"], cwd=repository, check=True, capture_output=True)
            codex_home = root / "codex-home"
            checkpoint = codex_home / "private" / "github-safe-publish" / "worktree.private.json"
            state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
            with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                subject.scan_working_tree(
                    state,
                    repository,
                    time_limit_seconds=30,
                    checkpoint_path=checkpoint,
                    checkpoint_interval=1,
                )
            self.assertEqual("complete", state.worktree_progress["status"])
            self.assertTrue(any(item.rule_id == "credential.assignment" for item in state.findings))
            self.assertTrue(any(item.surface == "working-tree" and item.status == "checked" for item in state.coverage))

    def test_parent_repository_ocr_budget_is_passed_to_artifact_worker(self) -> None:
        state = subject.ScanState("ExampleOrg/example", subject.empty_policy())
        state.image_ocr_budget_seconds = 10
        state.image_ocr_started_at = time.monotonic() - 20
        with mock.patch.object(subject.ARTIFACT_PROCESS_RUNNER, "run") as isolated:
            subject.scan_bytes_bounded(
                state,
                b"\x89PNG\r\n\x1a\nsynthetic",
                surface="working-tree",
                object_id="working-tree:image.png",
                display_path="image.png",
            )
        self.assertEqual(0, isolated.call_args.kwargs["ocr_budget_remaining"])

    def test_worktree_checkpoint_retries_current_file_and_resumes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Example User"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)
            (repository / "image.png").write_bytes(b"synthetic-image")
            subprocess.run(["git", "add", "image.png"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "add worktree fixture"], cwd=repository, check=True, capture_output=True)
            codex_home = root / "codex-home"
            checkpoint = codex_home / "private" / "github-safe-publish" / "worktree.private.json"
            calls = 0

            def budget_once(state: subject.ScanState, data: bytes, **kwargs: object) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    state.add_coverage("working-tree", "unreadable", "image-ocr-budget-exceeded:synthetic")
                else:
                    state.add_coverage("working-tree", "checked", "image-layers:synthetic", 1)

            with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                first = subject.ScanState("ExampleOrg/example", subject.empty_policy())
                with mock.patch.object(subject, "scan_bytes_bounded", side_effect=budget_once):
                    subject.scan_working_tree(first, repository, checkpoint_path=checkpoint, checkpoint_interval=1)
                self.assertEqual("in_progress", first.worktree_progress["status"])
                self.assertEqual(0, first.worktree_progress["processed_file_count"])

                second = subject.ScanState("ExampleOrg/example", subject.empty_policy())
                with mock.patch.object(subject, "scan_bytes_bounded", side_effect=budget_once):
                    subject.scan_working_tree(second, repository, checkpoint_path=checkpoint, checkpoint_interval=1)
                self.assertEqual("complete", second.worktree_progress["status"])
                self.assertTrue(second.worktree_progress["resumed"])
                self.assertFalse(any(item.reason.startswith("image-ocr-budget-exceeded") for item in second.coverage))

    def test_image_ocr_checkpoint_replays_across_scan_states_without_raw_text(self) -> None:
        marker = "SYNTHETIC_OCR_SECRET_8042"
        with tempfile.TemporaryDirectory() as temporary:
            codex_home = Path(temporary) / "codex-home"
            checkpoint = codex_home / "private" / "github-safe-publish" / "ocr.private.sqlite"
            binding = {"schema": 1, "repository": "ExampleOrg/example", "source_commit": "a" * 40}
            with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                first_store = subject.OcrCheckpointStore(checkpoint, binding)
                first = subject.ScanState("ExampleOrg/example", subject.empty_policy(), ocr_store=first_store)
                with mock.patch.object(
                    subject,
                    "extract_image_layers",
                    return_value=([("ocr:0:0", "password=" + marker)], {"metadata", "qr", "barcode", "ocr"}, []),
                ):
                    subject.scan_image_content(
                        first,
                        b"synthetic-image",
                        surface="working-tree",
                        object_id="working-tree:image.png",
                        display_path="image.png",
                    )
                first_store.close()

                second_store = subject.OcrCheckpointStore(checkpoint, binding)
                second = subject.ScanState("ExampleOrg/example", subject.empty_policy(), ocr_store=second_store)
                second.image_ocr_budget_seconds = 0
                with mock.patch.object(subject, "extract_image_layers", side_effect=AssertionError("OCR should replay")):
                    subject.scan_image_content(
                        second,
                        b"synthetic-image",
                        surface="working-tree",
                        object_id="working-tree:image.png",
                        display_path="image.png",
                    )
                second_store.close()

            self.assertEqual(subject.sorted_findings(first), subject.sorted_findings(second))
            self.assertFalse(any(item.reason.startswith("image-ocr-budget-exceeded") for item in second.coverage))
            checkpoint_bytes = checkpoint.read_bytes()
            self.assertNotIn(marker.encode("utf-8"), checkpoint_bytes)
            self.assertNotIn(subject.sha256_bytes(marker.encode("utf-8")).encode("ascii"), checkpoint_bytes)

    def test_private_record_pages_round_trip_without_loss(self) -> None:
        records = [{"record": index} for index in range(25)]
        with tempfile.TemporaryDirectory() as temporary:
            codex_home = Path(temporary) / "codex-home"
            base = codex_home / "private" / "github-safe-publish" / "report.private.json"
            with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                manifest = subject.write_private_record_pages(base, records, kind="test-findings", page_size=10)
                restored = subject.read_private_record_pages(base, manifest)
            self.assertEqual(25, manifest["record_count"])
            self.assertEqual(3, manifest["page_count"])
            self.assertEqual(records, restored)

    def test_history_checkpoint_retries_object_when_ocr_budget_expires(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "history"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Example User"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)
            (repository / "image.png").write_bytes(b"synthetic-image")
            subprocess.run(["git", "add", "image.png"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "add resumable image"], cwd=repository, check=True, capture_output=True)
            codex_home = root / "codex-home"
            checkpoint = codex_home / "private" / "github-safe-publish" / "history.private.json"
            calls = 0

            def budget_once(state: subject.ScanState, data: bytes, **kwargs: object) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    state.add_coverage("git-history", "unreadable", "image-ocr-budget-exceeded:synthetic")
                else:
                    state.add_coverage("git-history", "checked", "image-layers:synthetic", 1)

            with mock.patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                first = subject.ScanState("ExampleOrg/history", subject.empty_policy())
                with mock.patch.object(subject, "scan_bytes_bounded", side_effect=budget_once):
                    subject.scan_git_history(first, repository, checkpoint_path=checkpoint, checkpoint_interval=1)
                self.assertEqual("in_progress", first.history_progress["status"])
                first_index = first.history_progress["processed_object_count"]

                second = subject.ScanState("ExampleOrg/history", subject.empty_policy())
                with mock.patch.object(subject, "scan_bytes_bounded", side_effect=budget_once):
                    subject.scan_git_history(second, repository, checkpoint_path=checkpoint, checkpoint_interval=1)
                self.assertEqual("complete", second.history_progress["status"])
                self.assertGreaterEqual(second.history_progress["processed_object_count"], first_index)
                self.assertFalse(any(item.reason.startswith("image-ocr-budget-exceeded") for item in second.coverage))


if __name__ == "__main__":
    unittest.main()
