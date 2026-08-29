from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
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
            {"id": "private.contact", "kind": "literal", "value": "owner@private.test", "severity": "block"},
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
                "postgres://demo:SYNTHETIC_DB_PASS@db.internal:5432/app",
                "Contact owner@private.test or +1 (555) 010-1234",
                "uid=user-private-0042 device_id=device-private-0088",
                "AIALRA and AΙALRA",
                "北京市海淀区示例街道42号",
                "42 Example Street",
                "http://" + "10." + "24.1.8:8080/private",
                "AA:BB:CC:DD:EE:FF",
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
        state = subject.ScanState("synthetic", subject.validate_policy(policy))
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
        state = subject.ScanState("synthetic", subject.validate_policy(policy))
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
        approved_state = subject.ScanState("synthetic", subject.validate_policy(approved_policy))
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

    def test_confirmed_public_url_allows_with_risk_but_strict_profile_denies(self) -> None:
        state, finding = self._url_state()
        self.assertEqual("review", subject.decision_for(state))
        self.assertEqual("deny", subject.publication_decision_for(state))
        self._accept_url(state, finding)
        self.assertEqual("allow_with_risk", subject.publication_decision_for(state))
        self.assertEqual("deny", subject.publication_decision_for(state, release_profile="strict"))

    def test_expired_changed_object_or_changed_scanner_reopens_denial(self) -> None:
        cases = (
            {"expires_at": "2000-01-01T00:00:00Z"},
            {"object_sha256": "1" * 64},
            {"scanner_sha256": "2" * 64},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                state, finding = self._url_state()
                self._accept_url(state, finding, **changes)
                self.assertEqual("deny", subject.publication_decision_for(state))

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
        state = subject.ScanState("ExampleOrg/example", subject.validate_policy(policy))
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
            report_path = root / "gate.private.json"
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
            with (
                mock.patch.object(subject, "load_policy", return_value=subject.validate_policy(policy)),
                mock.patch.object(subject, "scan_working_tree", side_effect=scan_working_tree),
                mock.patch.object(subject, "scan_git_history", side_effect=checked_surface("git-history")),
                mock.patch.object(subject, "scan_submodules", side_effect=checked_surface("submodules")),
                mock.patch.object(subject, "scan_lfs", side_effect=checked_surface("git-lfs")),
                mock.patch.object(subject, "run_gitleaks", side_effect=checked_surface("gitleaks")),
            ):
                exit_code = subject.command_gate(args)

            report = json.loads(report_path.read_text(encoding="utf-8"))
            public = json.loads(public_path.read_text(encoding="utf-8"))
            self.assertEqual(0, exit_code)
            self.assertEqual("review", report["decision"])
            self.assertEqual("allow_with_risk", report["publication_decision"])
            self.assertEqual("allow_with_risk", public["publication_decision"])
            public_text = public_path.read_text(encoding="utf-8")
            self.assertNotIn("README.md", public_text)
            self.assertNotIn("infrastructure.url", public_text)
            self.assertNotIn("docs.example.com", public_text)


class ArtifactTests(unittest.TestCase):
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
            archive.writestr("docProps/core.xml", "<creator>owner@private.test</creator>")
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
        embedded_state = subject.ScanState("synthetic", subject.empty_policy())
        embedded_svg = b'<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,c3ludGhldGlj"/></svg>'
        subject.scan_bytes(embedded_state, embedded_svg, surface="working-tree", object_id="working-tree:embedded.svg", display_path="embedded.svg")
        self.assertTrue(any(item.reason.startswith("invalid-image") for item in embedded_state.coverage))

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
            remote_branches = subprocess.run(
                ["git", "for-each-ref", "--format=%(refname)", "refs/heads"],
                cwd=remote,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()

        self.assertEqual(0, exit_code)
        self.assertEqual(0, repeated_exit_code)
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
            subprocess.run(["git", "branch", "uid=user-private-0042"], cwd=repository, check=True)
            subprocess.run(["git", "tag", "-a", "fixture", "-m", "password=SYNTHETIC_TAG"], cwd=repository, check=True)
            subprocess.run(["git", "notes", "add", "-m", "owner@private.test"], cwd=repository, check=True)
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
            subject.scan_git_history(bounded_state, repository, time_limit_seconds=0)
            self.assertTrue(any(item.reason == "git-history-time-limit-exceeded" for item in bounded_state.coverage))
            self.assertEqual("incomplete", subject.decision_for(bounded_state))

    def test_working_tree_checkpoint_resumes_and_rejects_changed_bindings(self) -> None:
        marker = "SYNTHETIC_WORKTREE_CHECKPOINT_SECRET_8127"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "worktree"
            repository.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Example User"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)
            (repository / "secret.txt").write_text("password=" + marker + "\n", encoding="utf-8")
            subprocess.run(["git", "add", "secret.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "add resumable worktree fixture"], cwd=repository, check=True, capture_output=True)

            codex_home = root / "cold"
            checkpoint = codex_home / "private" / "github-safe-publish" / "worktree.private.json"
            previous_codex_home = os.environ.get("CODEX_HOME")
            os.environ["CODEX_HOME"] = str(codex_home)
            try:
                partial = subject.ScanState("ExampleOrg/worktree", subject.empty_policy())
                subject.scan_working_tree(
                    partial,
                    repository,
                    time_limit_seconds=0,
                    checkpoint_path=checkpoint,
                    checkpoint_interval=1,
                )
                self.assertEqual("incomplete", subject.decision_for(partial))
                self.assertEqual("deny", subject.publication_decision_for(partial))
                self.assertTrue(checkpoint.is_file())
                checkpoint_before_resume = checkpoint.read_bytes()
                checkpoint_text = checkpoint_before_resume.decode("utf-8")
                self.assertNotIn(marker, checkpoint_text)
                self.assertNotIn(subject.sha256_bytes(marker.encode("utf-8")), checkpoint_text)

                resumed = subject.ScanState("ExampleOrg/worktree", subject.empty_policy())
                subject.scan_working_tree(
                    resumed,
                    repository,
                    checkpoint_path=checkpoint,
                    checkpoint_interval=1,
                )
                self.assertEqual("complete", resumed.worktree_progress["status"])
                self.assertTrue(resumed.worktree_progress["resumed"])
                self.assertTrue(any(item.rule_id == "credential.assignment" for item in resumed.findings))
                self.assertFalse(any(item.reason == "working-tree-time-limit-exceeded" for item in resumed.coverage))

                one_shot = subject.ScanState("ExampleOrg/worktree", subject.empty_policy())
                subject.scan_working_tree(one_shot, repository)
                normalized = lambda state: sorted(
                    (item.surface, item.object, item.location, item.rule_id, item.status) for item in state.findings
                )
                self.assertEqual(normalized(one_shot), normalized(resumed))

                completed_checkpoint = checkpoint.read_bytes()
                (repository / "secret.txt").write_text("password=" + marker + "-changed\n", encoding="utf-8")
                stale = subject.ScanState("ExampleOrg/worktree", subject.empty_policy())
                subject.scan_working_tree(stale, repository, checkpoint_path=checkpoint)
                self.assertTrue(any(item.reason == "working-tree-checkpoint-binding-mismatch" for item in stale.coverage))
                self.assertEqual("incomplete", subject.decision_for(stale))
                self.assertEqual("deny", subject.publication_decision_for(stale))
                self.assertEqual(completed_checkpoint, checkpoint.read_bytes())
            finally:
                if previous_codex_home is None:
                    os.environ.pop("CODEX_HOME", None)
                else:
                    os.environ["CODEX_HOME"] = previous_codex_home

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
            (source / "sample.txt").write_text("AIALRA owner@private.test\n", encoding="utf-8")
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
            self.assertEqual("AIALRA owner@private.test\n", (source / "sample.txt").read_text(encoding="utf-8"))
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


if __name__ == "__main__":
    unittest.main()
