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
                "http://10.24.1.8:8080/private",
                "AA:BB:CC:DD:EE:FF",
                r"C:\Users\PrivateUser\Documents\notes.txt",
                "/home/private-user/notes.txt",
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


class ArtifactTests(unittest.TestCase):
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
        self.assertTrue(any(item.reason.startswith("binary-review-required") for item in state.coverage))
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
        self.assertTrue(any(item.reason.startswith("binary-review-required") for item in embedded_state.coverage))


class RepositoryTests(unittest.TestCase):
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
