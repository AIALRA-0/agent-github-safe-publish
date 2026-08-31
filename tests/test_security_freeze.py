from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))
import safe_publish as subject  # noqa: E402


def run_git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


class LegacySecurityFreezeTests(unittest.TestCase):
    def test_private_root_uses_dedicated_storage_override(self) -> None:
        configured = Path(tempfile.gettempdir()) / "synthetic-cold-private"
        with mock.patch.dict(os.environ, {"SAFE_PUBLISH_PRIVATE_ROOT": str(configured)}, clear=False):
            with mock.patch.object(subject, "PRIVATE_ROOT_OVERRIDE", None):
                self.assertEqual(configured.resolve(), subject.private_root())

    def test_gitleaks_finding_reuses_independently_scanned_object_digest(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        digest = "a" * 64
        state.object_sha256["git:" + "b" * 40 + ":tests/example.py"] = digest
        object_id = "gitleaks-blob:" + "b" * 40 + ":tests/example.py"
        self.assertTrue(subject.bind_gitleaks_object_digest(state, object_id))
        self.assertEqual(digest, state.object_sha256[object_id])

    def test_placeholder_requires_an_exact_supported_shape(self) -> None:
        self.assertFalse(subject.is_placeholder("prod-example-live-123456"))
        self.assertFalse(subject.is_placeholder("real-placeholder-token-123456"))
        self.assertTrue(subject.is_placeholder("${SERVICE_TOKEN}"))
        self.assertTrue(subject.is_placeholder("<REDACTED>"))

    def test_test_path_never_downgrades_an_unmarked_literal_credential(self) -> None:
        state = subject.ScanState("synthetic", subject.empty_policy())
        subject.scan_text(
            state,
            "password=prod-live-secret-123456",
            surface="working-tree",
            object_id="working-tree:tests/fixtures/runtime.env",
            display_path="tests/fixtures/runtime.env",
        )
        matching = [item for item in state.findings if item.rule_id == "credential.assignment"]
        self.assertTrue(matching)
        self.assertTrue(all(subject.finding_risk_level(item) == "critical" for item in matching))

    def test_git_blob_is_scanned_in_every_reachable_path_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            run_git(repository, "init", "-b", "main")
            run_git(repository, "config", "user.name", "Synthetic Tester")
            run_git(repository, "config", "user.email", "synthetic@example.invalid")
            (repository / "examples").mkdir()
            (repository / "production").mkdir()
            content = "password=prod-live-secret-123456\n"
            (repository / "examples" / "config.env").write_text(content, encoding="utf-8")
            (repository / "production" / "config.env").write_text(content, encoding="utf-8")
            run_git(repository, "add", ".")
            run_git(repository, "commit", "-m", "synthetic same blob paths")

            state = subject.ScanState("synthetic", subject.empty_policy())
            subject.scan_git_history(state, repository)
            paths = {
                item.object.split(":", 2)[-1]
                for item in state.findings
                if item.rule_id == "credential.assignment" and item.surface == "git-history"
            }
            self.assertEqual({"examples/config.env", "production/config.env"}, paths)

    def test_legacy_auto_merge_is_removed_from_the_public_parser(self) -> None:
        parser = subject.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "managed-publish",
                    "--source",
                    ".",
                    "--repository",
                    "ExampleOrg/example",
                    "--base-commit",
                    "0" * 40,
                    "--policy",
                    "policy.json",
                    "--private-output-dir",
                    "private",
                    "--intent",
                    "auto-merge",
                ]
            )

    def test_pages_target_rejects_private_and_metadata_addresses(self) -> None:
        private_resolver = lambda _host, _port: ["127.0.0.1", "169.254.169.254"]
        self.assertFalse(subject.public_url_is_safe("https://example.invalid/start", resolver=private_resolver))
        public_resolver = lambda _host, _port: ["93.184.216.34"]
        self.assertTrue(subject.public_url_is_safe("https://example.invalid/start", resolver=public_resolver))
        self.assertFalse(subject.public_url_is_safe("ftp://example.invalid/start", resolver=public_resolver))

    def test_validation_environment_removes_publication_credentials(self) -> None:
        source = {
            "PATH": os.environ.get("PATH", ""),
            "GH_TOKEN": "synthetic-secret",
            "GITHUB_TOKEN": "synthetic-secret",
            "SSH_AUTH_SOCK": "synthetic-socket",
            "AWS_SECRET_ACCESS_KEY": "synthetic-secret",
            "AZURE_CLIENT_SECRET": "synthetic-secret",
            "GOOGLE_APPLICATION_CREDENTIALS": "synthetic-path",
            "SAFE_PUBLIC_VALUE": "kept",
        }
        sanitized = subject.sanitized_validation_environment(source)
        self.assertEqual("kept", sanitized["SAFE_PUBLIC_VALUE"])
        for name in (
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "SSH_AUTH_SOCK",
            "AWS_SECRET_ACCESS_KEY",
            "AZURE_CLIENT_SECRET",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ):
            self.assertNotIn(name, sanitized)

    def test_candidate_fingerprint_changes_after_validation_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            run_git(repository, "init", "-b", "main")
            run_git(repository, "config", "user.name", "Synthetic Tester")
            run_git(repository, "config", "user.email", "synthetic@example.invalid")
            (repository / "file.txt").write_text("before\n", encoding="utf-8")
            run_git(repository, "add", ".")
            run_git(repository, "commit", "-m", "synthetic base")
            base = run_git(repository, "rev-parse", "HEAD")
            before = subject.fingerprint_candidate(repository, base)
            (repository / "file.txt").write_text("after\n", encoding="utf-8")
            after = subject.fingerprint_candidate(repository, base)
            self.assertNotEqual(before, after)

    def test_bounded_reader_rejects_before_reading_the_whole_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "large.bin"
            path.write_bytes(b"A" * 4097)
            with self.assertRaises(subject.BoundedReadExceeded):
                subject.read_file_bounded(path, 4096)

    def test_private_regex_rejects_nested_quantifiers_and_backreferences(self) -> None:
        for expression in (r"(a+)+$", r"(.*)*token", r"(secret)\1"):
            policy = subject.empty_policy()
            policy["identifiers"].append(
                {
                    "id": "private.unsafe-regex",
                    "kind": "regex",
                    "value": expression,
                    "severity": "block",
                    "normalization": ["nfkc"],
                    "scopes": ["all"],
                }
            )
            with self.assertRaises(ValueError):
                subject.validate_policy(policy)

    def test_private_permission_failure_stops_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private"
            path.mkdir()
            with mock.patch.object(subject.os, "chmod", side_effect=OSError("synthetic failure")):
                with self.assertRaises(RuntimeError):
                    subject.restrict_private_path(path, directory=True)

    def test_cached_gitleaks_requires_a_matching_executable_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "gitleaks.exe"
            receipt = root / "gitleaks.verified.json"
            executable.write_bytes(b"synthetic-v1")
            receipt.write_text(
                json.dumps({"version": subject.GITLEAKS_VERSION, "executable_sha256": subject.sha256_bytes(b"synthetic-v1")}),
                encoding="utf-8",
            )
            self.assertTrue(subject.cached_gitleaks_is_verified(executable, receipt))
            executable.write_bytes(b"synthetic-v2")
            self.assertFalse(subject.cached_gitleaks_is_verified(executable, receipt))

    def test_unbound_approved_location_cannot_hide_a_finding(self) -> None:
        policy = subject.empty_policy()
        policy["approved_locations"].append(
            {
                "rule_id": "infrastructure.url",
                "object": "working-tree:README.md",
                "approved_by": "synthetic-owner",
                "reason": "Legacy approval without content or scanner binding",
            }
        )
        state = subject.ScanState("synthetic", subject.validate_policy(policy))
        subject.scan_text(
            state,
            "Homepage https://docs.example.com/guide",
            surface="working-tree",
            object_id="working-tree:README.md",
            display_path="README.md",
        )
        self.assertEqual("review", state.findings[0].status)


if __name__ == "__main__":
    unittest.main()
