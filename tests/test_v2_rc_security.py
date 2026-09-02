from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from github_safe_publish.compiler import publish_compiler, resume_compiler, sanitize_compiler, verify_compiler  # noqa: E402
from github_safe_publish.credential_scanner import CredentialScannerUnavailable, scan_gitleaks  # noqa: E402
from github_safe_publish.detectors import inspect_tree, inspect_tree_detailed  # noqa: E402
from github_safe_publish.inventory import source_snapshot  # noqa: E402
from github_safe_publish.model import PublicationAuthorization, RemediationAction, SafetyCertification  # noqa: E402
from github_safe_publish.policy import default_policy, policy_sha256, validate_policy  # noqa: E402
from github_safe_publish.publication import authorization_sha256, publish_local  # noqa: E402
from github_safe_publish.sandbox import verify_pinned_image  # noqa: E402
from github_safe_publish.signing import DPAPI_PREFIX, private_key_fingerprint, sign_certification  # noqa: E402
from github_safe_publish.state import save_state  # noqa: E402
from github_safe_publish.transformers import transform_candidate  # noqa: E402
from github_safe_publish.validation import validate_candidate  # noqa: E402


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    ).stdout.strip()


def initialize(repository: Path) -> None:
    git(repository, "init", "-b", "main")
    git(repository, "config", "user.name", "Example")
    git(repository, "config", "user.email", "example@example.invalid")


class ReleaseCandidateSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._scanner = mock.patch(
            "github_safe_publish.verification.scan_gitleaks",
            return_value=([], {"path": "@credential-scanner", "status": "checked", "parser": "test", "sha256": "a" * 64}),
        )
        self._scanner.start()
        self.addCleanup(self._scanner.stop)

    def test_gitleaks_binding_canary_and_redacted_report_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            (candidate / "config.txt").write_text("safe\n", encoding="utf-8")
            executable = root / "gitleaks.exe"
            executable.write_bytes(b"synthetic executable")
            policy = default_policy()
            policy["security_runtime"].update({
                "credential_scanner": {
                    "path": str(executable),
                    "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                    "version": "8.30.1",
                },
                "private_temp_root": str(root / "private-temp"),
            })

            def fake_run(_executable, source, report, _timeout):
                record = {"File": "canary.txt", "RuleID": "canary"} if source != candidate else {"File": "config.txt", "RuleID": "synthetic"}
                report.write_text(json.dumps([record]), encoding="utf-8")
                return subprocess.CompletedProcess([], 1, b"", b"")

            with mock.patch("github_safe_publish.credential_scanner._run", side_effect=fake_run):
                findings, coverage = scan_gitleaks(candidate, policy)
            self.assertEqual(["gitleaks.synthetic"], [item.rule_id for item in findings])
            self.assertEqual("checked", coverage["status"])
            policy["security_runtime"]["credential_scanner"]["sha256"] = "0" * 64
            with self.assertRaises(CredentialScannerUnavailable):
                scan_gitleaks(candidate, policy)

    def test_gitleaks_retention_is_exact_and_paths_are_candidate_relative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            retained = candidate / "nested" / "config.txt"
            retained.parent.mkdir(parents=True)
            retained.write_text("public example\n", encoding="utf-8")
            executable = root / "gitleaks.exe"
            executable.write_bytes(b"synthetic executable")
            policy = default_policy()
            policy["security_runtime"].update({
                "credential_scanner": {
                    "path": str(executable),
                    "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                    "version": "8.30.1",
                },
                "private_temp_root": str(root / "private-temp"),
            })
            binding_document = json.loads(json.dumps(policy))
            binding_document["retention_rules"] = []
            policy["retention_rules"] = [{
                "action": "retain-public",
                "object": "nested/config.txt",
                "sha256": hashlib.sha256(retained.read_bytes()).hexdigest(),
                "scanner_ids": ["gitleaks-8.30.1:synthetic"],
                "tool_version": "2.0.1",
                "policy_sha256": policy_sha256(binding_document),
                "issued_by": "information-owner",
                "issued_at": "2026-08-31T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "review_trigger": "content-policy-scanner-or-expiry-change",
            }]
            policy = validate_policy(policy)

            def fake_run(_executable, source, report, _timeout):
                record = {"File": "canary.txt", "RuleID": "canary"} if source != candidate else {
                    "File": str(retained.resolve()),
                    "RuleID": "synthetic",
                }
                report.write_text(json.dumps([record]), encoding="utf-8")
                return subprocess.CompletedProcess([], 1, b"", b"")

            with mock.patch("github_safe_publish.credential_scanner._run", side_effect=fake_run):
                self.assertEqual([], scan_gitleaks(candidate, policy)[0])
                retained.write_text("changed public example\n", encoding="utf-8")
                findings, _ = scan_gitleaks(candidate, policy)
            self.assertEqual(["nested/config.txt"], [item.object_path for item in findings])

    def test_functional_commands_never_fall_back_to_the_host(self) -> None:
        policy = default_policy()
        policy["functional_contract"]["commands"] = ["python -c 'print(1)'"]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "container sandbox"):
                validate_candidate(Path(temporary), policy)

    def test_quoted_config_credentials_are_safely_externalized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            config.write_text('{"token":"synthetic-runtime-secret"}\n', encoding="utf-8")
            findings, _ = inspect_tree(root, default_policy())
            self.assertEqual(["credential.assignment"], [item.rule_id for item in findings])
            action = RemediationAction("config", findings[0].finding_id, "externalize", "config.json")
            transform_candidate(root, [action], default_policy())
            self.assertEqual("<REQUIRED_AT_RUNTIME>", json.loads(config.read_text(encoding="utf-8"))["token"])
            self.assertEqual([], inspect_tree(root, default_policy())[0])

    def test_rename_repairs_references_and_public_summary_hides_source_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private_path = "private_module.py"
            public_path = "src/public_module.py"
            (root / private_path).write_text("VALUE = 1\n", encoding="utf-8")
            (root / "app.py").write_text("from private_module import VALUE\n", encoding="utf-8")
            (root / "README.md").write_text("[module](private_module.py)\n", encoding="utf-8")
            policy = default_policy()
            policy["object_rules"] = [{"action": "rename", "path": private_path, "target": public_path}]
            transformations, _ = transform_candidate(root, [], policy)
            self.assertFalse((root / private_path).exists())
            self.assertTrue((root / public_path).is_file())
            self.assertIn("from src.public_module import VALUE", (root / "app.py").read_text(encoding="utf-8"))
            self.assertIn("[module](src/public_module.py)", (root / "README.md").read_text(encoding="utf-8"))
            self.assertIn("repair-reference", {item["action"] for item in transformations})
            public_summary = (root / "PUBLICATION_CHANGES.json").read_text(encoding="utf-8")
            self.assertNotIn(private_path, public_summary)
            self.assertNotIn(public_path, public_summary)

    def test_removed_object_uses_generic_stub_and_public_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private_path = "customer-export.bin"
            (root / private_path).write_bytes(b"opaque")
            action = RemediationAction("remove", "finding", "remove-and-stub", private_path)
            transformations, removed = transform_candidate(root, [action], default_policy())
            self.assertEqual([private_path], removed)
            replacement = next(item["replacement"] for item in transformations if item["action"] == "remove-and-stub")
            self.assertEqual("docs/safe-publish/removed-object-001.md", replacement)
            public_summary = (root / "PUBLICATION_CHANGES.json").read_text(encoding="utf-8")
            self.assertNotIn(private_path, public_summary)
            self.assertNotIn("customer", public_summary)

    def test_authorization_is_cryptographically_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            initialize(candidate)
            (candidate / "README.md").write_text("safe\n", encoding="utf-8")
            git(candidate, "add", ".")
            git(candidate, "commit", "-m", "candidate")
            commit = git(candidate, "rev-parse", "HEAD")
            tree = git(candidate, "rev-parse", "HEAD^{tree}")
            remote = root / "remote.git"
            key = root / "key.private"
            fingerprint = private_key_fingerprint(key)
            authorization = PublicationAuthorization(str(remote), "main", None, ("commit",), "minor", False, False, "2099-01-01T00:00:00Z", "transaction-1", fingerprint)
            certification = SafetyCertification(1, commit, tree, "a" * 64, "2.0.1", "b" * 64, str(remote), "main", None, "none", authorization_sha256(authorization))
            sign_certification(certification, key)
            mutations = {
                "target_repository": str(root / "other.git"),
                "target_branch": "other",
                "allowed_writes": ("release",),
                "maximum_degradation": "none",
                "expires_at": "2098-01-01T00:00:00Z",
                "idempotency_key": "tampered-transaction",
                "trusted_public_key_fingerprint": "f" * 64,
            }
            for field, value in mutations.items():
                with self.subTest(field=field):
                    tampered = replace(authorization, **{field: value})
                    expected = "invalid or untrusted" if field == "trusted_public_key_fingerprint" else "not bound"
                    with self.assertRaisesRegex(ValueError, expected):
                        publish_local(candidate, certification, tampered)

    def test_workflow_write_requires_scope_and_retries_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            (candidate / ".github" / "workflows").mkdir(parents=True)
            initialize(candidate)
            (candidate / "README.md").write_text("safe\n", encoding="utf-8")
            (candidate / ".github" / "workflows" / "test.yml").write_text("name: test\n", encoding="utf-8")
            git(candidate, "add", ".")
            git(candidate, "commit", "-m", "candidate")
            commit = git(candidate, "rev-parse", "HEAD")
            tree = git(candidate, "rev-parse", "HEAD^{tree}")
            remote = root / "remote.git"
            key = root / "key.private"
            fingerprint = private_key_fingerprint(key)
            denied = PublicationAuthorization(str(remote), "main", None, ("commit",), "minor", False, False, "2099-01-01T00:00:00Z", "workflow-1", fingerprint)
            denied_cert = SafetyCertification(1, commit, tree, "a" * 64, "2.0.1", "b" * 64, str(remote), "main", None, "none", authorization_sha256(denied))
            sign_certification(denied_cert, key)
            with self.assertRaisesRegex(ValueError, "workflow write"):
                publish_local(candidate, denied_cert, denied)
            allowed = replace(denied, workflow_in_scope=True)
            allowed_cert = replace(denied_cert, authorization_sha256=authorization_sha256(allowed), signature=None, public_key=None, public_key_fingerprint=None)
            sign_certification(allowed_cert, key)
            first = publish_local(candidate, allowed_cert, allowed)
            second = publish_local(candidate, allowed_cert, allowed)
            self.assertEqual("published", first.status)
            self.assertEqual(first.remote_commit, second.remote_commit)
            self.assertEqual(first.remote_tree, second.remote_tree)

    def test_publisher_needs_no_source_or_private_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            initialize(source)
            (source / "README.md").write_text("safe\n", encoding="utf-8")
            git(source, "add", ".")
            git(source, "commit", "-m", "source")
            key = root / "key.private"
            fingerprint = private_key_fingerprint(key)
            policy = default_policy()
            policy["publication"].update({"trusted_public_key_fingerprint": fingerprint, "idempotency_key": "publisher-no-source"})
            policy["security_runtime"]["certification_key_path"] = str(key)
            policy["remote_target"]["repository"] = str(root / "remote.git")
            policy_path = root / "policy.private.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            output = root / "output"
            self.assertEqual("validating", sanitize_compiler(source, policy_path, output).status)
            self.assertEqual("certified", verify_compiler(source, policy_path, output).status)
            policy_path.unlink()
            self.assertEqual("published", publish_compiler(root / "missing-source", root / "missing-policy", output).status)

    def test_candidate_commit_is_rechecked_after_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            initialize(source)
            (source / "README.md").write_text("safe\n", encoding="utf-8")
            git(source, "add", ".")
            git(source, "commit", "-m", "source")
            key = root / "key.private"
            fingerprint = private_key_fingerprint(key)
            policy = default_policy()
            policy["publication"].update({"trusted_public_key_fingerprint": fingerprint, "idempotency_key": "candidate-recheck"})
            policy["security_runtime"]["certification_key_path"] = str(key)
            policy["remote_target"]["repository"] = str(root / "remote.git")
            policy_path = root / "policy.private.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            output = root / "output"
            workflow = sanitize_compiler(source, policy_path, output)
            candidate = Path(workflow.candidate_manifest.candidate_path)
            (candidate / "README.md").write_text("changed\n", encoding="utf-8")
            git(candidate, "add", ".")
            git(
                candidate,
                "-c",
                "user.name=Example Attacker",
                "-c",
                "user.email=attacker@example.invalid",
                "commit",
                "-m",
                "unexpected",
            )
            verified = verify_compiler(source, policy_path, output)
            self.assertEqual("operator_attention", verified.status)
            self.assertIn("bound manifest", verified.pause_reason)

    def test_retryable_candidate_build_resumes_without_deleting_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            initialize(source)
            (source / "README.md").write_text("safe\n", encoding="utf-8")
            git(source, "add", ".")
            git(source, "commit", "-m", "source")
            key = root / "key.private"
            policy = default_policy()
            policy["publication"]["trusted_public_key_fingerprint"] = private_key_fingerprint(key)
            policy["security_runtime"]["certification_key_path"] = str(key)
            policy["remote_target"]["repository"] = str(root / "remote.git")
            policy_path = root / "policy.private.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            output = root / "output"
            with mock.patch("github_safe_publish.compiler.build_candidate", side_effect=subprocess.CalledProcessError(1, ["git", "clone"])):
                failed = sanitize_compiler(source, policy_path, output)
            self.assertEqual("retryable_failure", failed.status)
            resumed = resume_compiler(source, policy_path, output, publish=False)
            self.assertEqual("certified", resumed.status)
            self.assertTrue((output / "retries" / "retry-0001" / "workflow-state.private.json").is_file())

    def test_legal_hold_cannot_be_resumed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            output = root / "output"
            output.mkdir()
            state_path = output / "workflow-state.private.json"
            policy_path = root / "policy.private.json"
            policy_path.write_text(json.dumps(default_policy()), encoding="utf-8")
            from github_safe_publish.model import WorkflowState

            save_state(state_path, WorkflowState("hold-1", "legal_hold"))
            self.assertEqual("legal_hold", resume_compiler(source, policy_path, output).status)

    def test_source_snapshot_streams_without_path_read_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            initialize(repository)
            (repository / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))
            git(repository, "add", ".")
            git(repository, "commit", "-m", "streamed")
            with mock.patch("pathlib.Path.read_bytes", side_effect=AssertionError("unbounded read")):
                snapshot = source_snapshot(repository)
            self.assertEqual(1, snapshot.file_count)

    def test_complete_source_receipt_is_exact_and_expiring(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            initialize(source)
            git(source, "config", "core.autocrlf", "true")
            (source / "opaque.dat").write_bytes(b"\xff\xfe\x00\x01")
            (source / "config.py").write_text('token = "notA-placeholder-runtime-value9"\n', encoding="utf-8")
            (source / "ambiguous.py").write_bytes(b'token = "worker-token"\r\n')
            git(source, "add", ".")
            git(source, "commit", "-m", "opaque")
            snapshot = source_snapshot(source)
            report = {
                "source_commit": snapshot.commit,
                "scanner_sha256": "a" * 64,
                "policy_fingerprint": "b" * 64,
                "report_fingerprint": "c" * 64,
                "summary": {"critical_finding_count": 0, "critical_coverage_gap_count": 0},
                "worktree_progress": {"status": "complete", "processed_file_count": snapshot.file_count},
            }
            report_path = root / "audit.public.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            policy = default_policy()
            policy["validation"]["source_audit_receipt"] = {
                "report_path": str(report_path),
                "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                "source_commit": snapshot.commit,
                "source_tree": snapshot.tree,
                "scanner_sha256": report["scanner_sha256"],
                "policy_fingerprint": report["policy_fingerprint"],
                "report_fingerprint": report["report_fingerprint"],
                "worktree_file_count": snapshot.file_count,
                "issued_at": "2026-08-31T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "approved_by": "ExampleOwner",
                "review_trigger": "content-policy-scanner-or-expiry-change",
            }
            from github_safe_publish.receipts import validate_source_audit_receipt

            receipt = validate_source_audit_receipt(policy, source, snapshot)
            findings, _, coverage = inspect_tree_detailed(source, policy, inherited_source=source, source_receipt=receipt)
            self.assertEqual(["credential.assignment"], [item.rule_id for item in findings])
            self.assertIn("bound-source-audit-receipt", {item["parser"] for item in coverage})
            candidate = root / "candidate"
            candidate.mkdir()
            (candidate / "ambiguous.py").write_bytes(b'token = "worker-token"\n')
            findings, observations, _ = inspect_tree_detailed(
                candidate,
                policy,
                inherited_source=source,
                source_receipt=receipt,
            )
            self.assertEqual([], findings)
            self.assertEqual(["public.audited-ambiguous-assignment"], [item.rule_id for item in observations])
            policy["validation"]["source_audit_receipt"]["source_tree"] = "d" * 40
            with self.assertRaisesRegex(ValueError, "another source snapshot"):
                validate_source_audit_receipt(policy, source, snapshot)

    def test_image_metadata_is_removed_before_certification(self) -> None:
        from PIL import Image, PngImagePlugin
        from github_safe_publish.model import RemediationAction

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = PngImagePlugin.PngInfo()
            metadata.add_text("Author", "Synthetic Author")
            Image.new("RGB", (24, 24), "white").save(root / "image.png", pnginfo=metadata)
            findings, _ = inspect_tree(root, default_policy())
            self.assertEqual(["strip-metadata"], [item.remediation_hint for item in findings])
            actions = [RemediationAction("a", findings[0].finding_id, "strip-metadata", "image.png")]
            transform_candidate(root, actions, default_policy())
            findings, _ = inspect_tree(root, default_policy())
            self.assertEqual([], findings)

    def test_archive_path_traversal_becomes_removal_not_repack(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with zipfile.ZipFile(root / "unsafe.zip", "w") as archive:
                archive.writestr("../escape.txt", "synthetic")
            findings, _ = inspect_tree(root, default_policy())
            self.assertEqual(["remove-and-stub"], [item.remediation_hint for item in findings])

    def test_private_regex_and_local_image_id_are_bounded(self) -> None:
        policy = default_policy()
        policy["sensitive_entities"] = [{"id": "unsafe", "kind": "regex", "value": "(a+)+$", "category": "private-identity"}]
        with self.assertRaisesRegex(ValueError, "not bounded"):
            validate_policy(policy)
        image_id = "sha256:" + "a" * 64
        policy = default_policy()
        policy["security_runtime"]["image"] = image_id
        with mock.patch("github_safe_publish.sandbox.subprocess.run", return_value=subprocess.CompletedProcess([], 0, image_id + "\n", "")):
            self.assertEqual(image_id, verify_pinned_image(policy))

    def test_private_key_uses_platform_protection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "key.private"
            private_key_fingerprint(path)
            encoded = path.read_text(encoding="ascii")
            if os.name == "nt":
                self.assertTrue(encoded.startswith(DPAPI_PREFIX))
            else:
                self.assertEqual(0, stat.S_IMODE(path.stat().st_mode) & 0o077)

    def test_owner_decision_policy_revision_resumes_without_deleting_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            initialize(source)
            (source / "opaque.bin").write_bytes(b"opaque")
            git(source, "add", ".")
            git(source, "commit", "-m", "opaque")
            key = root / "key.private"
            fingerprint = private_key_fingerprint(key)
            policy = default_policy()
            policy["publication"]["trusted_public_key_fingerprint"] = fingerprint
            policy["security_runtime"]["certification_key_path"] = str(key)
            policy["remote_target"]["repository"] = str(root / "remote.git")
            policy_path = root / "policy.private.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            output = root / "output"
            self.assertEqual("needs_input", sanitize_compiler(source, policy_path, output).status)
            policy["degradation_policy"]["optional_paths"] = ["opaque.bin"]
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            resumed = resume_compiler(source, policy_path, output, publish=False)
            self.assertEqual("certified", resumed.status)
            self.assertTrue((output / "revisions" / "revision-0001" / "workflow-state.private.json").is_file())


if __name__ == "__main__":
    unittest.main()
