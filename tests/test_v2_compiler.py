from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from github_safe_publish.compiler import publish_compiler, resume_compiler, run_compiler, sanitize_compiler, verify_compiler  # noqa: E402
from github_safe_publish.model import SafetyCertification  # noqa: E402
from github_safe_publish.signing import sign_certification  # noqa: E402


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


class SafePublicationCompilerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._scanner = mock.patch(
            "github_safe_publish.verification.scan_gitleaks",
            return_value=([], {"path": "@credential-scanner", "status": "checked", "parser": "test", "sha256": "a" * 64}),
        )
        self._scanner.start()
        self.addCleanup(self._scanner.stop)

    def test_existing_public_update_uses_only_the_public_base_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public_work = root / "public-work"
            public_work.mkdir()
            git(public_work, "init", "-b", "main")
            git(public_work, "config", "user.name", "Example")
            git(public_work, "config", "user.email", "example@example.invalid")
            (public_work / "README.md").write_text("public base\n", encoding="utf-8")
            git(public_work, "add", ".")
            git(public_work, "commit", "-m", "public base")
            public_base = git(public_work, "rev-parse", "HEAD")
            remote = root / "public.git"
            subprocess.run(["git", "clone", "--bare", str(public_work), str(remote)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            source = root / "private-source"
            source.mkdir()
            git(source, "init", "-b", "main")
            git(source, "config", "user.name", "Private")
            git(source, "config", "user.email", "private@example.invalid")
            (source / "deleted.txt").write_text("private-history-marker\n", encoding="utf-8")
            git(source, "add", ".")
            git(source, "commit", "-m", "private history")
            private_commit = git(source, "rev-parse", "HEAD")
            (source / "deleted.txt").unlink()
            (source / "README.md").write_text("safe overlay\n", encoding="utf-8")
            git(source, "add", "-A")
            git(source, "commit", "-m", "safe source")

            key_path = root / "key.private"
            probe = SafetyCertification(1, "a" * 40, "b" * 40, "c" * 64, "probe", "d" * 64, str(remote), "main", public_base, "none")
            sign_certification(probe, key_path)
            policy = {
                "schema_version": 4,
                "publication": {
                    "mode": "update-existing-public",
                    "public_base": str(remote),
                    "allowed_writes": ["commit"],
                    "trusted_public_key_fingerprint": probe.public_key_fingerprint,
                },
                "sensitive_entities": [],
                "synthetic_mappings": [],
                "remediation_defaults": {},
                "object_rules": [],
                "retention_rules": [],
                "history_strategy": {"mode": "public-base-overlay"},
                "functional_contract": {"commands": []},
                "degradation_policy": {"maximum_automatic": "minor", "optional_paths": []},
                "validation": {"timeout_seconds": 30},
                "security_runtime": {"network": "disabled", "container_required": False, "certification_key_path": str(key_path)},
                "remote_target": {"repository": str(remote), "branch": "main", "expected_base": public_base},
            }
            policy_path = root / "policy.private.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            output = root / "run"
            state = run_compiler(source, policy_path, output)
            self.assertEqual("published", state.status)
            candidate = output / "candidate"
            self.assertEqual(public_base, git(candidate, "rev-parse", "HEAD^"))
            unreachable = subprocess.run(["git", "-C", str(candidate), "cat-file", "-e", private_commit], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(0, unreachable.returncode)
            self.assertEqual("safe overlay", (candidate / "README.md").read_text(encoding="utf-8").strip())

    def test_same_source_and_policy_produce_the_same_candidate_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            git(source, "init", "-b", "main")
            git(source, "config", "user.name", "Example")
            git(source, "config", "user.email", "example@example.invalid")
            (source / "config.py").write_text('password = "synthetic-runtime-value"\n', encoding="utf-8")
            long_path = source / ("segment-" + "a" * 80) / ("segment-" + "b" * 80) / ("document-" + "c" * 80 + ".txt")
            long_path.parent.mkdir(parents=True)
            long_path.write_text("safe long-path object\n", encoding="utf-8")
            git(source, "-c", "core.longpaths=true", "add", ".")
            git(source, "commit", "-m", "source")
            key_path = root / "key.private"
            probe = SafetyCertification(1, "a" * 40, "b" * 40, "c" * 64, "probe", "d" * 64, str(root / "remote.git"), "main", None, "none")
            sign_certification(probe, key_path)
            policy = {
                "schema_version": 4,
                "publication": {"mode": "new-publication", "trusted_public_key_fingerprint": probe.public_key_fingerprint},
                "sensitive_entities": [],
                "synthetic_mappings": [],
                "remediation_defaults": {},
                "object_rules": [],
                "retention_rules": [],
                "history_strategy": {"mode": "new-root"},
                "functional_contract": {"commands": []},
                "degradation_policy": {"maximum_automatic": "minor", "optional_paths": []},
                "validation": {"timeout_seconds": 30},
                "security_runtime": {"network": "disabled", "container_required": False, "certification_key_path": str(key_path)},
                "remote_target": {"repository": str(root / "remote.git"), "branch": "main", "expected_base": None},
            }
            policy_path = root / "policy.private.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            first_output = root / "run-1"
            self.assertEqual("validating", sanitize_compiler(source, policy_path, first_output).status)
            first = verify_compiler(source, policy_path, first_output)
            with mock.patch.dict(
                "os.environ",
                {"GIT_AUTHOR_DATE": "2040-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2040-01-01T00:00:00Z"},
            ):
                second_output = root / "run-2"
                self.assertEqual("validating", sanitize_compiler(source, policy_path, second_output).status)
                second = verify_compiler(source, policy_path, second_output)
            self.assertEqual("certified", first.status, first.pause_reason)
            self.assertEqual("certified", second.status, second.pause_reason)
            self.assertEqual(first.certification.candidate_commit, second.certification.candidate_commit)
            self.assertEqual(first.certification.candidate_tree, second.certification.candidate_tree)

    def test_new_publication_sanitizes_validates_certifies_and_publishes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "private-source"
            source.mkdir()
            git(source, "init", "-b", "main")
            git(source, "config", "user.name", "Synthetic Owner")
            git(source, "config", "user.email", "owner@example.invalid")
            old_marker = "old-private-" + "history-value"
            (source / "deleted.txt").write_text(old_marker + "\n", encoding="utf-8")
            git(source, "add", ".")
            git(source, "commit", "-m", "private history")
            (source / "deleted.txt").unlink()
            current_marker = "runtime-" + "private-token-value"
            private_name = "Synthetic Private Person"
            private_ip = ".".join(("10", "23", "45", "67"))
            (source / "app.py").write_text(
                f'token = "{current_marker}"\nOWNER = "{private_name}"\nHOST = "{private_ip}"\nprint("ready")\n',
                encoding="utf-8",
            )
            (source / ".env").write_text("SERVICE_TOKEN=" + current_marker + "\n", encoding="utf-8")
            (source / "test_app.py").write_text(
                "import unittest\nimport app\n\nclass PublicSmoke(unittest.TestCase):\n    def test_ready(self):\n        self.assertEqual('ready', 'ready')\n",
                encoding="utf-8",
            )
            git(source, "add", ".")
            git(source, "commit", "-m", "private current tree")
            before = {
                path.relative_to(source).as_posix(): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                for path in source.rglob("*") if path.is_file() and ".git" not in path.parts
            }
            remote = root / "public.git"
            key_path = root / "certification-ed25519.private.key"
            probe = SafetyCertification(1, "a" * 40, "b" * 40, "c" * 64, "probe", "d" * 64, str(remote), "main", None, "none")
            sign_certification(probe, key_path)
            policy = {
                "schema_version": 4,
                "publication": {
                    "mode": "new-publication",
                    "allowed_writes": ["commit"],
                    "idempotency_key": "north-star-transaction",
                    "trusted_public_key_fingerprint": probe.public_key_fingerprint,
                },
                "sensitive_entities": [
                    {"id": "private.owner", "kind": "literal", "value": private_name, "category": "private-identity"}
                ],
                "synthetic_mappings": [{"entity_id": "private.owner", "replacement": "Example Person"}],
                "remediation_defaults": {
                    "credential": "externalize",
                    "private-identity": "replace",
                    "private-infrastructure": "parameterize",
                    "unsupported-artifact": "remove-and-stub",
                },
                "object_rules": [],
                "retention_rules": [],
                "history_strategy": {"mode": "new-root"},
                "functional_contract": {"commands": [f'"{sys.executable}" -m unittest test_app.py']},
                "degradation_policy": {"maximum_automatic": "minor", "optional_paths": [".env"]},
                "validation": {"timeout_seconds": 30},
                "security_runtime": {"network": "disabled", "container_required": True, "certification_key_path": str(key_path)},
                "remote_target": {"repository": str(remote), "branch": "main", "expected_base": None},
            }
            policy_path = root / "policy.private.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            output = root / "run"
            with mock.patch(
                "github_safe_publish.validation.run_in_container",
                return_value={"command_id": "north-star", "exit_code": 0, "sandbox": "test-double"},
            ):
                state = run_compiler(source, policy_path, output)
            if state.status != "published":
                debug = subprocess.run(
                    [sys.executable, "-m", "unittest", "test_app.py"],
                    cwd=output / "candidate",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                self.fail(f"{state.pause_reason}; validation={debug.stdout}")
            candidate = output / "candidate"
            combined = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in candidate.rglob("*") if path.is_file() and ".git" not in path.parts)
            self.assertNotIn(current_marker, combined)
            self.assertNotIn(private_name, combined)
            self.assertNotIn(private_ip, combined)
            self.assertFalse((candidate / ".env").exists())
            self.assertTrue((candidate / ".env.example").exists())
            self.assertNotIn(old_marker, subprocess.run(["git", "--git-dir", str(remote), "log", "-p", "--all"], check=True, stdout=subprocess.PIPE, text=True).stdout)
            after = {
                path.relative_to(source).as_posix(): (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns)
                for path in source.rglob("*") if path.is_file() and ".git" not in path.parts
            }
            self.assertEqual(before, after)
            self.assertEqual(state.certification.candidate_tree, state.attestation.remote_tree)
            resumed = resume_compiler(source, policy_path, output)
            self.assertEqual("published", resumed.status)
            statement = json.loads((output / "publication-attestation.private.json").read_text(encoding="utf-8"))
            self.assertEqual("https://in-toto.io/Statement/v1", statement["_type"])
            self.assertEqual(state.certification.candidate_tree, statement["subject"][0]["digest"]["gitTree"])
            second = subprocess.run(["git", "-C", str(candidate), "status", "--porcelain"], check=True, stdout=subprocess.PIPE, text=True).stdout
            self.assertEqual("", second)

    def test_phase_commands_share_one_bound_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            git(source, "init", "-b", "main")
            git(source, "config", "user.name", "Example")
            git(source, "config", "user.email", "example@example.invalid")
            (source / "README.md").write_text("safe\n", encoding="utf-8")
            git(source, "add", ".")
            git(source, "commit", "-m", "safe source")
            remote = root / "remote.git"
            key_path = root / "key.private"
            probe = SafetyCertification(1, "a" * 40, "b" * 40, "c" * 64, "probe", "d" * 64, str(remote), "main", None, "none")
            sign_certification(probe, key_path)
            policy = {
                "schema_version": 4,
                "publication": {"mode": "new-publication", "trusted_public_key_fingerprint": probe.public_key_fingerprint},
                "sensitive_entities": [],
                "synthetic_mappings": [],
                "remediation_defaults": {},
                "object_rules": [],
                "retention_rules": [],
                "history_strategy": {"mode": "new-root"},
                "functional_contract": {"commands": []},
                "degradation_policy": {"maximum_automatic": "minor", "optional_paths": []},
                "validation": {"timeout_seconds": 30},
                "security_runtime": {"network": "disabled", "container_required": False, "certification_key_path": str(key_path)},
                "remote_target": {"repository": str(remote), "branch": "main", "expected_base": None},
            }
            policy_path = root / "policy.private.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            output = root / "run"
            sanitized = sanitize_compiler(source, policy_path, output)
            self.assertEqual("validating", sanitized.status)
            self.assertEqual(git(source, "rev-parse", "HEAD^{tree}"), sanitized.candidate_manifest.candidate_tree)
            self.assertEqual("certified", verify_compiler(source, policy_path, output).status)
            self.assertEqual("published", publish_compiler(source, policy_path, output).status)


if __name__ == "__main__":
    unittest.main()
