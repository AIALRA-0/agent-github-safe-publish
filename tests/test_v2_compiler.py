from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from github_safe_publish.compiler import run_compiler  # noqa: E402


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
            policy = {
                "schema_version": 4,
                "publication": {
                    "mode": "new-publication",
                    "allowed_writes": ["commit"],
                    "idempotency_key": "north-star-transaction",
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
                "security_runtime": {"network": "disabled", "container_required": False},
                "remote_target": {"repository": str(remote), "branch": "main", "expected_base": None},
            }
            policy_path = root / "policy.private.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            output = root / "run"
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
            second = subprocess.run(["git", "-C", str(candidate), "status", "--porcelain"], check=True, stdout=subprocess.PIPE, text=True).stdout
            self.assertEqual("", second)


if __name__ == "__main__":
    unittest.main()
