from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))
import safe_publish as subject  # noqa: E402


PILOTS = ("AIALRA-SKILL-TEMPLATE", "ReadWeave", "AIALRA-TTS")


class PilotDrillTests(unittest.TestCase):
    def test_each_pilot_allows_reviewed_noncritical_risk_and_denies_credentials(self) -> None:
        for pilot in PILOTS:
            with self.subTest(pilot=pilot):
                url_state = subject.ScanState(pilot, subject.empty_policy())
                object_id = "working-tree:README.md"
                subject.scan_text(
                    url_state,
                    "Documentation https://docs.example.com/guide",
                    surface="working-tree",
                    object_id=object_id,
                    display_path="README.md",
                )
                url_finding = next(item for item in url_state.findings if item.rule_id == "infrastructure.url")
                url_state.policy["risk_acceptances"] = [
                    {
                        "repository": pilot,
                        "rule_id": url_finding.rule_id,
                        "object": object_id,
                        "object_sha256": url_state.object_sha256[object_id],
                        "scanner_sha256": url_state.scanner_sha256,
                        "approved_by": "information-owner",
                        "reason": "Reviewed public documentation address",
                        "expires_at": "2099-01-01T00:00:00Z",
                        "review_trigger": "content-or-scanner-change",
                    }
                ]
                self.assertEqual("review", subject.decision_for(url_state))
                self.assertEqual("allow_with_risk", subject.publication_decision_for(url_state))

                secret_state = subject.ScanState(pilot, subject.empty_policy())
                credential_marker = "SYNTHETIC_PILOT_" + "SECRET_7421"
                subject.scan_text(
                    secret_state,
                    f"password={credential_marker}",
                    surface="working-tree",
                    object_id="working-tree:secret.txt",
                    display_path="secret.txt",
                )
                self.assertEqual("block", subject.decision_for(secret_state))
                self.assertEqual("deny", subject.publication_decision_for(secret_state))

    def test_each_pilot_fails_closed_for_missing_policy_and_pagination(self) -> None:
        for pilot in PILOTS:
            with self.subTest(pilot=pilot):
                with mock.patch.object(subject.os.environ, "get", return_value=""):
                    with self.assertRaises(ValueError):
                        subject.load_policy_from_env("SAFE_PUBLISH_POLICY_B64")
                with mock.patch.object(subject, "gh_json", return_value=(None, "tool_failed")):
                    records, error = subject.api_items("synthetic/page")
                self.assertEqual([], records)
                self.assertEqual("tool_failed", error)

    def test_each_pilot_distinguishes_false_positive_real_leak_and_unreadable_binary(self) -> None:
        for pilot in PILOTS:
            with self.subTest(pilot=pilot):
                state = subject.ScanState(pilot, subject.empty_policy())
                subject.scan_text(state, "owner@example.invalid https://example.invalid/path", surface="working-tree", object_id="working-tree:safe.txt", display_path="safe.txt")
                self.assertEqual([], state.findings)

                marker = "SYNTHETIC_" + "PILOT_LEAK_9274"
                subject.scan_text(state, "password=" + marker, surface="working-tree", object_id="working-tree:leak.txt", display_path="leak.txt")
                self.assertIn("credential.assignment", {item.rule_id for item in state.findings})

                subject.scan_bytes(state, b"invalid-image", surface="working-tree", object_id="working-tree:image.png", display_path="image.png")
                self.assertEqual("incomplete", subject.decision_for(state))
                public = json.dumps(subject.sorted_findings(state), sort_keys=True)
                self.assertNotIn(marker, public)

    def test_each_pilot_rejects_shallow_history(self) -> None:
        for pilot in PILOTS:
            with self.subTest(pilot=pilot), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary) / pilot
                repository.mkdir()
                subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
                subprocess.run(["git", "config", "user.name", "Example User"], cwd=repository, check=True)
                subprocess.run(["git", "config", "user.email", "owner@example.invalid"], cwd=repository, check=True)
                (repository / "safe.txt").write_text("safe\n", encoding="utf-8")
                subprocess.run(["git", "add", "safe.txt"], cwd=repository, check=True)
                subprocess.run(["git", "commit", "-m", "safe"], cwd=repository, check=True, capture_output=True)
                head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository, check=True, capture_output=True, text=True).stdout.strip()
                git_dir = Path(subprocess.run(["git", "rev-parse", "--git-dir"], cwd=repository, check=True, capture_output=True, text=True).stdout.strip())
                (repository / git_dir / "shallow").write_text(head + "\n", encoding="ascii")
                state = subject.ScanState(pilot, subject.empty_policy())
                subject.scan_git_history(state, repository)
                self.assertTrue(any(item.reason == "shallow-history" for item in state.coverage))
                self.assertEqual("incomplete", subject.decision_for(state))


if __name__ == "__main__":
    unittest.main()
