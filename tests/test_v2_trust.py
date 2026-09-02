from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from github_safe_publish.model import SafetyCertification  # noqa: E402
from github_safe_publish.policy import default_policy  # noqa: E402
from github_safe_publish.sandbox import run_in_container  # noqa: E402
from github_safe_publish.signing import sign_certification, verify_certification  # noqa: E402


class TrustedPublicationTests(unittest.TestCase):
    def test_ed25519_signature_binds_candidate_and_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            certification = SafetyCertification(1, "a" * 40, "b" * 40, "c" * 64, "2.0.1", "d" * 64, "owner/repository", "main", None, "none")
            sign_certification(certification, Path(temporary) / "key.private")
            self.assertTrue(verify_certification(certification, certification.public_key_fingerprint))
            self.assertFalse(verify_certification(certification, None))
            certification.candidate_tree = "e" * 40
            self.assertFalse(verify_certification(certification, certification.public_key_fingerprint))

    def test_container_command_uses_no_network_read_only_root_and_no_privileges(self) -> None:
        policy = default_policy()
        digest = "a" * 64
        image = "python:3.12-slim@sha256:" + digest
        policy["security_runtime"].update({"container_required": True, "image": image})
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("github_safe_publish.sandbox.subprocess.run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 1, "", "missing tagged reference"),
                    subprocess.CompletedProcess([], 0, "sha256:" + digest + '|["python@sha256:' + digest + '"]\n', ""),
                    subprocess.CompletedProcess([], 0, "29.0.1\n", ""),
                    subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], 0, "29.0.1\n", ""),
                ]
                result = run_in_container(Path(temporary), "python -m unittest", policy)
            arguments = run.call_args_list[3].args[0]
            self.assertEqual(0, result["exit_code"])
            self.assertIn("none", arguments)
            self.assertIn("--read-only", arguments)
            self.assertIn("never", arguments)
            self.assertIn("ALL", arguments)
            self.assertIn("no-new-privileges", arguments)
            self.assertIn("65532:65532", arguments)
            self.assertIn("nofile=1024:1024", arguments)
            self.assertNotIn("/var/run/docker.sock", " ".join(arguments))
            with mock.patch("github_safe_publish.sandbox.verify_pinned_image", return_value=image), mock.patch(
                "github_safe_publish.sandbox.docker_engine_version", return_value="29.0.1"
            ), mock.patch(
                "github_safe_publish.sandbox.subprocess.run",
                return_value=subprocess.CompletedProcess([], 125, b"", b"runtime unavailable"),
            ):
                with self.assertRaisesRegex(RuntimeError, "before the project command started"):
                    run_in_container(Path(temporary), "python -m unittest", policy)

    def test_container_image_must_be_digest_pinned(self) -> None:
        policy = default_policy()
        policy["security_runtime"].update({"container_required": True, "image": "alpine:latest"})
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "complete sha256 digest"):
                run_in_container(Path(temporary), "true", policy)

    def test_container_temporary_space_must_be_bounded(self) -> None:
        policy = default_policy()
        policy["security_runtime"].update(
            {"container_required": True, "image": "sha256:" + "a" * 64, "tmpfs_size": "unbounded"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("github_safe_publish.sandbox.verify_pinned_image", return_value=policy["security_runtime"]["image"]), mock.patch(
                "github_safe_publish.sandbox.docker_engine_version", return_value="29.0.1"
            ):
                with self.assertRaisesRegex(RuntimeError, "temporary-space"):
                    run_in_container(Path(temporary), "true", policy)

if __name__ == "__main__":
    unittest.main()
