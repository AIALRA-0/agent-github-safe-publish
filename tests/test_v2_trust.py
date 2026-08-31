from __future__ import annotations

from pathlib import Path
import os
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
            certification = SafetyCertification(1, "a" * 40, "b" * 40, "c" * 64, "2.0.0-beta.1", "d" * 64, "owner/repository", "main", None, "none")
            sign_certification(certification, Path(temporary) / "key.private")
            self.assertTrue(verify_certification(certification, certification.public_key_fingerprint))
            self.assertFalse(verify_certification(certification, None))
            certification.candidate_tree = "e" * 40
            self.assertFalse(verify_certification(certification, certification.public_key_fingerprint))

    def test_container_command_uses_no_network_read_only_root_and_no_privileges(self) -> None:
        policy = default_policy()
        image = "python@sha256:" + "a" * 64
        policy["security_runtime"].update({"container_required": True, "image": image})
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("github_safe_publish.sandbox.subprocess.run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, image + "\n", ""),
                    subprocess.CompletedProcess([], 0, "29.0.1\n", ""),
                    subprocess.CompletedProcess([], 0, "", ""),
                    subprocess.CompletedProcess([], 0, "29.0.1\n", ""),
                ]
                result = run_in_container(Path(temporary), "python -m unittest", policy)
            arguments = run.call_args_list[2].args[0]
            self.assertEqual(0, result["exit_code"])
            self.assertIn("none", arguments)
            self.assertIn("--read-only", arguments)
            self.assertIn("never", arguments)
            self.assertIn("ALL", arguments)
            self.assertIn("no-new-privileges", arguments)
            self.assertNotIn("/var/run/docker.sock", " ".join(arguments))

    def test_container_image_must_be_digest_pinned(self) -> None:
        policy = default_policy()
        policy["security_runtime"].update({"container_required": True, "image": "alpine:latest"})
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "complete sha256 digest"):
                run_in_container(Path(temporary), "true", policy)

    @unittest.skipUnless(os.environ.get("SAFE_PUBLISH_LIVE_CONTAINER") == "1", "live isolation canary")
    def test_live_wsl_container_blocks_network_credentials_and_writes(self) -> None:
        policy = default_policy()
        policy["validation"]["timeout_seconds"] = 60
        policy["security_runtime"].update(
            {
                "container_required": True,
                "backend": "wsl-docker",
                "wsl_distribution": "Ubuntu",
                "image": "alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce",
            }
        )
        command = " && ".join(
            (
                "test ! -e /var/run/docker.sock",
                "test -z \"${GITHUB_TOKEN:-}\"",
                "! touch /workspace/forbidden-write",
                "! touch /rootfs-write",
                "! wget -T 2 -q -O- https://example.com >/dev/null 2>&1",
                "grep -q '^NoNewPrivs:[[:space:]]*1' /proc/1/status",
                "grep -q '^CapEff:[[:space:]]*0000000000000000' /proc/1/status",
            )
        )
        previous = os.environ.get("GITHUB_TOKEN")
        os.environ["GITHUB_TOKEN"] = "synthetic-host-credential"
        try:
            with tempfile.TemporaryDirectory(dir="C:\\Codex-Cold-Storage") as temporary:
                result = run_in_container(Path(temporary), command, policy)
        finally:
            if previous is None:
                os.environ.pop("GITHUB_TOKEN", None)
            else:
                os.environ["GITHUB_TOKEN"] = previous
        self.assertEqual(0, result["exit_code"])
        self.assertEqual("wsl-docker", result["sandbox"])
        self.assertEqual("29.1.3", result["engine_version"])


if __name__ == "__main__":
    unittest.main()
