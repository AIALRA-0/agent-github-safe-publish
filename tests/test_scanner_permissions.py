"""Policy construction tests, not a claim of runtime isolation certification."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from eval_runtime_permissions import linux_permission_args  # noqa: E402
from run_behavior_eval import _codex_command  # noqa: E402


class ScannerPermissionTests(unittest.TestCase):
    def test_unavailable_scanner_denies_actual_path_and_retains_other_boundaries(self):
        args = linux_permission_args(Path("fixture"), scanner_available=False)
        profile = next(item for item in args if item.startswith("permissions="))
        self.assertIn('"/runtime/gitleaks"="deny"', profile)
        self.assertIn('\":root\"=\"deny\"', profile)
        self.assertIn("network={enabled=false}", profile)

    def test_default_availability_does_not_add_denial(self):
        self.assertFalse(any('"/runtime/gitleaks"="deny"' in item
                             for item in linux_permission_args(Path("fixture"))))

    def test_linux_command_wires_explicit_capability_without_changing_model(self):
        with patch("run_behavior_eval.sys.platform", "linux"):
            args = _codex_command("codex", Path("fixture"), Path("schema"), Path("out"),
                                  "synthetic-model", "medium", scanner_available=False)
        self.assertIn("synthetic-model", args)
        self.assertTrue(any('"/runtime/gitleaks"="deny"' in item for item in args))

    def test_unsupported_platform_and_non_boolean_cannot_fake_absence(self):
        with patch("run_behavior_eval.sys.platform", "win32"), self.assertRaises(ValueError):
            _codex_command("codex", Path("fixture"), Path("schema"), Path("out"),
                           "synthetic-model", "medium", scanner_available=False)
        for value in (0, 1, "false", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                linux_permission_args(Path("fixture"), scanner_available=value)
