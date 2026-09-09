"""Synthetic capture regressions; never invoke Codex or read private candidates."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import generate_behavior_holdout as subject
from run_behavior_eval import _capture_codex as capture_local_process


def synthetic_stream():
    records = [
        {"type": "thread.started", "thread_id": "synthetic-thread"},
        {"type": "item.completed", "item": {"type": "reasoning", "text": "HIDDEN_ITEM"}},
        {"type": "response.reasoning.delta", "delta": "HIDDEN_DELTA"},
        {"type": "item.completed", "channel": "analysis",
         "item": {"type": "agent_message", "text": "HIDDEN_CHANNEL"}},
        {"type": "item.completed", "item": {"type": "agent_message", "text": "visible final",
         "reasoning": "HIDDEN_FIELD", "analysis": "HIDDEN_ANALYSIS"}},
        {"type": "item.completed", "item": {"type": "command_execution", "command": "git status",
         "exit_code": 0, "aggregated_output": "visible tool output"}},
        {"type": "error", "message": "HIDDEN_ERROR"},
        {"type": "unknown", "text": "HIDDEN_UNKNOWN"},
        ["HIDDEN_ARRAY"],
    ]
    return "\n".join(json.dumps(record) for record in records) + '\nHIDDEN_PLAIN\n{"HIDDEN_TRUNCATED":'


class HoldoutCaptureTests(unittest.TestCase):
    def test_errors_keep_only_allowlisted_codes_and_bounded_http_status(self):
        records = [
            {"type": "error", "code": "invalid_json_schema", "status_code": 400,
             "message": "HIDDEN_PROMPT", "param": "HIDDEN_PATH"},
            {"type": "turn.failed", "error": {"code": "rate_limit_exceeded",
             "http_status_code": 429, "message": "HIDDEN_REASONING"}},
            {"type": "error", "code": "HIDDEN_UNKNOWN", "status": "HIDDEN_STATUS"},
            {"type": "error", "code": ["HIDDEN"], "status_code": True},
            {"type": "error", "status_code": 999999},
            {"type": "error", "channel": "analysis", "code": "server_error", "status": 500},
        ]
        visible = subject._visible_capture("\n".join(map(json.dumps, records)))
        self.assertNotIn("HIDDEN", visible)
        self.assertEqual([json.loads(line) for line in visible.splitlines()], [
            {"type": "error", "code": "invalid_json_schema", "http_status_code": 400},
            {"type": "turn.failed", "code": "rate_limit_exceeded", "http_status_code": 429},
            {"type": "error"}, {"type": "error"}, {"type": "error"},
        ])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="gsp-holdout-capture-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.arguments = dict(
            codex="never-execute-codex", model="synthetic-model", reasoning="medium",
            prompt="synthetic input only", schema_path=self.root / "schema.json",
            output_path=self.root / "candidate.json", raw_output_dir=self.root, label="generation",
        )

    def saved(self):
        stdout = (self.root / "generation-stdout.jsonl").read_text(encoding="utf-8")
        stderr = (self.root / "generation-stderr.txt").read_text(encoding="utf-8")
        self.assertNotIn("HIDDEN", stdout + stderr)
        return stdout, stderr

    def run_mocked(self, *, result=None, error=None):
        initialized = subprocess.CompletedProcess(["git", "init"], 0, "", "")
        with mock.patch.object(subject.subprocess, "run", return_value=initialized) as git, \
             mock.patch.object(subject, "_capture_codex", return_value=result, side_effect=error) as capture:
            code = subject._run_codex(**self.arguments)
        self.assertEqual(git.call_count, 1)
        self.assertEqual(git.call_args.args[0], ["git", "init", "-b", "main"])
        return code, capture

    def test_success_retains_visible_events_and_compatible_flags(self):
        with mock.patch.object(subject.sys, "platform", "win32"):
            code, capture = self.run_mocked(result=subprocess.CompletedProcess(
                [], 0, synthetic_stream(), "HIDDEN_STDERR"))
        self.assertEqual(code, 0)
        stdout, stderr = self.saved()
        self.assertIn("visible final", stdout)
        self.assertIn("visible tool output", stdout)
        self.assertIn("STDERR_WITHHELD", stderr)
        command = capture.call_args.args[0]
        for flag in ("--ephemeral", "--ignore-user-config", "--ignore-rules", "--json"):
            self.assertIn(flag, command)
        for flag, value in (("--output-schema", self.arguments["schema_path"]),
                            ("--output-last-message", self.arguments["output_path"]),
                            ("--sandbox", "read-only"), ("--model", "synthetic-model")):
            self.assertEqual(command[command.index(flag) + 1], str(value))
        self.assertIn('model_reasoning_effort="medium"', command)
        self.assertIn("show_raw_agent_reasoning=false", command)
        self.assertIn("shell_environment_policy.experimental_use_profile=false", command)
        self.assertEqual(capture.call_args.kwargs["prompt"], "synthetic input only")
        self.assertEqual(capture.call_args.kwargs["timeout"], 360)

    def test_linux_uses_parent_named_permissions_without_legacy_sandbox(self):
        with mock.patch.object(subject.sys, "platform", "linux"), \
             mock.patch.object(subject, "linux_permission_args", wraps=subject.linux_permission_args) as permissions:
            code, capture = self.run_mocked(result=subprocess.CompletedProcess([], 0, "", ""))
        self.assertEqual(code, 0)
        work = capture.call_args.kwargs["cwd"]
        permissions.assert_called_once_with(work)
        command = capture.call_args.args[0]
        self.assertNotIn("--sandbox", command)
        self.assertNotIn("--approve-for-me", command)
        expected = subject.linux_permission_args(work)
        self.assertEqual(command[-len(expected) - 1:-1], expected)
        self.assertIn('default_permissions="behavior_eval"', command)
        self.assertIn('approval_policy="never"', command)
        self.assertEqual(command[-1], "-")

    def test_nonzero_and_timeout_results_never_persist_raw_streams(self):
        for code in (2, 124, 125):
            with self.subTest(code=code):
                actual, _ = self.run_mocked(result=subprocess.CompletedProcess(
                    [], code, synthetic_stream().encode(), b"HIDDEN_STDERR\xff"))
                self.assertEqual(actual, code)
                stdout, stderr = self.saved()
                self.assertIn("visible final", stdout)
                self.assertIn(f"EXIT_CODE={code}", stderr)
                if code == 124:
                    self.assertIn("TIMEOUT", stderr)
                if code == 125:
                    self.assertIn("INCOMPLETE_TOOL_CAPTURE", stderr)

    def test_byte_timeout_exception_preserves_only_visible_partial_events(self):
        error = subprocess.TimeoutExpired(["never-execute-codex"], 360,
                                          output=synthetic_stream().encode() + b"\xff",
                                          stderr=b"HIDDEN_STDERR")
        code, _ = self.run_mocked(error=error)
        self.assertEqual(code, 124)
        stdout, stderr = self.saved()
        self.assertIn("visible tool output", stdout)
        self.assertIn("TIMEOUT", stderr)

    def test_launch_failure_does_not_echo_exception(self):
        code, _ = self.run_mocked(error=OSError("HIDDEN_EXCEPTION"))
        self.assertEqual(code, -1)
        self.assertEqual(self.saved()[0], "")

    def test_git_init_failure_does_not_start_capture_or_echo_raw_diagnostics(self):
        with mock.patch.object(subject.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 1, "HIDDEN_STDOUT", "HIDDEN_STDERR")), \
             mock.patch.object(subject, "_capture_codex") as capture:
            self.assertEqual(subject._run_codex(**self.arguments), -1)
        capture.assert_not_called()
        self.assertEqual(self.saved()[0], "")

    def test_environment_uses_parent_controls_without_credential_free_claim(self):
        inherited = {"PATH": "synthetic-path", "CODEX_HOME": "synthetic-auth-home",
                     "CODEX_THREAD_ID": "inherited-thread", "CODEX_OTHER": "inherited-config",
                     "GH_TOKEN": "synthetic-secret", "GITHUB_TOKEN": "synthetic-secret",
                     "OPENAI_API_KEY": "synthetic-secret", "SERVICE_AUTH": "synthetic-secret",
                     "GIT_CONFIG_COUNT": "99", "GIT_CONFIG_KEY_98": "credential.helper",
                     "GIT_CONFIG_VALUE_98": "inherited-helper", "GIT_DIR": "foreign-repo"}
        with mock.patch.dict(os.environ, inherited, clear=True):
            environment = subject._environment(self.root)
        self.assertEqual(environment["CODEX_HOME"], "synthetic-auth-home")
        for name in inherited.keys() - {"PATH", "CODEX_HOME", "GIT_CONFIG_COUNT"}:
            self.assertNotIn(name, environment)
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "3")
        self.assertEqual(environment["GIT_CONFIG_VALUE_0"], "")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertTrue(Path(environment["GH_CONFIG_DIR"]).is_dir())

    def test_local_python_tree_timeout_uses_real_parent_capture(self):
        # Only this synthetic Python process tree runs, never the requested CLI.
        program = (
            "import json, subprocess, sys, time; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
            "print(json.dumps({'type':'item.completed','item':{'type':'reasoning','text':'HIDDEN_ITEM'}}), flush=True); "
            "print(json.dumps({'type':'item.completed','item':{'type':'agent_message','text':'visible partial'}}), flush=True); "
            "print('HIDDEN_STDERR', file=sys.stderr, flush=True); time.sleep(30)"
        )

        def local_only(command, *, cwd, env, prompt, timeout):
            self.assertEqual(command[0], "never-execute-codex")
            return capture_local_process([sys.executable, "-B", "-c", program],
                                         cwd=cwd, env=env, prompt="", timeout=1)

        started = time.monotonic()
        with mock.patch.object(subject, "_capture_codex", side_effect=local_only):
            self.assertEqual(subject._run_codex(**self.arguments), 124)
        self.assertLess(time.monotonic() - started, 15)
        stdout, stderr = self.saved()
        self.assertIn("visible partial", stdout)
        self.assertIn("TIMEOUT", stderr)
        self.assertNotIn("INCOMPLETE_TOOL_CAPTURE", stderr)


if __name__ == "__main__":
    unittest.main()
