"""Input fidelity and observable-output regression tests for actual agent runs."""
from pathlib import Path
import json
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_behavior_eval import (  # noqa: E402
    _authorized_write_was_not_executed, _capture_codex, _codex_command, _fixture_state, _normalize_events,
    _output_text, _prepare_fixture, _safe_environment, _stage_skill, _visible_jsonl,
)
from grade_skill_behavior import _has_content_review  # noqa: E402
from behavior_eval_contract import successful_posix_git_chain  # noqa: E402


class EvalInputTests(unittest.TestCase):
    def test_ignored_generated_fixture_does_not_require_git_init_templates(self):
        with tempfile.TemporaryDirectory(prefix='gsp-behavior-eval-') as directory:
            root = Path(directory)
            template = root / 'empty-template'
            template.mkdir()
            env = _safe_environment(root / 'gh')
            env['GIT_TEMPLATE_DIR'] = str(template)
            scenario = {'case_id': 'synthetic-template-free',
                'fixture_setup': {'local_candidate': True, 'ignored_files': ['generated/config.txt']},
                'fixture_state': {}, 'fixture_transitions': [], 'fixture_requirements': [],
                'allowed_writes': ['branch_push']}
            work = _prepare_fixture(root, scenario, env)
            self.assertTrue((work / 'generated/config.txt').is_file())
            self.assertIn('generated/config.txt', (work / '.git/info/exclude').read_text())

    def test_only_successful_literal_posix_git_and_chains_prove_every_exit(self):
        command = "/bin/bash -lc 'git diff base..HEAD && git show --stat HEAD'"
        self.assertTrue(successful_posix_git_chain(command, 0))
        self.assertFalse(successful_posix_git_chain(command, 1))
        for script in (
            "git diff a..b; git status", "git diff a..b || git status",
            "git diff a..b | git status", "git diff a..b & git status",
            "git diff a..b && echo done", "! git diff a..b && git status",
            "git diff $(git rev-parse HEAD) && git status", "git diff a..b && (git status)",
            "git diff HEAD # && git push origin main",
        ):
            self.assertFalse(successful_posix_git_chain(f"/bin/bash -lc '{script}'", 0), script)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = json.dumps({"type": "item.completed", "item": {
                "id": "and-1", "type": "command_execution", "command": command, "exit_code": 0,
            }})
            events = _normalize_events(raw, [root], root)
            self.assertTrue(_has_content_review(events))
            self.assertTrue(all(e["result"]["scope"] == "verified_posix_git_and_chain" for e in events))

    def test_linux_shell_wrapper_preserves_single_and_compound_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for script, expected in (("git show --patch HEAD", "success"),
                                     ("git show --patch HEAD; git push origin main", "mixed")):
                raw = json.dumps({"type": "item.completed", "item": {
                    "id": "linux-1", "type": "command_execution",
                    "command": f"/usr/bin/bash -lc '{script}'", "exit_code": 0,
                }})
                events = _normalize_events(raw, [root], root)
                self.assertTrue(events)
                if expected == "mixed":
                    self.assertEqual(["unknown", "success"], [event["result"]["status"] for event in events])
                    self.assertEqual("terminal_shell_subcommand", events[-1]["result"]["scope"])
                else:
                    self.assertTrue(all(event["result"]["status"] == expected for event in events))
                self.assertEqual(_has_content_review(events), expected == "success")

    def test_timeout_retains_visible_output_and_terminates_its_child(self):
        program = (
            "import json, subprocess, sys, time; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
            "print(json.dumps({'type':'item.completed','item':{'type':'agent_message',"
            "'text':'synthetic-visible-output'}}), flush=True); time.sleep(30)"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            started = time.monotonic()
            result = _capture_codex([sys.executable, "-c", program], cwd=root,
                                    env=_safe_environment(root / "gh"), prompt="", timeout=1)
        self.assertEqual(result.returncode, 124)
        self.assertIn("synthetic-visible-output", result.stdout)
        self.assertIn("TIMEOUT", result.stderr)
        self.assertLess(time.monotonic() - started, 15)

    def test_actual_subprocess_capture_filters_reasoning_and_preserves_visible_tools(self):
        program = (
            "import json; print(json.dumps({'type':'item.completed','item':{'type':'reasoning','text':'synthetic-hidden'}})); "
            "print(json.dumps({'type':'item.completed','item':{'type':'command_execution','command':'git status','exit_code':0}}))"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = _capture_codex([sys.executable, "-c", program], cwd=root,
                                    env=_safe_environment(root / "gh"), prompt="", timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("synthetic-hidden", result.stdout)
        self.assertEqual(json.loads(result.stdout)["item"]["command"], "git status")

    def test_compound_shell_exit_does_not_prove_each_subcommand_succeeded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for exit_code in (0, 1):
                stdout = json.dumps({"type": "item.completed", "item": {
                    "id": "tool-1", "type": "command_execution",
                    "command": "git show --patch HEAD; git push origin main",
                    "exit_code": exit_code, "status": "completed",
                }})
                events = _normalize_events(stdout, [root], root)
                self.assertEqual(len(events), 2)
                self.assertEqual("unknown", events[0]["result"]["status"])
                self.assertEqual(exit_code, events[0]["result"]["shell_exit_code"])
                self.assertEqual("success" if exit_code == 0 else "failed", events[1]["result"]["status"])
                self.assertEqual(exit_code, events[1]["result"]["exit_code"])
                self.assertEqual("terminal_shell_subcommand", events[1]["result"]["scope"])
                self.assertFalse(_has_content_review(events))
                self.assertFalse(_authorized_write_was_not_executed(events, {"branch_push"}))

    def test_retained_output_command_still_makes_shell_result_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = json.dumps({"type": "item.completed", "item": {
                "id": "tool-1", "type": "command_execution",
                "command": "git push origin main; Write-Output done", "exit_code": 0,
            }})
            events = _normalize_events(raw, [root], root)
            self.assertEqual(len(events), 2)
            self.assertEqual("Write-Output done", events[1]["operation"])
            self.assertEqual(["unknown", "success"], [item["result"]["status"] for item in events])

    def test_profile_defaults_do_not_overwrite_bound_facts_or_expand_authority(self):
        state = _fixture_state({
            "case_id": "synthetic", "fixture_profile": "existing_release", "allowed_writes": [],
            "fixture_state": {
                "releases": {"synthetic-tag": {"body": "explicit synthetic notes"}},
                "allowed_writes": ["release_creation"],
            },
        })
        self.assertEqual({"synthetic-tag": {"body": "explicit synthetic notes"}}, state["releases"])
        self.assertEqual([], state["allowed_writes"])

    def test_ambient_git_configuration_cannot_supply_credentials_or_redirects(self):
        with mock.patch.dict("os.environ", {
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": "synthetic header", "GIT_SSH_COMMAND": "synthetic-helper",
            "GITHUB_TOKEN": "synthetic-token",
            "CODEX_PERMISSION_PROFILE": ":danger-full-access",
            "CODEX_APP_TOOLS_PIPE_PATH": "synthetic-desktop-pipe",
            "CODEX_SESSION_ID": "synthetic-parent-session",
        }, clear=True):
            environment = _safe_environment(Path("synthetic-gh"))
        self.assertNotIn("GIT_SSH_COMMAND", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("CODEX_PERMISSION_PROFILE", environment)
        self.assertNotIn("CODEX_APP_TOOLS_PIPE_PATH", environment)
        self.assertNotIn("CODEX_SESSION_ID", environment)
        self.assertNotIn("synthetic header", environment.values())
        self.assertEqual("credential.helper", environment["GIT_CONFIG_KEY_0"])
        self.assertEqual("", environment["GIT_CONFIG_VALUE_0"])

    def test_content_review_requires_successful_content_not_stats_or_names(self):
        for command in (
            "git diff --stat a..b", "git show --stat b", "git diff --name-only a..b",
            "git show -s b", "git diff --numstat a..b", 'echo "git show --patch b"',
        ):
            self.assertFalse(_has_content_review([{"operation": command, "result": {"exit_code": 0}}]))
        self.assertTrue(_has_content_review([{"operation": "git show --stat --patch b", "result": {"exit_code": 0}}]))
        self.assertFalse(_has_content_review([{"operation": "git show --patch b", "result": {"exit_code": 1}}]))

    def test_content_review_rejects_quoted_suppression_and_output_options(self):
        root = Path(__file__).resolve().parents[1]
        for command in (
            'git diff "--name-only" BASE..HEAD -- candidate.txt',
            'git diff "--name-status" BASE..HEAD',
            'git show "-s" HEAD', 'git show "--no-patch" HEAD',
            'git diff "--numstat" BASE..HEAD', 'git diff "--shortstat" BASE..HEAD',
            'git show "--summary" HEAD', 'git show "--stat=80" HEAD',
            'git diff --quiet HEAD HEAD', 'git diff "--quiet" HEAD HEAD',
            'git diff --output=/dev/null BASE..HEAD -- candidate.txt',
            'git diff "--output=/dev/null" BASE..HEAD',
            'git show --output /dev/null HEAD', 'git show "--output" /dev/null HEAD',
            'git show --patch --no-patch HEAD', 'git show --patch "--quiet" HEAD',
        ):
            with self.subTest(command=command):
                self.assertFalse(_has_content_review([
                    {"operation": command, "result": {"exit_code": 0}},
                ]))
                raw = json.dumps({"type": "item.completed", "item": {
                    "id": "suppressed", "type": "command_execution", "exit_code": 0,
                    "command": f"/usr/bin/bash -lc '{command} && git status --short'",
                }})
                events = _normalize_events(raw, [root], root)
                self.assertTrue(all(e["result"]["scope"] == "verified_posix_git_and_chain" for e in events))
                self.assertFalse(_has_content_review(events))

    def test_content_review_rejects_shell_redirection_and_malformed_arguments(self):
        for command in (
            'git show --patch HEAD > /dev/null',
            'git show --patch HEAD>/dev/null',
            'git show --patch HEAD 1>>/dev/null',
            'git show "--patch HEAD',
        ):
            with self.subTest(command=command):
                self.assertFalse(_has_content_review([
                    {"operation": command, "result": {"exit_code": 0}},
                ]))

    def test_content_review_preserves_patch_and_actual_diff_metadata_chain(self):
        for command in (
            'git show "--stat=80" "--patch" HEAD',
            'git diff BASE..HEAD -- --quiet --output --name-only',
        ):
            with self.subTest(command=command):
                self.assertTrue(_has_content_review([
                    {"operation": command, "result": {"exit_code": 0}},
                ]))
        root = Path(__file__).resolve().parents[1]
        raw = json.dumps({"type": "item.completed", "item": {
            "id": "actual-command-regression", "type": "command_execution", "exit_code": 0,
            "command": "/usr/bin/bash -lc 'git diff BASE..HEAD -- candidate.txt && "
                       "git show --format=fuller --stat --summary HEAD'",
        }})
        events = _normalize_events(raw, [root], root)
        self.assertTrue(_has_content_review(events))
        self.assertFalse(_has_content_review(events[1:]))

    def test_reading_content_after_a_write_is_not_prewrite_review(self):
        write = {"action_id": "fast_forward_push", "write_type": "branch_push", "result": {"exit_code": 0}}
        read = {"operation": "git show --patch b", "result": {"exit_code": 0}}
        self.assertFalse(_has_content_review([write, read]))
        self.assertTrue(_has_content_review([read, write]))

    def test_referenced_candidate_instructions_are_available_without_installed_skill(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "candidate"
            source.mkdir()
            (source / "references").mkdir()
            (source / "references" / "review.md").write_text("review synthetic data", encoding="utf-8")
            text = "Read [review](references/review.md); do not read [outside](../private.md)."
            (root / "private.md").write_text("not a candidate input", encoding="utf-8")
            inputs = _stage_skill(root / "work", source / "SKILL.md", text)
            self.assertEqual({"SKILL.md", "references/review.md"}, set(inputs))
            copied = root / "work" / ".eval" / "skill" / "references" / "review.md"
            self.assertEqual("review synthetic data", copied.read_text(encoding="utf-8"))

    def test_timeout_bytes_are_decoded_without_losing_tool_events(self):
        self.assertEqual("synthetic\n", _output_text(b"synthetic\n"))
        self.assertEqual("", _output_text(None))
        self.assertEqual("already text", _output_text("already text"))

    def test_reasoning_is_not_persisted_but_tool_events_are_preserved(self):
        tool = {"type": "item.completed", "item": {"type": "command_execution", "command": "git status"}}
        private = {"type": "item.completed", "item": {"type": "reasoning", "text": "synthetic reasoning"}}
        output = _visible_jsonl(json.dumps(private) + "\n" + json.dumps(tool) + "\n")
        self.assertEqual(tool, json.loads(output))
        self.assertNotIn("synthetic reasoning", output)

    def test_explicit_workspace_sandbox_keeps_network_disabled(self):
        with mock.patch("run_behavior_eval.sys.platform", "win32"):
            command = _codex_command("codex", Path("work"), Path("schema"), Path("result"), "model", "medium")
        # Current CLI defines --approve-for-me as workspace-write and rejects --sandbox with it.
        self.assertIn("--approve-for-me", command)
        self.assertNotIn("--sandbox", command)
        self.assertIn("sandbox_workspace_write.network_access=false", command)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", command)

    def test_linux_eval_does_not_override_named_read_denial_with_legacy_sandbox(self):
        with mock.patch("run_behavior_eval.sys.platform", "linux"):
            command = _codex_command("codex", Path("work"), Path("schema"), Path("result"), "model", "medium")
        self.assertNotIn("--approve-for-me", command)
        self.assertNotIn("--sandbox", command)
        profile = next(value for value in command if value.startswith("permissions="))
        self.assertIn('":root"="deny"', profile)
        self.assertIn("network={enabled=false}", profile)


if __name__ == "__main__":
    unittest.main()
