"""Input fidelity and observable-output regression tests for actual agent runs."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_behavior_eval import (  # noqa: E402
    _authorized_write_was_not_executed, _codex_command, _fixture_state, _normalize_events,
    _output_text, _safe_environment, _stage_skill, _visible_jsonl,
)
from grade_skill_behavior import _has_content_review  # noqa: E402


class EvalInputTests(unittest.TestCase):
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
                for event in events:
                    self.assertEqual("unknown", event["result"]["status"])
                    self.assertEqual(exit_code, event["result"]["shell_exit_code"])
                self.assertFalse(_has_content_review(events))
                self.assertFalse(_authorized_write_was_not_executed(events, {"branch_push"}))

    def test_filtered_output_command_still_makes_shell_result_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = json.dumps({"type": "item.completed", "item": {
                "id": "tool-1", "type": "command_execution",
                "command": "git push origin main; Write-Output done", "exit_code": 0,
            }})
            events = _normalize_events(raw, [root], root)
            self.assertEqual(len(events), 1)
            self.assertEqual("unknown", events[0]["result"]["status"])

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
        }, clear=True):
            environment = _safe_environment(Path("synthetic-gh"))
        self.assertNotIn("GIT_SSH_COMMAND", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)
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
        command = _codex_command("codex", Path("work"), Path("schema"), Path("result"), "model", "medium")
        # Current CLI defines --approve-for-me as workspace-write and rejects --sandbox with it.
        self.assertIn("--approve-for-me", command)
        self.assertNotIn("--sandbox", command)
        self.assertIn("sandbox_workspace_write.network_access=false", command)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", command)


if __name__ == "__main__":
    unittest.main()
