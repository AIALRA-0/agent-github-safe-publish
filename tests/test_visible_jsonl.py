"""Synthetic visible-capture regressions; no model or network execution."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_behavior_eval as runner  # noqa: E402


MARKER = {"type": "capture.error", "error": "malformed_jsonl"}


class VisibleJsonlTests(unittest.TestCase):
    def test_malformed_and_nonobject_lines_never_retain_raw_fragments(self):
        for raw in ('{"type":"reasoning","text":"synthetic-hidden',
                    'synthetic-hidden', '"synthetic-hidden"',
                    '["synthetic-hidden"]', 'null', '123'):
            with self.subTest(raw=raw):
                clean = runner._visible_jsonl(raw)
                self.assertEqual(json.loads(clean), MARKER)
                self.assertNotIn("synthetic-hidden", clean)

    def test_known_reasoning_events_are_filtered(self):
        for kind in ("reasoning", "agent_reasoning", "reasoning_text", "raw_reasoning"):
            for event in ({"type": kind, "text": "synthetic-hidden"},
                          {"type": "item.completed", "item": {
                              "type": kind, "text": "synthetic-hidden"}}):
                with self.subTest(event=event):
                    self.assertEqual(runner._visible_jsonl(json.dumps(event)), "")
        self.assertEqual(runner._visible_jsonl(json.dumps({
            "type": "response.reasoning_text.delta", "delta": "synthetic-hidden"})), "")

    def test_visible_messages_and_tools_are_preserved_including_unicode_separators(self):
        events = [
            {"type": "item.completed", "item": {
                "type": "agent_message", "text": "Visible reasoning explanation\u2028next\u0085line"}},
            {"type": "item.completed", "item": {
                "type": "command_execution", "command": "git status", "exit_code": 0}},
        ]
        raw = "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n"
        self.assertEqual(runner._visible_jsonl(raw), raw)

    def test_blank_lines_are_ignored_and_filtering_is_idempotent(self):
        self.assertEqual(runner._visible_jsonl("\n \r\n\t\n"), "")
        raw = '{"type":"item.completed","item":{"type":"agent_message","text":"visible"}}\ntruncated'
        once = runner._visible_jsonl(raw)
        self.assertEqual(runner._visible_jsonl(once), once)
        self.assertEqual("".join(runner._visible_jsonl(line) for line in raw.split("\n")), once)

    def test_actual_timeout_capture_drops_truncated_hidden_fragment(self):
        visible = json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "text": "synthetic-visible"}})
        truncated = '{"type":"item.completed","item":{"type":"reasoning","text":"synthetic-hidden'
        program = (
            "import sys, time; "
            f"print({visible!r}, flush=True); "
            f"sys.stdout.write({truncated!r}); sys.stdout.flush(); time.sleep(30)"
        )
        with tempfile.TemporaryDirectory() as directory:
            result = runner._capture_codex(
                [sys.executable, "-c", program], cwd=Path(directory),
                env={key: value for key, value in os.environ.items()
                     if key in {"SYSTEMROOT", "SystemRoot", "PATH", "TEMP", "TMP"}},
                prompt="", timeout=1,
            )
        self.assertEqual(result.returncode, 124)
        self.assertNotIn("synthetic-hidden", result.stdout)
        self.assertEqual([json.loads(line) for line in result.stdout.split("\n") if line],
                         [json.loads(visible), MARKER])

    def test_runner_marks_malformed_capture_failure_without_discarding_tool_evidence(self):
        tool = json.dumps({"type": "item.completed", "item": {
            "id": "synthetic-tool", "type": "command_execution",
            "command": "git status", "exit_code": 0}}) + "\n"
        for malformed in (False, True):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                schema = root / "schema.json"
                schema.write_text('{"properties":{}}', encoding="utf-8")
                args = SimpleNamespace(
                    raw_output_dir=root / "raw", skill=root / "unused-skill",
                    output_schema=schema, codex="unused", model="synthetic",
                    reasoning="low", language="en", context_profile="minimal", timeout_seconds=1,
                )

                def fake_capture(command, **kwargs):
                    Path(command[0]).write_text('{}', encoding="utf-8")
                    stdout = tool + ('{"type":"reasoning","text":"synthetic-hidden' if malformed else '')
                    return subprocess.CompletedProcess(command, 0, stdout, '')

                with mock.patch.object(runner, "_safe_environment", return_value={}), \
                     mock.patch.object(runner, "_prepare_fixture", side_effect=lambda root, *_: root), \
                     mock.patch.object(runner, "_stage_skill", return_value={}), \
                     mock.patch.object(runner, "_snapshot", return_value={}), \
                     mock.patch.object(runner, "_prompt", return_value=""), \
                     mock.patch.object(runner, "_codex_command", side_effect=lambda *a: [str(a[3])]), \
                     mock.patch.object(runner, "_capture_codex", side_effect=fake_capture):
                    record, ok = runner._execute_case({"case_id": "synthetic", "allowed_writes": []}, args, "", 1)
                self.assertEqual(ok, not malformed)
                self.assertEqual(len(record["events"]), 1)
                self.assertIn("codex_exit=0", record["raw_output"]["redacted_summary"])
                saved = next(args.raw_output_dir.rglob("stdout.jsonl")).read_text(encoding="utf-8")
                self.assertNotIn("synthetic-hidden", saved)
                self.assertEqual("capture.error" in saved, malformed)


if __name__ == "__main__":
    unittest.main()
