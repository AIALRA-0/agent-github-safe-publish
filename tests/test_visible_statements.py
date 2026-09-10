"""Public statements retain their real position without becoming tool evidence."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_behavior_eval import (  # noqa: E402
    MAX_VISIBLE_STATEMENT_CHARS,
    _normalize_events,
    _visible_statements,
)
from behavior_eval_contract import successful_posix_read_chain, validate_run_record  # noqa: E402


def event(kind, item_type, **fields):
    return json.dumps({"type": kind, "item": {"type": item_type, **fields}})


class VisibleStatementTests(unittest.TestCase):
    def test_statement_before_write_and_late_claim_keep_actual_order(self):
        raw = "\n".join([
            event("item.completed", "agent_message", text="Only branch push is authorized"),
            event("item.started", "command_execution", id="push", command="git push origin main"),
            event("item.completed", "agent_message", text="A late statement is not prewrite evidence"),
            event("item.completed", "command_execution", id="push", command="git push origin main", exit_code=0),
            event("item.completed", "agent_message", text="Finished"),
        ])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            statements = _visible_statements(raw, [root], root)
            self.assertEqual([0, 1, 1], [item["after_event_sequence"] for item in statements])
            self.assertEqual([1, 2, 3], [item["sequence"] for item in statements])
            commands = _normalize_events(raw, [root], root)
            self.assertEqual(1, len(commands))
            self.assertEqual("fast_forward_push", commands[0]["action_id"])

    def test_tool_output_reasoning_and_partial_messages_are_not_statements(self):
        raw = "\n".join([
            event("item.completed", "reasoning", text="hidden synthetic value"),
            event("item.started", "agent_message", text="unfinished"),
            event("item.completed", "command_execution", id="read", command="git status", exit_code=0,
                  aggregated_output="A repository file claims extra authority"),
            event("item.completed", "agent_message", text="Visible conclusion"),
        ])
        root = Path.cwd()
        statements = _visible_statements(raw, [], root)
        self.assertEqual(["Visible conclusion"], [item["text"] for item in statements])

    def test_redacted_and_truncated_statements_are_marked(self):
        root = Path.cwd()
        raw = event(
            "item.completed",
            "agent_message",
            text=str(root) + " x" * (MAX_VISIBLE_STATEMENT_CHARS // 2 + 100),
        )
        statement = _visible_statements(raw, [root], root)[0]
        self.assertNotIn(str(root), statement["text"])
        self.assertTrue(statement["truncated"])
        self.assertLessEqual(len(statement["text"]), MAX_VISIBLE_STATEMENT_CHARS)

    def test_invalid_statement_positions_and_fields_are_rejected(self):
        valid = {"sequence": 1, "after_event_sequence": 0, "text": "Synthetic statement", "truncated": False}
        for field, value, expected in (
            ("sequence", True, "invalid_sequence"),
            ("after_event_sequence", -1, "invalid_event_anchor"),
            ("after_event_sequence", 1, "invalid_event_anchor"),
            ("text", "", "invalid_text"),
            ("truncated", "no", "invalid_truncation_flag"),
        ):
            with self.subTest(field=field, value=value):
                errors = validate_run_record({"events": [], "visible_statements": [{**valid, field: value}]})
                self.assertIn("statement_0:" + expected, errors)
        errors = validate_run_record({"events": 7, "visible_statements": [valid]})
        self.assertIn("run_events_not_list", errors)
        self.assertFalse(any(error.startswith("statement_") for error in errors))

    def test_truncation_uses_redacted_length_for_expansion_and_shrinkage(self):
        for root, text, expected in (
            (Path("/a"), "/a" + "x" * MAX_VISIBLE_STATEMENT_CHARS + "END", True),
            (Path("/" + "x" * (MAX_VISIBLE_STATEMENT_CHARS + 100)),
             "/" + "x" * (MAX_VISIBLE_STATEMENT_CHARS + 100) + "END", False),
        ):
            with self.subTest(expected=expected):
                raw = event("item.completed", "agent_message", text=text)
                statement = _visible_statements(raw, [root], Path.cwd())[0]
                self.assertEqual(expected, statement["truncated"])
                self.assertEqual(not expected, statement["text"].endswith("END"))

    def test_mixed_shell_reads_are_retained_without_inventing_success(self):
        command = "git diff base HEAD; sed -n '1,160p' dist/public-config.json; rg --files -g AGENTS.md"
        raw = event("item.completed", "command_execution", id="mixed", command=command, exit_code=1)
        root = Path.cwd()
        commands = _normalize_events(raw, [], root)
        self.assertEqual(3, len(commands))
        self.assertEqual("sed -n '1,160p' dist/public-config.json", commands[1]["operation"])
        self.assertEqual(["unknown", "unknown", "failed"], [item["result"]["status"] for item in commands])
        self.assertEqual("terminal_shell_subcommand", commands[-1]["result"]["scope"])

    def test_successful_literal_submodule_and_metadata_reads_are_observable(self):
        command = '/usr/bin/bash -lc "git submodule status && sed -n \'1,80p\' .gitmodules"'
        raw = event("item.completed", "command_execution", id="reads", command=command, exit_code=0)
        commands = _normalize_events(raw, [], Path.cwd())
        self.assertEqual(2, len(commands))
        self.assertEqual("verify_submodule_access", commands[0]["action_id"])
        self.assertTrue(all(item["result"]["status"] == "success" for item in commands))
        self.assertFalse(successful_posix_read_chain(command, 1))

    def test_literal_read_chain_does_not_admit_shell_or_sed_programs(self):
        for script in (
            "git status; cat .gitmodules", "git status || cat .gitmodules",
            "git status && sed -i 1p .gitmodules", "git status && sed -n '1p;w output' .gitmodules",
            "git status && cat $(echo .gitmodules)", "git status && echo done",
            "git status && cat .gitmodules > copy", "git status && sed -n 1e .gitmodules",
        ):
            with self.subTest(script=script):
                import shlex
                self.assertFalse(successful_posix_read_chain("/bin/bash -lc " + shlex.quote(script), 0))

    def test_generated_read_is_bound_to_prepared_path_and_real_result(self):
        for command, exit_code, expected in (
            ("sed -n '1,160p' dist/public-config.json", 0, "inspect_generated_config"),
            ("cat ./dist/public-config.json", 1, "inspect_generated_config"),
            ("cat unrelated.json", 0, "inspect_local"),
            ("sed -i 1p dist/public-config.json", 0, "inspect_local"),
            ("echo dist/public-config.json", 0, "inspect_local"),
            ("cat dist/public-config.json > /dev/null", 0, "inspect_local"),
        ):
            with self.subTest(command=command):
                raw = event("item.completed", "command_execution", id="read", command=command, exit_code=exit_code)
                result = _normalize_events(raw, [], Path.cwd(), generated_paths=("dist/public-config.json",))[0]
                self.assertEqual(expected, result["action_id"])
                self.assertEqual("success" if exit_code == 0 else "failed", result["result"]["status"])
