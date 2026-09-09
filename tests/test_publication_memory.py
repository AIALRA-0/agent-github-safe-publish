"""Observable local Git/journal tests; not a claim about every future agent."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "publication_memory.py"
spec = importlib.util.spec_from_file_location("publication_memory", SCRIPT)
memory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(memory)


def lesson(**updates):
    return {"id": "generated-config", "category": "credentials", "paths": ["config/*"],
            "cause": "Generated examples can copy a live configuration",
            "repair": "Generate examples from synthetic defaults",
            "regression_check": "Review every outgoing config blob and generated bundle",
            "status": "fixed", **updates}


class PublicationMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name) / "project"
        self.repo.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Synthetic Test")
        self.git("config", "user.email", "synthetic@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")
        self.commit("README.md", "synthetic fixture\n")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        environment = os.environ.copy()
        environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                           GIT_TERMINAL_PROMPT="0")
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True,
                              capture_output=True, text=True, env=environment).stdout

    def commit(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        self.git("add", "--", name)
        self.git("commit", "-m", "synthetic fixture update")

    def cli(self, *args, stdin=None):
        return subprocess.run([sys.executable, str(SCRIPT), "--repo", str(self.repo), *args],
                              input=stdin, capture_output=True, text=True)

    def test_missing_history_is_explicit_and_read_only(self):
        result = self.cli("show")
        self.assertEqual(0, result.returncode)
        self.assertEqual("unavailable", json.loads(result.stdout)["history"])
        self.assertFalse(memory.journal_path(self.repo).parent.exists())
        self.assertEqual("", self.git("status", "--porcelain"))

    def test_new_process_reads_saved_lesson_without_tracking_it(self):
        self.assertEqual(0, self.cli("record", stdin=json.dumps(lesson())).returncode)
        result = json.loads(self.cli("show").stdout)
        self.assertEqual("generated-config", result["lessons"][0]["id"])
        self.assertEqual("", self.git("status", "--porcelain", "--untracked-files=all"))
        self.assertNotIn("risks.json", self.git("ls-files"))

    def test_updates_do_not_duplicate_or_remove_other_lessons(self):
        memory.record(self.repo, lesson(status="open"))
        memory.record(self.repo, lesson(id="metadata", paths=["*"], category="write_integrity"))
        memory.record(self.repo, lesson(status="fixed"))
        saved = memory.read_journal(memory.journal_path(self.repo))["lessons"]
        self.assertEqual(2, len(saved))
        self.assertEqual("fixed", saved[0]["status"])

    def test_intermediate_commits_are_selected_even_when_net_diff_is_clean(self):
        memory.record(self.repo, lesson())
        self.commit("config/example.txt", "SYNTHETIC_UNSAFE_VALUE\n")
        self.git("rm", "config/example.txt")
        self.git("commit", "-m", "remove synthetic value")
        self.assertEqual("", self.git("diff", "--name-only", self.base, "HEAD"))
        result = json.loads(self.cli("relevant", "--base", self.base).stdout)
        self.assertIn("config/example.txt", result["paths"])
        self.assertEqual(1, len(result["lessons"]))
        self.assertIn("path selection only", result["scope"])
        commits = self.git("rev-list", f"{self.base}..HEAD").splitlines()
        self.assertTrue(any("SYNTHETIC_UNSAFE_VALUE" in self.git("show", commit)
                            for commit in commits))

    def test_recurrence_update_preserves_existing_issue_link(self):
        url = "https://github.com/example/synthetic/issues/1"
        memory.record(self.repo, lesson(issue_url=url))
        memory.record(self.repo, lesson(status="open"))
        saved = memory.read_journal(memory.journal_path(self.repo))["lessons"][0]
        self.assertEqual(url, saved["issue_url"])
        self.assertEqual("open", saved["status"])

    def test_unrelated_changes_skip_path_specific_but_keep_global_lessons(self):
        memory.record(self.repo, lesson())
        memory.record(self.repo, lesson(id="metadata", paths=["*"], category="write_integrity"))
        self.commit("docs/usage.txt", "safe change\n")
        result = json.loads(self.cli("relevant", "--base", self.base).stdout)
        self.assertEqual(["metadata"], [item["id"] for item in result["lessons"]])

    def test_rename_includes_old_and_new_path(self):
        self.commit("config/example.txt", "synthetic\n")
        base = self.git("rev-parse", "HEAD").strip()
        self.git("mv", "config/example.txt", "moved.txt")
        self.git("commit", "-m", "move synthetic configuration")
        self.assertEqual(["config/example.txt", "moved.txt"],
                         memory.outgoing_paths(self.repo, base, "HEAD"))

    def test_invalid_or_duplicate_records_are_preserved(self):
        path = memory.journal_path(self.repo)
        path.parent.mkdir(parents=True)
        for original in ("{broken", '{"schema_version":1,"schema_version":1,"lessons":[]}'):
            with self.subTest(original=original):
                path.write_text(original, encoding="utf-8")
                result = self.cli("record", stdin=json.dumps(lesson()))
                self.assertEqual(2, result.returncode)
                self.assertEqual(original, path.read_text(encoding="utf-8"))
                self.assertNotIn(original, result.stderr)

    def test_concurrent_writer_is_not_overwritten(self):
        memory.record(self.repo, lesson())
        path = memory.journal_path(self.repo)
        before = path.read_bytes()
        lock = path.with_suffix(".lock")
        lock.write_text("another writer", encoding="utf-8")
        self.assertEqual(2, self.cli("record", stdin=json.dumps(lesson(status="open"))).returncode)
        self.assertEqual(before, path.read_bytes())
        self.assertTrue(lock.exists())

    def test_unknown_fields_private_urls_and_absolute_paths_are_rejected(self):
        for data in (lesson(command="never execute"), lesson(paths=["../other"]),
                     lesson(paths=["C:/private"]), lesson(paths=["/private"]),
                     lesson(issue_url="https://github.com/example/repo/issues/1?token=synthetic")):
            with self.subTest(data=data):
                self.assertEqual(2, self.cli("record", stdin=json.dumps(data)).returncode)
        self.assertFalse(memory.journal_path(self.repo).exists())

    def test_record_is_data_and_never_runs_its_descriptive_check(self):
        marker = self.repo / "must-not-exist"
        payload = lesson(regression_check=f"touch {marker}")
        self.assertEqual(0, self.cli("record", stdin=json.dumps(payload)).returncode)
        self.assertEqual(0, self.cli("show").returncode)
        self.assertFalse(marker.exists())

    def test_invalid_base_is_not_reported_as_empty_safe_scope(self):
        result = self.cli("relevant", "--base", "missing-ref")
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)

    def test_recurrence_repair_and_bare_remote_readback(self):
        # A real local Git sequence, not a simulated model statement or real credential.
        remote = Path(self.temporary.name) / "synthetic.git"
        self.git("init", "--bare", str(remote))
        self.git("remote", "add", "origin", str(remote))
        self.git("push", "origin", "HEAD:refs/heads/main")
        memory.record(self.repo, lesson())
        unsafe = "SYNTHETIC_UNSAFE_VALUE"
        path = self.repo / "config" / "example.txt"
        path.parent.mkdir()
        path.write_text(unsafe, encoding="utf-8")
        # Fresh process reloads the old lesson before reviewing the uncommitted recurrence.
        old = json.loads(self.cli("show").stdout)["lessons"]
        self.assertEqual(1, len(memory.relevant({"lessons": old}, ["config/example.txt"])))
        self.assertIn(unsafe, path.read_text(encoding="utf-8"))
        self.commit("config/example.txt", "SYNTHETIC_PUBLIC_DEFAULT\n")
        for commit in self.git("rev-list", f"{self.base}..HEAD").splitlines():
            self.assertNotIn(unsafe, self.git("show", commit))
        memory.record(self.repo, lesson(status="fixed"))
        self.git("push", "origin", "HEAD:refs/heads/main")
        head = self.git("rev-parse", "HEAD").strip()
        self.assertEqual(head, self.git("ls-remote", "origin", "refs/heads/main").split()[0])
        self.assertEqual("", self.git("status", "--porcelain"))
        refs = self.git("ls-remote", "origin")
        self.assertNotIn("refs/tags/", refs)
        self.assertEqual(1, refs.count("refs/heads/"))


if __name__ == "__main__":
    unittest.main()
