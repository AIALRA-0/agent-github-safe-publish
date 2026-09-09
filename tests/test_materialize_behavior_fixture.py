"""Local temporary Git only. Never open private cases or parent runner modules."""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from behavior_fixture_spec import FixtureSpecError, prepare_fixture_spec
import materialize_behavior_fixture as subject
from materialize_behavior_fixture import apply_git_updates, materialize


def spec():
    return {"fixture_profile": "default", "fixture_setup": {}, "fixture_state": {},
            "fixture_transitions": [], "fixture_requirements": []}


class RuntimePathRegressionTests(unittest.TestCase):
    def test_empty_updates_skip_path_and_git_validation(self):
        with patch.object(subject, "_paths", side_effect=AssertionError("must not inspect paths")) as paths, \
             patch.object(subject, "_LocalGit", side_effect=AssertionError("must not initialize Git")) as git:
            self.assertEqual([], apply_git_updates(Path("not-a-fixture") / "work", [], {}))
        paths.assert_not_called()
        git.assert_not_called()

    def test_nonempty_updates_still_require_scoped_paths(self):
        with patch.object(subject, "_paths", side_effect=FixtureSpecError(["scoped-path-denied"])) as paths, \
             patch.object(subject, "_LocalGit") as git:
            with self.assertRaisesRegex(FixtureSpecError, "scoped-path-denied"):
                apply_git_updates(Path("not-a-fixture") / "work",
                                  [{"collection": "branches", "name": "main", "target": None}], {})
        paths.assert_called_once()
        git.assert_not_called()

    def test_linux_paths_ignore_tempfile_fallback_to_work_and_keep_direct_root_guard(self):
        # Linux CI exercises real /tmp. On Windows translate only that literal;
        # retain native Path semantics and actual on-disk directory validation.
        native_linux = sys.platform == "linux"
        with tempfile.TemporaryDirectory(prefix="gsp-behavior-eval-",
                                         dir="/tmp" if native_linux else None) as temporary:
            root = Path(temporary).resolve()
            work, bare = root / "work", root / "remote.git"
            (work / ".git").mkdir(parents=True)
            bare.mkdir()

            def native_path(value):
                if not native_linux and value == "/tmp":
                    return root.parent
                return Path(value)

            with patch.object(subject.sys, "platform", "linux"), \
                 patch.object(subject.tempfile, "gettempdir", return_value=str(work)) as fallback, \
                 patch.object(subject, "Path", side_effect=native_path):
                self.assertEqual((work, root, bare), subject._paths(work))
                with self.assertRaisesRegex(FixtureSpecError, "not_dedicated_temporary_fixture"):
                    subject._paths(work / "nested" / "work")
            fallback.assert_not_called()


class MaterializeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gsp-behavior-eval-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.work = self.root / "work"
        self.bare = self.root / "remote.git"
        self.work.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
        self.env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                         "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "file"})
        self.git("init", "--bare", str(self.bare))
        self.git("-C", str(self.work), "init", "-b", "main")
        self.git("-C", str(self.work), "config", "user.name", "Synthetic Unit")
        self.git("-C", str(self.work), "config", "user.email", "unit@example.invalid")
        (self.work / "README.md").write_text("synthetic base\n", encoding="utf-8")
        self.git("-C", str(self.work), "add", "README.md")
        self.git("-C", str(self.work), "commit", "-m", "synthetic base")
        self.base = self.git("-C", str(self.work), "rev-parse", "HEAD")
        self.git("-C", str(self.work), "remote", "add", "origin", str(self.bare))
        self.git("-C", str(self.work), "push", "origin", "main")
        (self.work / "example.txt").write_text("synthetic candidate\n", encoding="utf-8")
        self.git("-C", str(self.work), "add", "example.txt")
        self.git("-C", str(self.work), "commit", "-m", "synthetic candidate")
        self.candidate = self.git("-C", str(self.work), "rev-parse", "HEAD")
        self.commits = {"base": self.base, "candidate": self.candidate}
        (self.work / ".eval").mkdir()
        self.state_path = self.work / ".eval" / "remote-state.json"
        self.state_path.write_text(json.dumps({"allowed_writes": ["branch_push"],
                                               "fixture_events": [], "parent_control": "preserve"}), encoding="utf-8")

    def git(self, *args):
        result = subprocess.run(["git", *args], cwd=self.root, env=self.env,
                                text=True, encoding="utf-8", capture_output=True,
                                timeout=15, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.strip()

    def test_multiple_refs_annotated_tags_and_state_readback(self):
        value = spec()
        value["fixture_setup"] = {"local_candidate": True, "local_branches": {"topic-example": "@candidate"},
                                   "current_branch": "topic-example"}
        value["fixture_state"] = {"branches": {"main": "@base", "topic-example": "@candidate"},
                                   "tags": {"release-example": "@base", "candidate-example": "@candidate"}}
        value["fixture_requirements"] = [{"at": "initial", "kind": "equals",
                                            "path": ["tags", "release-example"], "value": "@base"}]
        original = deepcopy(value)
        plan = materialize(prepare_fixture_spec(value), self.work, self.commits, self.env)
        self.assertTrue(plan["bound"])
        self.assertEqual(self.candidate, self.git("--git-dir", str(self.bare), "rev-parse", "refs/heads/topic-example"))
        self.assertEqual("tag", self.git("--git-dir", str(self.bare), "cat-file", "-t", "refs/tags/release-example"))
        self.assertEqual(self.base, self.git("--git-dir", str(self.bare), "rev-parse", "refs/tags/release-example^{commit}"))
        self.assertEqual(self.candidate, self.git("-C", str(self.work), "rev-parse", "refs/remotes/origin/topic-example"))
        self.assertEqual("topic-example", self.git("-C", str(self.work), "symbolic-ref", "--short", "HEAD"))
        persisted = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual("preserve", persisted["parent_control"])
        self.assertEqual(["branch_push"], persisted["allowed_writes"])
        self.assertEqual(plan["state"]["tags"], persisted["tags"])
        self.assertEqual(original, value)

    def test_native_temp_path_accepts_windows_short_parent_without_weakening_root_guard(self):
        raw_work = Path(self.temporary.name) / "work"
        self.assertTrue(os.path.samefile(raw_work, self.work))
        result = materialize(prepare_fixture_spec(spec()), raw_work, self.commits, self.env)
        self.assertTrue(result["bound"])
        with self.assertRaisesRegex(FixtureSpecError, "not_dedicated_temporary_fixture"):
            materialize(prepare_fixture_spec(spec()), raw_work / "nested", self.commits, self.env)

    def test_no_worktree_file_is_deleted_or_rewritten_and_no_network_transport(self):
        (self.work / "untouched.txt").write_text("keep me", encoding="utf-8")
        expected = {p.name: p.read_bytes() for p in self.work.iterdir() if p.is_file()}
        self.git("-C", str(self.work), "remote", "set-url", "origin", "https://example.invalid/never-contact.git")
        commands = []
        actual_run = subprocess.run

        def capture(command, **kwargs):
            commands.append(command)
            self.assertNotIn("push", command)
            self.assertNotIn("checkout", command)
            self.assertNotIn("https://example.invalid/never-contact.git", command)
            self.assertEqual("file", kwargs["env"]["GIT_ALLOW_PROTOCOL"])
            return actual_run(command, **kwargs)

        with patch("materialize_behavior_fixture.subprocess.run", side_effect=capture):
            materialize(prepare_fixture_spec(spec()), self.work, self.commits, self.env)
        self.assertTrue(commands)
        self.assertEqual(expected, {p.name: p.read_bytes() for p in self.work.iterdir() if p.is_file()})

    def test_missing_binding_fails_before_refs_change(self):
        old = self.git("--git-dir", str(self.bare), "show-ref")
        with self.assertRaisesRegex(FixtureSpecError, "missing_or_invalid_actual_commit"):
            materialize(prepare_fixture_spec(spec()), self.work, {"base": self.base}, self.env)
        self.assertEqual(old, self.git("--git-dir", str(self.bare), "show-ref"))

    def test_nonexistent_commit_not_guessed(self):
        value = spec()
        value["fixture_setup"]["remote_advanced"] = True
        commits = {**self.commits, "remote_advanced": "a" * 40}
        with self.assertRaisesRegex(FixtureSpecError, "bound_commit_does_not_exist"):
            materialize(prepare_fixture_spec(value), self.work, commits, self.env)

    def test_nonfixture_directory_is_rejected_before_any_git_call(self):
        with patch("materialize_behavior_fixture.subprocess.run", side_effect=AssertionError("must not run")):
            with self.assertRaisesRegex(FixtureSpecError, "not_dedicated_temporary_fixture"):
                materialize(prepare_fixture_spec(spec()), Path.cwd(), self.commits, self.env)
            with self.assertRaisesRegex(FixtureSpecError, "not_dedicated_temporary_fixture"):
                materialize(prepare_fixture_spec(spec()), self.work / "nested", self.commits, self.env)

    def test_gitfile_external_alternates_and_config_includes_rejected(self):
        alternate = self.work / ".git" / "objects" / "info" / "alternates"
        alternate.write_text(str(self.root / "outside-objects") + "\n", encoding="utf-8")
        with self.assertRaisesRegex(FixtureSpecError, "external_object_or_common_directory"):
            materialize(prepare_fixture_spec(spec()), self.work, self.commits, self.env)
        alternate.write_text("", encoding="utf-8")
        config = self.work / ".git" / "config"
        with config.open("a", encoding="utf-8") as stream:
            stream.write('\n[include]\n\tpath = unrelated-config\n')
        with self.assertRaisesRegex(FixtureSpecError, "config_include_not_supported"):
            materialize(prepare_fixture_spec(spec()), self.work, self.commits, self.env)

    def test_gitfile_is_not_a_valid_work_repository(self):
        (self.work / ".git").rename(self.root / "saved-git")
        (self.work / ".git").write_text("gitdir: ../saved-git\n", encoding="utf-8")
        with self.assertRaisesRegex(FixtureSpecError, "unsafe_repository_path"):
            materialize(prepare_fixture_spec(spec()), self.work, self.commits, self.env)

    def test_dangerous_git_environment_is_not_forwarded(self):
        supplied = {**self.env, "GIT_DIR": str(self.root / "outside"),
                    "GIT_WORK_TREE": str(self.root), "GIT_CONFIG_COUNT": "1",
                    "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": "outside"}
        actual_run = subprocess.run

        def check(command, **kwargs):
            for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"):
                self.assertNotIn(name, kwargs["env"])
            return actual_run(command, **kwargs)

        with patch("materialize_behavior_fixture.subprocess.run", side_effect=check):
            materialize(prepare_fixture_spec(spec()), self.work, self.commits, supplied)

    def test_detached_head_and_empty_remote_refs_are_materialized_without_file_removal(self):
        value = spec()
        value["fixture_setup"]["detached_head"] = True
        value["fixture_state"]["branches"] = {}
        plan = materialize(prepare_fixture_spec(value), self.work, self.commits, self.env)
        self.assertEqual({}, plan["state"]["branches"])
        self.assertEqual("", self.git("--git-dir", str(self.bare), "for-each-ref", "refs/heads/"))
        self.assertEqual(self.candidate, self.git("-C", str(self.work), "rev-parse", "HEAD"))
        self.assertEqual("synthetic candidate\n", (self.work / "example.txt").read_text(encoding="utf-8"))

    def test_head_change_requires_parent_preparation_instead_of_checkout(self):
        value = spec()
        value["fixture_setup"] = {"local_branches": {"initial-example": "@base"}, "current_branch": "initial-example"}
        with self.assertRaisesRegex(FixtureSpecError, "head_requires_parent_preparation"):
            materialize(prepare_fixture_spec(value), self.work, self.commits, self.env)
        self.assertTrue((self.work / "example.txt").is_file())

    def test_repeat_materialization_is_stable(self):
        value = spec()
        value["fixture_state"]["tags"] = {"example": "@base"}
        first = materialize(prepare_fixture_spec(value), self.work, self.commits, self.env)
        oid = self.git("--git-dir", str(self.bare), "rev-parse", "refs/tags/example")
        second = materialize(prepare_fixture_spec(value), self.work, self.commits, self.env)
        self.assertEqual(first, second)
        self.assertEqual(oid, self.git("--git-dir", str(self.bare), "rev-parse", "refs/tags/example"))

    def test_hook_updates_are_remote_only_with_exact_old_refs_and_fixture_attribution(self):
        value = spec()
        value["fixture_state"]["tags"] = {"example": "@base", "keep-example": "@base"}
        materialize(prepare_fixture_spec(value), self.work, self.commits, self.env)
        old_tag = self.git("--git-dir", str(self.bare), "rev-parse", "refs/tags/example")
        updates = [{"collection": "branches", "name": "main", "target": self.candidate},
                   {"collection": "tags", "name": "example", "target": self.candidate}]
        saved = deepcopy(updates)
        events = apply_git_updates(self.work, updates, self.env)
        self.assertEqual(saved, updates)
        self.assertEqual("fixture", events[0]["source"])
        self.assertEqual(self.base, events[0]["before"]["ref_oid"])
        self.assertEqual(old_tag, events[1]["before"]["ref_oid"])
        self.assertEqual(self.base, events[1]["before"]["target"])
        self.assertEqual(self.candidate, events[1]["after"]["target"])
        self.assertEqual(self.base, self.git("-C", str(self.work), "rev-parse", "refs/remotes/origin/main"))
        self.assertEqual(old_tag, self.git("-C", str(self.work), "rev-parse", "refs/tags/example"))
        self.assertEqual(self.candidate, self.git("--git-dir", str(self.bare), "rev-parse", "refs/tags/example^{commit}"))
        self.assertEqual("tag", self.git("--git-dir", str(self.bare), "cat-file", "-t", "refs/tags/example"))
        deleted = apply_git_updates(self.work, [{"collection": "tags", "name": "example", "target": None}], self.env)
        self.assertIsNone(deleted[0]["after"]["ref_oid"])
        self.assertEqual("refs/tags/keep-example", self.git("--git-dir", str(self.bare), "for-each-ref", "--format=%(refname)", "refs/tags/"))
        self.assertTrue((self.work / "example.txt").is_file())
        with self.assertRaisesRegex(FixtureSpecError, "not_dedicated_temporary_fixture"):
            apply_git_updates(Path.cwd(), updates, self.env)
        with self.assertRaisesRegex(FixtureSpecError, "invalid_git_updates"):
            apply_git_updates(self.work, [{"collection": "outside", "name": "main", "target": None}], self.env)


if __name__ == "__main__":
    unittest.main()
