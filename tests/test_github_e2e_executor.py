"""Offline regression coverage for the deterministic executor, never live GitHub."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_github_e2e as executor


PREFIX = "e2e-v2.0.2-offline-test"
REPO = executor.ALLOWED_REPOSITORY


def result(value="", code=0, stderr=""):
    return subprocess.CompletedProcess([], code, value if isinstance(value, str) else json.dumps(value), stderr)


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        # A missing mock must fail, never fall through to a credentialed tool.
        self.transport = mock.patch.object(executor.subprocess, "run", side_effect=AssertionError("unexpected subprocess"))
        self.transport.start()
        self.addCleanup(self.transport.stop)

    def test_transport_ignores_ambient_routing_and_git_configuration(self):
        inherited = {
            "GH_HOST": "elsewhere.invalid", "GH_REPO": "other/product",
            "GH_TOKEN": "synthetic-test-token", "GIT_DIR": "other-checkout",
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "remote.origin.mirror",
            "GIT_CONFIG_VALUE_0": "true", "GIT_SSH_COMMAND": "unexpected-helper",
        }
        with mock.patch.dict(os.environ, inherited, clear=True), mock.patch.object(executor.subprocess, "run", return_value=result()) as run:
            executor._run(["git", "rev-parse", "HEAD"])
        env = run.call_args.kwargs["env"]
        self.assertEqual(env["GH_HOST"], "github.com")
        self.assertNotIn("GH_REPO", env)
        self.assertNotIn("GIT_DIR", env)
        self.assertNotIn("GIT_SSH_COMMAND", env)
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        config = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
        self.assertEqual(config["credential.https://github.com.helper"], "!gh auth git-credential")
        self.assertEqual(config["core.hooksPath"], os.devnull)
        self.assertEqual(config["http.followRedirects"], "false")
        self.assertNotIn("remote.origin.mirror", config)
        self.assertEqual(env["GH_TOKEN"], "synthetic-test-token")

    def test_clone_pins_https_origin_for_every_checkout(self):
        with mock.patch.object(executor, "_run", side_effect=[result(), result(executor.REPOSITORY_URL), result(executor.REPOSITORY_URL)]) as run:
            executor._clone_repository(REPO, Path("primary"))
        self.assertEqual(run.call_args_list[0].args[0], ["git", "clone", executor.REPOSITORY_URL, "primary"])
        with mock.patch.object(executor, "_run", side_effect=[result(), result(executor.REPOSITORY_URL), result("https://elsewhere.invalid/product")]):
            with self.assertRaisesRegex(RuntimeError, "fixed GitHub URL"):
                executor._clone_repository(REPO, Path("primary"))
        with self.assertRaises(ValueError):
            executor._clone_repository("other/product", Path("primary"))

    def test_destructive_and_bulk_spellings_are_rejected(self):
        for args in (["-f", "origin", "main"], ["origin", "+HEAD:main"], ["--mirror", "origin"], ["origin", ":main"], ["--tags", "origin"]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                executor._validate_command(["git", "push", *args])
        for flag in ("--method=DELETE", "-XDELETE"):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                executor._validate_command(["gh", "api", flag, f"repos/{REPO}"])

    def test_command_failure_does_not_render_transport_secrets(self):
        failure = executor.CommandFailure("git push", result(code=1, stderr="synthetic-token-secret"))
        self.assertNotIn("synthetic-token-secret", str(failure))

    def test_repository_lookup_failure_does_not_create_repository(self):
        with mock.patch.object(executor, "_run", return_value=result(code=1)), mock.patch.object(executor, "_gh", return_value=result(code=1, stderr="connection timed out")):
            with self.assertRaisesRegex(RuntimeError, "confirmed HTTP 404"):
                executor._ensure_repository(REPO, Path("unused"))

    def test_existing_ref_stops_before_push(self):
        with mock.patch.object(executor, "_remote_ref", return_value="existing"), mock.patch.object(executor, "_run") as run:
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                executor._push_new_ref(Path("unused"), "HEAD", f"refs/heads/{PREFIX}-push")
            run.assert_not_called()

    def test_ref_readback_matches_exact_name_not_first_suffix_match(self):
        with mock.patch.object(executor, "_run", return_value=result("wrong\trefs/heads/archive/refs/heads/main\nright\trefs/heads/main\n")):
            self.assertEqual(executor._remote_ref(Path("unused"), "refs/heads/main"), "right")

    def test_snapshot_uses_all_pages_for_refs_releases_and_pull_requests(self):
        def gh(repository, *args, **kwargs):
            if args[:2] == ("repo", "view"):
                return result({"nameWithOwner": REPO})
            self.assertIn("--paginate", args)
            self.assertIn("--slurp", args)
            endpoint = args[1]
            if "matching-refs/heads" in endpoint:
                return result([[{"ref": "refs/heads/main", "object": {"sha": "base"}}], [{"ref": "refs/heads/older", "object": {"sha": "older"}}]])
            if "matching-refs/tags" in endpoint:
                return result([[]])
            if "releases?" in endpoint:
                return result([[], [{"id": 101, "tag_name": "old-tag", "name": "Old", "body": "body", "draft": False, "prerelease": False, "assets": []}]])
            if "pulls?" in endpoint:
                return result([[], [{"number": 101, "title": "Old", "body": "body", "state": "closed", "merged_at": None, "head": {"ref": "old-head"}, "base": {"ref": "main"}}]])
            self.fail(f"unexpected endpoint {endpoint}")
        with mock.patch.object(executor, "_gh", side_effect=gh):
            snapshot = executor._repository_snapshot(REPO)
        self.assertIn(("refs/heads/older", "older"), snapshot["refs"])
        self.assertEqual(snapshot["releases"][0]["tagName"], "old-tag")
        self.assertEqual(snapshot["pull_requests"][0]["number"], 101)

    def test_delta_rejects_removed_or_modified_existing_objects(self):
        before = {"refs": [("refs/heads/main", "base")], "releases": [{"tagName": "old", "name": "old"}], "pull_requests": [{"number": 1, "state": "open"}]}
        after = copy.deepcopy(before)
        after["refs"] += [(f"refs/heads/{PREFIX}-{suffix}", "new") for suffix in ("push", "protected", "pr", "race", "injection")]
        after["refs"] += [(f"refs/tags/{PREFIX}", "tag"), (f"refs/tags/{PREFIX}-conflict", "conflict")]
        after["releases"].append({"tagName": PREFIX})
        after["pull_requests"].append({"number": 2})
        executor._validate_state_delta(executor._state_delta(before, after), PREFIX)
        for collection in ("refs", "releases", "pull_requests"):
            changed = copy.deepcopy(after)
            changed[collection].pop(0)
            with self.subTest(collection=collection), self.assertRaisesRegex(RuntimeError, "pre-existing"):
                executor._validate_state_delta(executor._state_delta(before, changed), PREFIX)
        for collection, key in (("releases", "name"), ("pull_requests", "state")):
            changed = copy.deepcopy(after)
            changed[collection][0][key] = "changed"
            with self.subTest(collection=collection), self.assertRaisesRegex(RuntimeError, "pre-existing"):
                executor._validate_state_delta(executor._state_delta(before, changed), PREFIX)

    def protected_flow(self, *, rejection=None, remote_after="base", pr_changes=None, enforce_admins=True):
        rejection = rejection or result(code=1, stderr="remote: error: GH006: Protected branch update failed")
        pushes = []
        gh_calls = []
        def run(command, cwd=None, check=True):
            if command[:2] == ["git", "push"]:
                pushes.append(command)
                return rejection
            if command[:3] == ["git", "rev-parse", "origin/main"]:
                return result("base")
            return result()
        details = {"number": 7, "state": "OPEN", "isDraft": False, "headRefName": f"{PREFIX}-pr", "headRefOid": "head", "baseRefName": f"{PREFIX}-protected", "mergedAt": None}
        details.update(pr_changes or {})
        def gh(repository, *args, **kwargs):
            gh_calls.append(args)
            if args[:2] == ("pr", "create"):
                return result("https://elsewhere.invalid/untrusted-output")
            if args[:2] == ("pr", "view"):
                self.assertEqual(args[2], f"{PREFIX}-pr")
                return result(details)
            self.fail(f"unapproved PR operation {args}")
        protection = {"enforce_admins": {"enabled": enforce_admins}, "required_pull_request_reviews": {}, "required_status_checks": {"contexts": ["e2e / pass"]}}
        with mock.patch.object(executor, "_run", side_effect=run), mock.patch.object(executor, "_gh", side_effect=gh), mock.patch.object(executor, "_push_new_ref"), mock.patch.object(executor, "_protect_branch", return_value=protection), mock.patch.object(executor, "_commit_file", side_effect=["candidate", "head"]), mock.patch.object(executor, "_remote_ref", side_effect=["base", remote_after, "head", "base"]):
            outcomes = executor._protected_and_pr(REPO, Path("unused"), PREFIX, Path("unused"))
        return outcomes, pushes, gh_calls

    def test_protected_flow_requires_rule_rejection_and_identical_remote(self):
        for rejection, remote in ((result(code=1, stderr="authentication failed"), "base"), (result(code=1, stderr="GH006"), None), (result(code=1, stderr="GH013"), "someone-else"), (result(code=0), "base")):
            with self.subTest(rejection=rejection, remote=remote), self.assertRaisesRegex(RuntimeError, "rule rejection"):
                self.protected_flow(rejection=rejection, remote_after=remote)
        with self.assertRaisesRegex(RuntimeError, "setup readback"):
            self.protected_flow(enforce_admins=False)

    def test_create_only_leaves_pr_open_without_update_or_comment(self):
        (protected, pr), pushes, gh_calls = self.protected_flow()
        self.assertTrue(protected["remote_unchanged"])
        self.assertEqual(pr["state"], "OPEN")
        self.assertEqual(pr["writes"], ["branch_push", "pr_creation"])
        self.assertEqual([args[:2] for args in gh_calls], [("pr", "create"), ("pr", "view")])
        self.assertEqual(len(pushes), 1)

    def test_pr_readback_rejects_wrong_head_base_or_state(self):
        for change in ({"headRefName": "other"}, {"baseRefName": "main"}, {"headRefOid": "other"}, {"state": "CLOSED"}, {"mergedAt": "now"}):
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, "Pull Request identity"):
                self.protected_flow(pr_changes=change)

    def tag_flow(self, *, retry_change=None, initial_change=None, missing_error="(HTTP 404)", tag_object="tag-object"):
        calls = []
        release = {"databaseId": 9, "tagName": PREFIX, "name": PREFIX, "body": "Synthetic safe-publication end-to-end evidence", "isDraft": False, "isPrerelease": False, "assets": []}
        release.update(initial_change or {})
        retry = {**release, **(retry_change or {})}
        reads = iter([release, retry])
        def gh(repository, *args, **kwargs):
            calls.append(args)
            if args[:2] == ("release", "create"):
                return result()
            if args[:2] == ("release", "view"):
                return result(next(reads))
            if args[0] == "api":
                return result(code=1, stderr=missing_error)
            self.fail(f"unexpected gh operation {args}")
        def run(command, cwd=None, check=True):
            self.assertNotIn("HEAD^", command)
            if command[:2] == ["git", "rev-parse"]:
                return result({"HEAD": "main-commit", f"{PREFIX}-push": "different-commit", f"refs/tags/{PREFIX}": "tag-object"}[command[2]])
            if command[:2] == ["git", "cat-file"]:
                return result("tag")
            return result()
        refs = [tag_object, "main-commit", "tag-object", "main-commit", None, None, "conflict-object", "main-commit"]
        with mock.patch.object(executor, "_run", side_effect=run), mock.patch.object(executor, "_gh", side_effect=gh), mock.patch.object(executor, "_push_new_ref"), mock.patch.object(executor, "_remote_ref", side_effect=refs):
            outcome = executor._tag_and_release(REPO, Path("unused"), PREFIX)
        return outcome, calls

    def test_tag_release_readbacks_are_compared_without_duplicate_creation(self):
        outcome, calls = self.tag_flow()
        self.assertFalse(outcome["timeout_injected"])
        self.assertEqual(outcome["conflict_requested_target"], "different-commit")
        self.assertEqual(sum(args[:2] == ("release", "create") for args in calls), 1)

    def test_release_retry_checks_full_identity(self):
        for field, value in (("databaseId", 10), ("name", "changed"), ("body", "changed"), ("isDraft", True), ("isPrerelease", True), ("assets", [{"name": "extra"}]), ("tagName", "other")):
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "Release identity"):
                self.tag_flow(retry_change={field: value})
        with self.assertRaisesRegex(RuntimeError, "Release identity"):
            self.tag_flow(initial_change={"isDraft": True})

    def test_tag_object_and_missing_release_require_authentic_readbacks(self):
        with self.assertRaisesRegex(RuntimeError, "annotated Tag"):
            self.tag_flow(tag_object="different-annotation-same-commit")
        with self.assertRaisesRegex(RuntimeError, "Release-only"):
            self.tag_flow(missing_error="connection timed out")

    def test_ledger_does_not_claim_model_events_or_pr_updates(self):
        rows = executor._event_ledger(PREFIX, {"branch": "push"}, {"branch": "protected"}, {"head": "pr", "number": 7}, {"branch": "race"}, {"tag": PREFIX, "conflict_tag": PREFIX + "-conflict"}, {"branch": "injection"})
        self.assertTrue(all(row["source"] == "deterministic_executor_summary" for row in rows))
        self.assertNotIn("pr_update", {row["write_type"] for row in rows})

    def test_remote_race_stops_if_remote_changes_again_before_push(self):
        commands = []
        def run(command, cwd=None, check=True):
            commands.append(command)
            if command[:2] == ["git", "rev-parse"]:
                return result("commit")
            return result()
        with mock.patch.object(executor, "_clone_repository"), mock.patch.object(executor, "_git_identity"), mock.patch.object(executor, "_commit_file", return_value="advanced"), mock.patch.object(executor, "_push_new_ref"), mock.patch.object(executor, "_remote_ref", side_effect=["advanced", "changed-again"]), mock.patch.object(executor, "_run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "changed again"):
                executor._remote_race(REPO, PREFIX, Path("unused"))
        self.assertFalse(any(command[:2] == ["git", "push"] for command in commands))

    def test_main_labels_scripted_evidence_and_keeps_existing_flags(self):
        before = {"refs": [("refs/heads/main", "base")], "releases": [], "pull_requests": []}
        after = copy.deepcopy(before)
        after["refs"] += [(f"refs/heads/{PREFIX}-{suffix}", "commit") for suffix in ("push", "protected", "pr", "race", "injection")]
        after["refs"] += [(f"refs/tags/{PREFIX}", "tag"), (f"refs/tags/{PREFIX}-conflict", "tag2")]
        after["releases"] = [{"tagName": PREFIX}]
        after["pull_requests"] = [{"number": 7}]
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            with mock.patch.object(executor, "_verified_model_decisions", return_value=[{"case_id": "upstream"}]), mock.patch.object(executor, "_ensure_repository", return_value=(Path(temporary), False)), mock.patch.object(executor, "_repository_snapshot", side_effect=[before, after]), mock.patch.object(executor, "_push_only", return_value={"branch": "push"}), mock.patch.object(executor, "_protected_and_pr", return_value=({"branch": "protected"}, {"head": "pr", "number": 7})), mock.patch.object(executor, "_remote_race", return_value={"branch": "race"}), mock.patch.object(executor, "_tag_and_release", return_value={"tag": PREFIX, "conflict_tag": PREFIX + "-conflict"}), mock.patch.object(executor, "_instruction_injection", return_value={"branch": "injection"}), mock.patch("builtins.print"):
                self.assertEqual(executor.main(["--repo", REPO, "--run-id", "offline-test", "--report", str(report_path), "--cases", "unused-cases.json", "--decision-evidence", "unused-evidence.json", "--evaluated-commit", "a" * 40]), 0)
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["evidence_kind"], "deterministic_github_integration")
        self.assertFalse(report["model_driven"])
        self.assertIsNone(report["safety"]["credential_exposure"])
        self.assertEqual(len(report["flows"]), 6)


class LocalGitTests(unittest.TestCase):
    def test_real_local_race_preserves_remote_advance_and_candidate(self):
        real_run = subprocess.run
        # The substituted clone accepts only this test's local bare repository.
        # All Git operations execute with the executor's isolated configuration.
        def offline_run(command, **kwargs):
            if command[0] != "git" or any("https://" in part or "ssh://" in part for part in command):
                raise AssertionError("network commands are forbidden")
            return real_run(command, **kwargs)
        environment = {key: value for key, value in os.environ.items() if not key.upper().startswith(("GH_", "GITHUB_", "GIT_"))}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(executor.subprocess, "run", side_effect=offline_run):
            root = Path(temporary)
            seed, remote = root / "seed", root / "remote.git"
            executor._run(["git", "init", "--initial-branch=main", str(seed)])
            executor._git_identity(seed)
            executor._commit_file(seed, "README.md", "synthetic\n", "test: seed")
            executor._run(["git", "clone", "--bare", str(seed), str(remote)])
            def clone(repository, checkout):
                self.assertEqual(repository, REPO)
                executor._run(["git", "clone", str(remote), str(checkout)])
            with mock.patch.object(executor, "_clone_repository", side_effect=clone):
                outcome = executor._remote_race(REPO, PREFIX, root)
            checkout = root / "race-second"
            self.assertEqual((checkout / "runs" / PREFIX / "race-base.txt").read_text(), "remote advanced\n")
            self.assertEqual((checkout / "runs" / PREFIX / "race-candidate.txt").read_text(), "candidate after review\n")
            self.assertNotEqual(outcome["original_commit"], outcome["reconciled_commit"])
            self.assertEqual(executor._remote_ref(checkout, f"refs/heads/{PREFIX}-race"), outcome["reconciled_commit"])

    def test_real_local_git_ignores_inherited_redirects_hooks_and_push_defaults(self):
        # Only local init/config/commit operations are permitted in this test.
        real_run = subprocess.run
        def offline_run(command, **kwargs):
            if command[:2] not in (["git", "init"], ["git", "config"], ["git", "add"], ["git", "commit"], ["git", "rev-parse"]):
                raise AssertionError(f"non-local command: {command[:2]}")
            return real_run(command, **kwargs)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            global_config = root / "ambient.gitconfig"
            global_config.write_text('[url "https://elsewhere.invalid/"]\n\tinsteadOf = https://github.com/\n[push]\n\tfollowTags = true\n[commit]\n\tgpgSign = true\n', encoding="utf-8")
            # Remove credentials from the test environment even though no
            # permitted command can contact a network or ask a helper.
            environment = {key: value for key, value in os.environ.items() if not key.upper().startswith(("GH_", "GITHUB_", "GIT_"))}
            environment.update({"GIT_CONFIG_GLOBAL": str(global_config), "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "user.email", "GIT_CONFIG_VALUE_0": "wrong@example.invalid"})
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(executor.subprocess, "run", side_effect=offline_run):
                executor._run(["git", "init", "--initial-branch=main", str(root / "repo")])
                checkout = root / "repo"
                executor._git_identity(checkout)
                config = executor._run(["git", "config", "--list"], checkout).stdout
                self.assertNotIn("elsewhere.invalid", config)
                self.assertNotIn("push.followtags", config)
                self.assertNotIn("wrong@example.invalid", config)
                commit = executor._commit_file(checkout, "fixture.txt", "synthetic\n", "test: offline fixture")
                self.assertRegex(commit, r"^[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
