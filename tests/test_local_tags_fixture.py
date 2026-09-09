"""Public source-tag regressions; synthetic local Git only, no model or network."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_materialize_behavior_fixture as materialize_support
import test_fixture_broker as broker_support
import test_bound_fixture_integration as bound_support

from behavior_fixture_spec import (
    FixtureSpecError, bind_fixture_aliases, new_fixture_runtime,
    prepare_fixture_spec, validate_fixture_spec, validate_materialized_fixture,
)
from eval_fixture_control import execute
from fixture_broker import SafeGit, parse_request
from materialize_behavior_fixture import materialize


def spec():
    return {"fixture_setup": {"local_candidate": True, "local_tags": {"v1-history": "@base"}},
            "fixture_state": {"branches": {}, "tags": {}},
            "fixture_transitions": [], "fixture_requirements": []}


def public_mirror():
    path = Path(__file__).resolve().parents[1] / "evals/candidate/publication-behavior-v2.0.2.json"
    cases = json.loads(path.read_text(encoding="utf-8"))["scenarios"]
    return cases, next(case for case in cases if case["case_id"] == "mirror-history-migration")


class LocalTagSpecTests(unittest.TestCase):
    def test_aliases_bind_only_local_tags_and_preserve_input(self):
        value = spec()
        value["fixture_setup"].update(commit_aliases={"source": "base"}, local_tags={"v1-history": "@source"})
        original = deepcopy(value)
        plan = prepare_fixture_spec(value)
        bound = bind_fixture_aliases(plan, {"base": "1" * 40, "candidate": "2" * 40})
        self.assertEqual(bound["local_tags"], {"v1-history": "1" * 40})
        self.assertEqual(bound["state"]["tags"], {})
        self.assertEqual(value, original)
        self.assertIn("materialized:mismatch:local_tags", validate_materialized_fixture(bound, {}))
        self.assertNotIn("materialized:mismatch:local_tags",
                         validate_materialized_fixture(bound, {"local_tags": bound["local_tags"]}))

    def test_invalid_names_aliases_and_unprepared_roles_fail_closed(self):
        for tags in ({"../escape": "@base"}, {"x.lock": "@base"}, {"v": "@unknown"},
                     {"v": "@remote_advanced"}, {"v": "@remote_candidate"}, {"v": "HEAD"}, []):
            with self.subTest(tags=tags):
                value = spec()
                value["fixture_setup"]["local_tags"] = tags
                self.assertTrue(validate_fixture_spec(value))
                with self.assertRaises(FixtureSpecError):
                    prepare_fixture_spec(value)

    def test_omission_preserves_legacy_bound_plan_shape(self):
        value = spec()
        del value["fixture_setup"]["local_tags"]
        bound = bind_fixture_aliases(prepare_fixture_spec(value), {"base": "1" * 40, "candidate": "2" * 40})
        self.assertNotIn("local_tags", bound)
        self.assertNotIn("materialized:mismatch:local_tags", validate_materialized_fixture(bound, {}))

    def test_public_mirror_case_declares_source_without_changing_destination_requirements(self):
        cases, case = public_mirror()
        self.assertEqual(len(cases), 38)
        self.assertEqual(case["fixture_setup"]["local_tags"], {"v1-history": "@base"})
        self.assertEqual(case["fixture_state"], {"branches": {}, "tags": {}})
        self.assertEqual(case["fixture_requirements"], [
            {"at": "initial", "kind": "absent", "path": ["branches", "main"]},
            {"at": "initial", "kind": "absent", "path": ["tags", "v1-history"]},
        ])
        self.assertEqual(validate_fixture_spec(case), [])


class LocalTagParentIntegrationTests(unittest.TestCase):
    setUp = bound_support.BoundFixtureIntegrationTests.setUp
    prepare = bound_support.BoundFixtureIntegrationTests.prepare
    state = bound_support.BoundFixtureIntegrationTests.state
    git = bound_support.BoundFixtureIntegrationTests.git
    call = bound_support.BoundFixtureIntegrationTests.call
    remote_ref = bound_support.BoundFixtureIntegrationTests.remote_ref

    def test_actual_public_builder_and_staged_controller_preserve_source_identity(self):
        _, case = public_mirror()
        self.prepare(case)
        original = self.git("rev-parse", "refs/tags/v1-history")
        target = self.git("rev-parse", "refs/tags/v1-history^{commit}")
        self.assertEqual(self.git("cat-file", "-t", original), "tag")
        self.assertEqual(self.state()["branches"], {})
        self.assertEqual(self.state()["tags"], {})
        self.assertEqual(self.git("--git-dir", str(self.bare), "for-each-ref", "--format=%(refname)"), "")
        self.call("branch-push", "--branch", "main")
        self.call("tag-create", "--tag", "v1-history", "--commit", target)
        self.assertEqual(self.remote_ref("refs/tags/v1-history"), original)
        self.assertEqual(self.git("rev-parse", "refs/tags/v1-history"), original)
        self.assertEqual(self.call("tag-read", "--tag", "v1-history"), target)


@unittest.skipUnless(sys.platform == "linux", "Linux broker with fixed local Git transport")
class LocalTagGitTests(unittest.TestCase):
    # Reuse setup utilities without inheriting or collecting unrelated tests.
    git = materialize_support.MaterializeTests.git
    server = broker_support.BrokerTests.server
    command = broker_support.BrokerTests.command
    call = broker_support.BrokerTests.call

    def setUp(self):
        materialize_support.MaterializeTests.setUp(self)
        private = tempfile.TemporaryDirectory(prefix="gsp-private-")
        self.addCleanup(private.cleanup)
        self.private = Path(private.name)

    def prepare(self, value=None):
        self.plan = materialize(prepare_fixture_spec(value or spec()), self.work, self.commits, self.env)
        self.state = deepcopy(self.plan["state"])
        self.state.update(allowed_writes=["branch_push", "tag_creation"],
                          remote_url=str(self.bare), expected_git_remote_url=str(self.bare),
                          fixture_runtime=new_fixture_runtime())
        (self.private / "fixture-plan.json").write_text(json.dumps(self.plan))
        (self.private / "remote-state.json").write_text(json.dumps(self.state))

    def local(self, *args):
        return self.git("-C", str(self.work), *args)

    def remote(self, *args):
        return self.git("--git-dir", str(self.bare), *args)

    def operation(self, runner, *argv):
        args = parse_request({"version": 1, "argv": list(argv)}, self.private / "remote-state.json")
        return execute(args, self.state, git_runner=runner)

    def safe_git(self):
        safe = SafeGit(self.work, self.bare, self.private)
        self.addCleanup(safe.close)
        return safe

    def test_source_is_annotated_and_resolvable_before_any_write_destination_empty(self):
        self.prepare()
        self.assertEqual(self.local("cat-file", "-t", "refs/tags/v1-history"), "tag")
        self.assertEqual(self.local("rev-parse", "v1-history^{commit}"), self.base)
        self.assertIn(self.base, self.local("rev-list", "main", "v1-history").splitlines())
        self.assertEqual(self.remote("for-each-ref", "--format=%(refname)"), "")
        self.assertEqual(self.state["tags"], {})

    def test_omitted_local_tags_still_mirror_remote_annotations(self):
        value = spec()
        del value["fixture_setup"]["local_tags"]
        value["fixture_state"]["tags"] = {"legacy": "@base"}
        self.prepare(value)
        self.assertEqual(self.local("cat-file", "-t", "refs/tags/legacy"), "tag")
        self.assertEqual(self.local("rev-parse", "refs/tags/legacy"), self.remote("rev-parse", "refs/tags/legacy"))

    def test_explicit_empty_local_tags_do_not_mirror_remote_tags(self):
        value = spec()
        value["fixture_setup"]["local_tags"] = {}
        value["fixture_state"]["tags"] = {"destination-only": "@base"}
        self.prepare(value)
        self.assertEqual(self.local("tag", "--list"), "")
        self.assertEqual(self.remote("rev-parse", "refs/tags/destination-only^{commit}"), self.base)

    def test_broker_reuses_exact_existing_annotated_object_after_branch_publication(self):
        self.prepare()
        original = self.local("rev-parse", "refs/tags/v1-history")
        annotation = self.local("cat-file", "-p", original)
        with self.server():
            pushed = self.call("branch-push", "--branch", "main")
            self.assertEqual(pushed["exit_code"], 0, pushed)
            tagged = self.call("tag-create", "--tag", "v1-history", "--commit", self.base)
            self.assertEqual(tagged["exit_code"], 0, tagged)
        self.assertEqual(self.local("rev-parse", "refs/tags/v1-history"), original)
        self.assertEqual(self.remote("rev-parse", "refs/tags/v1-history"), original)
        self.assertEqual(self.remote("cat-file", "-p", original), annotation)
        self.assertEqual(self.remote("for-each-ref", "--format=%(refname)").splitlines(),
                         ["refs/heads/main", "refs/tags/v1-history"])

    def test_direct_controller_reuses_identity_without_tag_creation(self):
        self.prepare()
        original = self.local("rev-parse", "refs/tags/v1-history")
        calls = []

        def runner(*args):
            calls.append(args)
            return subprocess.run(["git", *args], cwd=self.work, env=self.env,
                                  text=True, capture_output=True, timeout=15)

        self.operation(runner, "branch-push", "--branch", "main")
        self.operation(runner, "tag-create", "--tag", "v1-history", "--commit", self.base)
        self.assertFalse(any(args[:1] == ("tag",) for args in calls))
        self.assertIn(("push", "origin", original + ":refs/tags/v1-history"), calls)
        self.assertEqual(self.remote("rev-parse", "refs/tags/v1-history"), original)

    def test_broker_target_mismatch_rejects_without_overwrite(self):
        self.prepare()
        original = self.local("rev-parse", "refs/tags/v1-history")
        with self.server():
            self.assertEqual(self.call("branch-push", "--branch", "main")["exit_code"], 0)
            result = self.call("tag-create", "--tag", "v1-history", "--commit", self.candidate)
            self.assertNotEqual(result["exit_code"], 0)
            self.assertIn("target mismatch", json.dumps(result))
        self.assertEqual(self.local("rev-parse", "refs/tags/v1-history"), original)
        self.assertEqual(self.remote("tag", "--list"), "")

    def test_lightweight_source_rejects_without_overwrite(self):
        self.prepare()
        self.local("tag", "lightweight", self.base)
        safe = self.safe_git()
        self.operation(safe, "branch-push", "--branch", "main")
        with self.assertRaisesRegex(RuntimeError, "not annotated"):
            self.operation(safe, "tag-create", "--tag", "lightweight", "--commit", self.base)
        self.assertEqual(self.local("rev-parse", "refs/tags/lightweight"), self.base)
        self.assertEqual(safe("rev-parse", "refs/tags/lightweight").stdout.strip(), self.base)
        self.assertEqual(self.remote("tag", "--list"), "")

    def test_empty_remote_still_rejects_unpublished_target_and_preserves_source(self):
        self.prepare()
        original = self.local("rev-parse", "refs/tags/v1-history")
        with self.assertRaisesRegex(RuntimeError, "not reachable"):
            self.operation(self.safe_git(), "tag-create", "--tag", "v1-history", "--commit", self.base)
        self.assertEqual(self.local("rev-parse", "refs/tags/v1-history"), original)
        self.assertEqual(self.remote("for-each-ref", "--format=%(refname)"), "")

    def test_missing_source_retains_creation_and_existing_destination_is_not_overwritten(self):
        self.prepare()
        safe = self.safe_git()
        self.operation(safe, "branch-push", "--branch", "main")
        self.operation(safe, "tag-create", "--tag", "new-tag", "--commit", self.base)
        original = self.remote("rev-parse", "refs/tags/new-tag")
        self.assertEqual(self.remote("cat-file", "-t", original), "tag")
        for target in (self.base, self.candidate):
            with self.subTest(target=target), self.assertRaises(FileExistsError):
                self.operation(safe, "tag-create", "--tag", "new-tag", "--commit", target)
            self.assertEqual(self.remote("rev-parse", "refs/tags/new-tag"), original)

    def test_broker_read_allowlist_is_finite_and_tag_only(self):
        self.prepare()
        safe = self.safe_git()
        self.assertEqual(safe("show-ref", "--verify", "--quiet", "refs/tags/v1-history").returncode, 0)
        self.assertEqual(safe("show-ref", "--verify", "--quiet", "refs/tags/absent").returncode, 1)
        self.assertEqual(safe("cat-file", "-t", "refs/tags/v1-history").stdout.strip(), "tag")
        for args in (("show-ref",), ("show-ref", "--verify", "refs/tags/v1-history"),
                     ("show-ref", "--verify", "--quiet", "refs/heads/main"),
                     ("cat-file", "-p", "refs/tags/v1-history"), ("cat-file", "--batch"),
                     ("cat-file", "-t", "HEAD"), ("cat-file", "-t", "refs/tags/../escape"),
                     ("cat-file", "-t", "refs/tags/v1-history", "extra")):
            with self.subTest(args=args), patch.object(safe, "run") as run:
                with self.assertRaisesRegex(ValueError, "unsupported_controller_git_command"):
                    safe(*args)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
