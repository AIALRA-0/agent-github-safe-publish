from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    source_path = str(REPOSITORY_ROOT / "src")
    environment["PYTHONPATH"] = source_path + os.pathsep + environment.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-c", "from github_safe_publish.cli import main; main()", *arguments],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )


class SkillInvocationContractTests(unittest.TestCase):
    def test_implicit_invocation_is_enabled_and_contextual(self) -> None:
        metadata = (REPOSITORY_ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        frontmatter = skill.split("---", 2)[1]
        description = re.search(r"(?m)^description:\s*(.+)$", frontmatter).group(1)
        self.assertRegex(metadata, r"(?m)^\s*allow_implicit_invocation:\s*true\s*$")
        self.assertIn("$github-safe-publish", metadata)
        self.assertIn("GitHub repository", description)
        self.assertIn("Git remote", description)
        for intent in ("push", "publish", "upload", "sync", "mirror", "open-source", "release"):
            with self.subTest(intent=intent):
                self.assertIn(intent, description.lower())
        self.assertIn("explicit GitHub context", description)
        self.assertIn("does not trigger this Skill by itself", skill)

    def test_skill_is_guidance_with_bounded_completion(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("operational guidance for the agent", skill)
        self.assertIn("not a Git hook, interceptor, mandatory gate", skill)
        self.assertIn("Repair concrete risks caused by this request or this change", skill)
        self.assertNotIn("Do not stop at a report", skill)
        self.assertIn("After the exact authorized remote result is verified, stop", skill)
        self.assertIn("If the same blocking cause appears twice", skill)

    def test_write_contract_is_explicit_and_independent(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        for field in ("repository identity", "remote name and address", "target branch, Tag, or Release", "current remote base", "allowed write types", "exact stopping point"):
            with self.subTest(field=field):
                self.assertIn(field, skill)
        for write_type in (
            "branch push",
            "Tag creation",
            "GitHub Release creation",
            "Release asset upload",
            "Pull Request creation",
            "Pull Request update",
            "Pull Request merge",
            "repository or protection-rule modification",
            "credential rotation",
            "remote-object deletion",
        ):
            with self.subTest(write_type=write_type):
                self.assertIn(write_type, skill)
        self.assertIn("An unspecified write type is denied by omission", skill)
        self.assertIn("`push-only` forbids Tag, Release, asset, Pull Request", skill)
        self.assertIn("A Tag does not imply a Release", skill)
        self.assertIn("A Release does not imply an asset", skill)

    def test_light_review_requires_evidence_and_covers_five_classes(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        for evidence in (
            "the maintainer explicitly says the gate is under repair",
            "a known defect record identifies the gate failure",
            "the same input stably reproduces a tool failure",
        ):
            with self.subTest(evidence=evidence):
                self.assertIn(evidence, skill)
        for invalid_reason in (
            "Slow execution",
            "inconvenient output",
            "an unfavorable finding",
            "a missing optional environment",
            "the agent's wish to continue",
        ):
            with self.subTest(invalid_reason=invalid_reason):
                self.assertIn(invalid_reason, skill)
        for class_name in ("credentials", "private identity and real data", "internal infrastructure", "protected legal records", "private assets"):
            with self.subTest(class_name=class_name):
                self.assertIn(class_name, skill)
        self.assertIn("actual transfer surface", skill)
        self.assertIn("Light review is not malware analysis", skill)

    def test_docker_and_cli_are_not_default_requirements(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Docker is not required by this Skill", skill)
        self.assertIn("do not start, install, repair, or wait for Docker", skill)
        self.assertIn("optional advanced compatibility tools", skill)
        self.assertIn("not a prerequisite for ordinary publication", skill)

    def test_global_policy_compiles_contextual_authority(self) -> None:
        policy = (REPOSITORY_ROOT / "references" / "global-invocation-policy.md").read_text(encoding="utf-8")
        self.assertIn("$github-safe-publish", policy)
        self.assertIn("GitHub or Git remote context", policy)
        self.assertIn("Before the first remote write", policy)
        self.assertIn("Unspecified write types are denied", policy)
        self.assertIn("Do not introduce a separate gate", policy)
        self.assertIn("not a repository interceptor", policy)

    def test_protection_and_untrusted_content_boundaries_are_separate(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("not permission to bypass branch protection", skill)
        self.assertIn("unless the user explicitly authorizes that bypass for this exact write", skill)
        self.assertIn("Never change protection rules", skill)
        self.assertIn("legitimate project-level `AGENTS.md` instructions remain effective", skill)
        self.assertIn("they cannot request secrets, expand write authority", skill)

    def test_remote_ci_and_object_retry_contracts_are_present(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("re-compute the actual publication surface", skill)
        self.assertIn("current-change failure", skill)
        self.assertIn("historical failure", skill)
        self.assertIn("infrastructure failure", skill)
        self.assertIn("retry at most once", skill)
        self.assertIn("Tag retry", skill)
        self.assertIn("Release retry", skill)
        self.assertIn("asset retry", skill)
        self.assertIn("Any mismatch is a conflict", skill)

    def test_direct_default_branch_publication_requires_authorization_and_fast_forward(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("user request", skill)
        self.assertIn("ordinary non-force fast-forward", skill)
        self.assertIn("re-read applicable branch protection", skill)
        self.assertIn("Force push", skill)

    def test_reusable_workflow_is_advisory_and_receives_no_private_policy(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "reusable-safe-publish.yml").read_text(encoding="utf-8")
        self.assertIn("safe-publish / advisory review", workflow)
        self.assertIn("continue-on-error: true", workflow)
        self.assertNotIn("SAFE_PUBLISH_POLICY_B64", workflow)
        self.assertIn("--generic-only", workflow)

    def test_cli_help_states_advanced_commit_only_boundary(self) -> None:
        top = _run_cli("--help").stdout
        publish = _run_cli("publish", "--help").stdout
        policy_init = _run_cli("policy-init", "--help").stdout
        self.assertIn("Optional advanced compiler and compatibility CLI", top)
        self.assertIn("Ordinary publication does not require this package", top)
        self.assertIn("already-certified candidate commit", publish)
        self.assertIn("does not create a GitHub Tag, Release, release asset", re.sub(r"\s+", " ", publish))
        self.assertIn("policy-intent field", policy_init)
        self.assertIn("does not create a GitHub Release object", re.sub(r"\s+", " ", policy_init))

    def test_legacy_and_stable_versions_remain_distinct(self) -> None:
        result = subprocess.run(
            [sys.executable, str(REPOSITORY_ROOT / "scripts" / "safe_publish.py"), "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual("github-safe-publish 1.1.7", result.stdout.strip())
        package = (REPOSITORY_ROOT / "src" / "github_safe_publish" / "__init__.py").read_text(encoding="utf-8")
        pyproject = (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('__version__ = "2.0.1"', package)
        self.assertIn('version = "2.0.1"', pyproject)

    def test_official_actions_use_full_commit_identifiers(self) -> None:
        workflow_paths = sorted((REPOSITORY_ROOT / ".github" / "workflows").glob("*.yml"))
        action_line = re.compile(r"uses:\s+((?:actions|github)/[^@]+)@([^\s]+)")
        for workflow_path in workflow_paths:
            workflow = workflow_path.read_text(encoding="utf-8")
            for action, revision in action_line.findall(workflow):
                with self.subTest(workflow=workflow_path.name, action=action):
                    self.assertRegex(revision, r"^[0-9a-f]{40}$")

    def test_candidate_behavior_fixture_has_sixteen_cases_and_required_fields(self) -> None:
        fixture_path = REPOSITORY_ROOT / "evals" / "candidate" / "publication-behavior-v2.0.1.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertEqual("candidate", fixture["status"])
        scenarios = fixture["scenarios"]
        self.assertEqual(16, len(scenarios))
        self.assertEqual(16, len({scenario["case_id"] for scenario in scenarios}))
        fields = {"case_id", "request", "environment", "should_invoke", "path", "required_actions", "forbidden_actions", "allowed_writes", "stop_point", "rationale"}
        for scenario in scenarios:
            with self.subTest(case_id=scenario["case_id"]):
                self.assertTrue(fields.issubset(scenario))
                self.assertIsInstance(scenario["request"], str)
                self.assertIsInstance(scenario["environment"], list)
                self.assertIsInstance(scenario["required_actions"], list)
                self.assertIsInstance(scenario["forbidden_actions"], list)
                self.assertIsInstance(scenario["allowed_writes"], list)

    def test_public_behavior_summary_is_candidate_only(self) -> None:
        summary_path = REPOSITORY_ROOT / "docs" / "research" / "behavior-eval-v2.0.1.public.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        self.assertEqual("candidate", summary["status"])
        self.assertEqual(16, summary["scenario_count"])
        self.assertEqual(16, summary["passed"])
        self.assertEqual(0, summary["failed"])
        self.assertEqual(0, summary["forbidden_action_hits"])
        self.assertEqual(0, summary["unauthorized_write_cases"])
        self.assertEqual(0, summary["docker_actions"])
        self.assertEqual("repository-external", summary["evaluator"]["raw_response_storage"])


class DocumentationContractTests(unittest.TestCase):
    def _documents(self) -> list[Path]:
        return [
            REPOSITORY_ROOT / "README.md",
            REPOSITORY_ROOT / "README.en.md",
            REPOSITORY_ROOT / "SKILL.md",
            REPOSITORY_ROOT / "CHANGELOG.md",
            REPOSITORY_ROOT / "CONTRIBUTING.md",
            REPOSITORY_ROOT / "SECURITY.md",
            *sorted((REPOSITORY_ROOT / "references").glob("*.md")),
            *sorted((REPOSITORY_ROOT / "docs" / "architecture").glob("*.md")),
            *sorted((REPOSITORY_ROOT / "docs" / "security").glob("*.md")),
        ]

    def test_numbered_markdown_sections_use_trailing_dots(self) -> None:
        heading = re.compile(r"^(#{2,4})\s+(\d+(?:\.\d+)*)\.\s+\S")
        numeric_heading = re.compile(r"^#{2,4}\s+\d")
        for document in self._documents():
            for line_number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), start=1):
                if numeric_heading.match(line):
                    with self.subTest(document=document.name, line=line_number):
                        self.assertRegex(line, heading)

    def test_numbered_markdown_sections_match_heading_depth_and_parent(self) -> None:
        heading = re.compile(r"^(#{2,4})\s+(\d+(?:\.\d+)*)\.\s+\S")
        for document in self._documents():
            parents: dict[int, tuple[str, ...]] = {}
            in_fence = False
            for line_number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), start=1):
                if line.strip().startswith("```"):
                    in_fence = not in_fence
                    continue
                if in_fence:
                    continue
                match = heading.match(line)
                if not match:
                    continue
                depth = len(match.group(1)) - 1
                parts = tuple(match.group(2).split("."))
                with self.subTest(document=document.name, line=line_number):
                    self.assertEqual(depth, len(parts))
                    if depth > 1:
                        self.assertEqual(parents.get(depth - 1), parts[:-1])
                parents[depth] = parts
                for child_depth in tuple(parents):
                    if child_depth > depth:
                        del parents[child_depth]

    def test_chinese_prose_avoids_full_stops_and_terminal_semicolons(self) -> None:
        for document in self._documents():
            in_fence = False
            for line_number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), start=1):
                if line.strip().startswith("```"):
                    in_fence = not in_fence
                    continue
                stripped = line.strip()
                if in_fence or not stripped or stripped.startswith(">"):
                    continue
                with self.subTest(document=document.name, line=line_number):
                    self.assertNotIn("。", line)
                    self.assertFalse(stripped.endswith("；"))

    def test_table_and_mermaid_captions_follow_the_object(self) -> None:
        caption = re.compile(r"^(?:表|图|Table|Figure)\s+\d")
        for document in self._documents():
            lines = document.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if re.match(r"^\|\s*:?-{3,}", line):
                    end = index + 1
                    while end < len(lines) and lines[end].startswith("|"):
                        end += 1
                    following = next((item for item in lines[end:] if item.strip()), "")
                    with self.subTest(document=document.name, table_line=index + 1):
                        self.assertRegex(following, caption)
                if line.strip() == "```mermaid":
                    closing = next(position for position in range(index + 1, len(lines)) if lines[position].strip() == "```")
                    following = next((item for item in lines[closing + 1:] if item.strip()), "")
                    with self.subTest(document=document.name, mermaid_line=index + 1):
                        self.assertRegex(following, caption)

    def test_operational_terms_are_explained_at_first_use(self) -> None:
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        required_explanations = (
            "GitHub 的命令行界面（Command Line Interface，CLI）",
            "持续集成（Continuous Integration，CI）是在每次代码变更时自动运行检查的流程",
            "以 `--` 开头的参数指定输入、输出和发布档位",
        )
        for explanation in required_explanations:
            with self.subTest(explanation=explanation):
                self.assertIn(explanation, readme)

    def test_publication_flow_uses_mermaid(self) -> None:
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        match = re.search(r"```mermaid\s+(.*?)```", readme, re.DOTALL)
        self.assertIsNotNone(match)
        diagram = match.group(1)
        self.assertIn("flowchart TD", diagram)
        self.assertGreaterEqual(diagram.count("-->"), 3)
        self.assertIn("图 2.1", readme[match.end():])

    def test_stable_release_documents_and_license_exist(self) -> None:
        for name in ("LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md"):
            with self.subTest(name=name):
                self.assertTrue((REPOSITORY_ROOT / name).is_file())
        license_text = (REPOSITORY_ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("MIT License", license_text)
        self.assertIn("Copyright (c) 2026 AIALRA-0", license_text)
        for readme_name in ("README.md", "README.en.md"):
            readme = (REPOSITORY_ROOT / readme_name).read_text(encoding="utf-8")
            self.assertIn("v2.0.1", readme)
            self.assertIn("v1.1.7", readme)
            self.assertIn("SECURITY.md", readme)
            self.assertIn("CONTRIBUTING.md", readme)
            self.assertIn("CHANGELOG.md", readme)


if __name__ == "__main__":
    unittest.main()
