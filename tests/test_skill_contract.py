from pathlib import Path
import re
import subprocess
import sys
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class SkillInvocationContractTests(unittest.TestCase):
    def test_implicit_invocation_is_enabled(self) -> None:
        metadata = (REPOSITORY_ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertRegex(metadata, r"(?m)^\s*allow_implicit_invocation:\s*true\s*$")
        self.assertIn("$github-safe-publish", metadata)

    def test_discovery_description_covers_remote_publication_intents(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        frontmatter = skill.split("---", 2)[1]
        description_match = re.search(r"(?m)^description:\s*(.+)$", frontmatter)
        self.assertIsNotNone(description_match)
        description = description_match.group(1).lower()
        for intent in ("push", "publish", "upload", "sync", "mirror", "open-source", "release"):
            with self.subTest(intent=intent):
                self.assertIn(intent, description)

    def test_discovery_description_covers_chinese_publication_intents(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        frontmatter = skill.split("---", 2)[1]
        description_match = re.search(r"(?m)^description:\s*(.+)$", frontmatter)
        self.assertIsNotNone(description_match)
        description = description_match.group(1)
        for intent in ("推送", "发布", "上传", "同步", "镜像", "开源", "全量发布"):
            with self.subTest(intent=intent):
                self.assertIn(intent, description)

    def test_global_policy_fails_closed_before_remote_write(self) -> None:
        policy = (REPOSITORY_ROOT / "references" / "global-invocation-policy.md").read_text(encoding="utf-8")
        self.assertIn("$github-safe-publish", policy)
        self.assertIn("record the result as `incomplete`", policy)
        self.assertIn("exact publication copy receives `allow` or `allow_with_risk`", policy)
        self.assertIn("explicitly authorizes the GitHub write", policy)
        for intent in ("推送", "发布", "上传", "同步", "镜像", "开源", "全量发布"):
            with self.subTest(intent=intent):
                self.assertIn(intent, policy)

    def test_skill_routes_local_audit_and_policy_compilation(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("`audit-local`", skill)
        self.assertIn("`compile-policy`", skill)
        self.assertIn("repository-associated", skill)

    def test_skill_preserves_strict_audit_and_graded_publication(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("`decision` remains the strict audit result", skill)
        self.assertIn("`publication_decision`", skill)
        self.assertIn("`permissive-noncritical`", skill)
        self.assertIn("`strict` profile", skill)
        self.assertIn("never override credentials", skill)
        self.assertIn("`result_explanation`", skill)

    def test_direct_default_branch_publication_requires_explicit_authorization_and_fast_forward(self) -> None:
        skill = (REPOSITORY_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("explicitly requests that exact route", skill)
        self.assertIn("fast-forward", skill)
        self.assertIn("exact gate permits publication", skill)

    def test_repository_workflow_never_receives_private_policy(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "reusable-safe-publish.yml").read_text(encoding="utf-8")
        self.assertNotIn("SAFE_PUBLISH_POLICY_B64", workflow)
        self.assertIn("--generic-only", workflow)

    def test_stable_version_interface(self) -> None:
        result = subprocess.run(
            [sys.executable, str(REPOSITORY_ROOT / "scripts" / "safe_publish.py"), "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual("github-safe-publish 1.1.7", result.stdout.strip())

    def test_reusable_workflow_accepts_only_public_inputs(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "reusable-safe-publish.yml").read_text(encoding="utf-8")
        call_block = workflow.split("workflow_call:", 1)[1].split("permissions:", 1)[0]
        self.assertIn("tool_ref:", call_block)
        self.assertIn("shadow:", call_block)
        self.assertNotIn("secrets:", call_block)
        self.assertNotIn("SAFE_PUBLISH_POLICY_B64", workflow)

    def test_runtime_locks_platform_specific_opencv(self) -> None:
        requirements = (REPOSITORY_ROOT / "requirements-gate.txt").read_text(encoding="utf-8")
        expected = (
            'Pillow==12.3.0',
            'numpy==2.5.2',
            'opencv-python==4.14.0.94; sys_platform == "win32"',
            'opencv-python-headless==4.14.0.94; sys_platform != "win32"',
            'pypdf==6.16.2',
            'PyMuPDF==1.28.2',
            'cryptography==50.0.1',
        )
        for requirement in expected:
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, requirements)

    def test_official_actions_use_full_commit_identifiers(self) -> None:
        workflow_paths = sorted((REPOSITORY_ROOT / ".github" / "workflows").glob("*.yml"))
        action_line = re.compile(r"uses:\s+((?:actions|github)/[^@]+)@([^\s]+)")
        for workflow_path in workflow_paths:
            workflow = workflow_path.read_text(encoding="utf-8")
            for action, revision in action_line.findall(workflow):
                with self.subTest(workflow=workflow_path.name, action=action):
                    self.assertRegex(revision, r"^[0-9a-f]{40}$")


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

    def test_colon_led_nested_lists_increase_indentation(self) -> None:
        for document in self._documents():
            lines = document.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines[:-1]):
                match = re.match(r"^(\s*)-\s+.*[:：]\s*$", line)
                if not match:
                    continue
                following = next((item for item in lines[index + 1:] if item.strip()), "")
                nested = re.match(r"^(\s*)-\s+", following)
                if nested:
                    with self.subTest(document=document.name, line=index + 1):
                        self.assertGreater(len(nested.group(1)), len(match.group(1)))

    def test_multi_node_publication_flow_uses_mermaid(self) -> None:
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        match = re.search(r"```mermaid\s+(.*?)```", readme, re.DOTALL)
        self.assertIsNotNone(match)
        diagram = match.group(1)
        self.assertIn("flowchart TD", diagram)
        self.assertGreaterEqual(diagram.count("-->"), 3)
        self.assertIn("图 2.1", readme[match.end():])

    def test_stable_release_documents_and_license_exist(self) -> None:
        required = ("LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md")
        for name in required:
            with self.subTest(name=name):
                self.assertTrue((REPOSITORY_ROOT / name).is_file())
        license_text = (REPOSITORY_ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("MIT License", license_text)
        self.assertIn("Copyright (c) 2026 AIALRA-0", license_text)
        for readme_name in ("README.md", "README.en.md"):
            readme = (REPOSITORY_ROOT / readme_name).read_text(encoding="utf-8")
            self.assertIn("v1.1.7", readme)
            self.assertIn("SECURITY.md", readme)
            self.assertIn("CONTRIBUTING.md", readme)
            self.assertIn("CHANGELOG.md", readme)


if __name__ == "__main__":
    unittest.main()
