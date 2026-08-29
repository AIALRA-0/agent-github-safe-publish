from pathlib import Path
import re
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

    def test_repository_workflow_never_receives_private_policy(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "reusable-safe-publish.yml").read_text(encoding="utf-8")
        self.assertNotIn("SAFE_PUBLISH_POLICY_B64", workflow)
        self.assertIn("--generic-only", workflow)


if __name__ == "__main__":
    unittest.main()
