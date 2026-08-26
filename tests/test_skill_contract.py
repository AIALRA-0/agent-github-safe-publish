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

    def test_global_policy_fails_closed_before_remote_write(self) -> None:
        policy = (REPOSITORY_ROOT / "references" / "global-invocation-policy.md").read_text(encoding="utf-8")
        self.assertIn("$github-safe-publish", policy)
        self.assertIn("record the result as `incomplete`", policy)
        self.assertIn("exact publication copy receives `pass`", policy)
        self.assertIn("explicitly authorizes the GitHub write", policy)


if __name__ == "__main__":
    unittest.main()
