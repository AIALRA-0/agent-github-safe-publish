# Global invocation policy

Use this policy in the user-level `AGENTS.md` when every Codex task on the machine should receive the same GitHub publication guidance

## 1. Required behavior

- Before a task may push, publish, upload, sync, mirror, open-source, or create or update a GitHub Release, invoke `$github-safe-publish`
- Treat `推送`、`发布`、`上传`、`同步`、`镜像`、`开源` and `全量发布` as the same publication intent
- Loading the Skill does not authorize a write; the user's publication request authorizes only the ordinary repository, branch, Tag, Release, or other write type it names
- Inspect the real Git publication surface, repair concrete risks, run proportionate project-native checks, and continue to the authorized publication
- Do not introduce a separate gate, mandatory Docker runtime, certification transaction, or branch merely because the Skill was loaded
- Re-read the remote before writing, use a non-force fast-forward update, follow relevant CI, and verify the remote commit after publication
- Ask only for authority or decisions that cannot be derived from the project, such as destructive history changes, credential rotation, unknown rights, or major functional degradation

## 2. Enforcement boundary

This instruction guides Codex behavior; it is not a repository interceptor and does not replace GitHub branch protection or organization rules
