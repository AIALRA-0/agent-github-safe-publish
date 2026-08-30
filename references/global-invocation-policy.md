# Global invocation policy

Use this policy in the user-level `AGENTS.md` when every Codex task on the machine must load the same GitHub publication boundary

## 1. Required behavior

- Before any task may push, publish, upload, sync, mirror, open-source, or create or update a GitHub Release, invoke `$github-safe-publish`
- Treat Chinese requests such as `推送`、`发布`、`上传`、`同步`、`镜像`、`开源` and `全量发布` as the same publication intent
- The trigger depends on the intended external transfer, even when the user does not mention privacy, sanitization, redaction, or the Skill name
- Read-only GitHub inspection and a purely local commit with no planned remote transfer do not trigger this policy
- Loading the Skill does not authorize a GitHub write
- Stop before the write when the Skill, private policy, declared object coverage, or required scanner is unavailable, and record the result as `incomplete`
- Continue only when the exact publication copy receives `allow` or `allow_with_risk` under the selected release profile and the current task explicitly authorizes the GitHub write

## 2. Enforcement boundary

This instruction makes the behavior mandatory for Codex tasks that load the user-level `AGENTS.md`

Repository rulesets or branch protection remain necessary when the GitHub remote must reject writes from clients that do not load Codex instructions
