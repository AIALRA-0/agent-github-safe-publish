# Global invocation policy

Use this policy in the user-level `AGENTS.md` when every Codex task on the machine must load the same GitHub publication boundary

## 1. Required behavior

- Before any task may push, publish, upload, sync, mirror, open-source, or create or update a GitHub Release, invoke `$github-safe-publish`
- Treat Chinese requests such as `推送`、`发布`、`上传`、`同步`、`镜像`、`开源` and `全量发布` as the same publication intent
- The trigger depends on the intended external transfer, even when the user does not mention privacy, sanitization, redaction, or the Skill name
- Read-only GitHub inspection and a purely local commit with no planned remote transfer do not trigger this policy
- Loading the Skill alone does not authorize a GitHub write; an explicit publication request authorizes only its exact ordinary target, branch, write types, degradation ceiling, expiry, and idempotency key
- Keep the source read-only, turn every unsafe finding into remediation, and continue changing the isolated candidate until it is certified or reaches a resumable `needs_input`, `retryable_failure`, `internal_error`, or `operator_attention` state
- Publish only the exact signed candidate whose authorization remains valid; legacy `allow` and `allow_with_risk` decisions do not replace v2 certification
- When the Skill, private policy, object coverage, digest-bound Gitleaks runtime, container isolation, or signing trust is unavailable, preserve the private checkpoint and do not touch the remote

## 2. Enforcement boundary

This instruction makes the behavior mandatory for Codex tasks that load the user-level `AGENTS.md`

Repository rulesets or branch protection remain necessary when the GitHub remote must reject writes from clients that do not load Codex instructions
