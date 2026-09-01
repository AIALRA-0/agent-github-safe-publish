---
name: github-safe-publish
description: Guide Codex through safe GitHub push, publish, upload, sync, mirror, open-source, Release, 推送、发布、上传、同步、镜像、开源 and 全量发布 work; review and repair the real project, then complete the authorized publication without turning safety into a blocking gate
---

# GitHub Safe Publish

Help Codex finish a safe GitHub publication

This is operational guidance for the agent, not an interceptor, mandatory checker, or separate release platform

Stable Skill version: `2.0.0`

## 1. Default workflow

When the user asks to publish, continue through review, repair, verification, push, CI follow-up, and Release work until the authorized result is live

1. Confirm the actual repository, active worktree, branch, remote, requested write type, and current Git state from the environment
2. Review the content that will really transfer, including staged, unstaged, untracked, ignored-but-referenced, generated, binary, LFS, submodule, history, tag, and Release surfaces when they are relevant
3. Turn each concrete risk into a repair in the project or a separate sanitized candidate
4. Run the project's existing tests, linters, builds, and available secret scan in proportion to the change
5. Re-read the remote branch immediately before writing, allow only an ordinary fast-forward update, then push and read back the remote commit
6. Wait for relevant CI and security checks, repair failures in the same authorized workstream, and publish the requested Tag or Release only after the target commit is green

Do not stop at a report when the issue can be safely repaired within the user's request

## 2. Repair instead of gate

- Remove or externalize credentials and private configuration, synthesize example data, strip metadata, repair references, and keep required public behavior working
- Keep the user's preferred simple Git shape; do not create extra branches, worktrees, checkpoints, policies, signatures, or audit loops unless the repository or requested publication genuinely needs them
- Preserve `LICENSE`, `NOTICE`, `CITATION`, copyright, and third-party attribution unless the user or verified rights information authorizes a change
- Ask for the minimum owner decision only when publication rights are unknown, a required private component has no safe replacement, or the repair would cause a major product change
- A finding is work to resolve, not a reason to abandon the publication

## 3. Use normal project tools

Prefer tools already used by the repository and platform

- Git status, diff, history, attributes, submodules, LFS, and remote refs establish the actual publication surface
- Repository-native tests, linters, builds, and GitHub checks establish functional confidence
- Gitleaks or another available secret scanner may supplement review, but no single scanner replaces reading the actual diff and files
- If a repository already uses a strict publication gate whose heavyweight review is defective or under repair, replace that run with a light critical-content review of credentials, private identity and data, internal infrastructure, and protected legal or private assets; publish after those critical risks are repaired and project checks pass, while reporting the limited coverage honestly
- Docker is not required by this Skill; do not start, install, repair, or wait for Docker merely because the Skill was loaded
- The bundled Python CLI is optional compatibility tooling for users who explicitly want its compiler, policy, exposure, or legacy report features; it is not a prerequisite for ordinary publication

Read the architecture and policy references only when the user explicitly asks to use or change that optional CLI workflow

## 4. Authority and safety boundaries

An explicit push or publication request authorizes the ordinary target and write types it names; it does not authorize unrelated repositories or destructive recovery

- Never print real secret values, private source values, or reversible secret fingerprints in public output
- Do not force-push, rewrite published history, delete remote branches, tags, or Releases, rotate credentials, or change organization rules without separate authorization
- If a credential may still be valid, remove it from the publication surface and report the required owner action; perform external rotation only when separately authorized
- Direct publication to the default branch is allowed when the user requested that route and the update is fast-forward
- If the remote advanced, stop the write, fetch, and reconcile the new state without overwriting it

## 5. Finish

The normal successful end state is the requested content published to the exact remote target

Report the local commit, remote commit, checks run, CI result, Tag or Release when applicable, remaining owner actions if any, and whether the worktree is clean
