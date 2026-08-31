# Managed publication contract

This document describes the v1 compatibility command; v2 uses `run`, signed certification, and the trusted publisher described in `SKILL.md`

## 1. Trigger

Use `managed-publish` only after the user authorizes a GitHub push, publication, synchronization, mirror, open-source transfer, or Release operation

The command has no schedule and performs no periodic audit

## 2. Inputs and private state

The caller supplies the source repository, GitHub repository name, current base commit, repository-external private policy, private output directory, validation commands, README auditor, and publication intent

The private checkpoint binds the base commit, candidate Git tree object, candidate index SHA-256, binary patch SHA-256, scanner SHA-256, policy fingerprint, report fingerprint, and validation outcomes

Before the exact gate starts, the orchestrator writes a fail-closed report placeholder. A scanner exception produces `SCANNER_CRASHED`; a missing or unchanged gate report produces `GATE_REPORT_MISSING`. Both outcomes are atomic `incomplete` checkpoints and stop every remote action

`--resume` may reuse only the isolated candidate in the same private output directory. A changed source base, policy, scanner, or candidate produces a new fingerprint and requires a new gate

## 3. Publication decisions

<div align="center">

| Decision | Remote action |
|---|---|
| `allow` | Create a branch and pull request for review; never merge automatically |
| `allow_with_risk` | Create a branch and pull request for human review; never merge automatically |
| `deny` | Keep evidence local and perform no remote write |
| `incomplete` | Keep evidence local and repair the missing parser, validation, or coverage |

表 3.1 各发布结论对应的远程操作

</div>

The command never pushes directly to the default branch and never uses an administrator bypass

On Windows, validation runs through a noninteractive PowerShell wrapper that returns the inner native exit code. A PowerShell command failure without a native exit code returns `1`

## 4. Legacy merge boundary

Version 1.1.7 removes `--intent auto-merge`; the legacy command can audit or create a pull request, but it cannot merge that pull request

Version 2 replaces this path with a trusted publisher that accepts only a signed certification bound to the candidate, authorization, target, and expected remote base

History rewriting, Release replacement, ruleset changes, credential rotation, and destructive cleanup remain separate owner-approved operations
