# Managed publication contract

## 1 Trigger

Use `managed-publish` only after the user authorizes a GitHub push, publication, synchronization, mirror, open-source transfer, or Release operation

The command has no schedule and performs no periodic audit

## 2 Inputs and private state

The caller supplies the source repository, GitHub repository name, current base commit, repository-external private policy, private output directory, validation commands, README auditor, and publication intent

The private checkpoint binds the base commit, candidate Git tree object, candidate index SHA-256, binary patch SHA-256, scanner SHA-256, policy fingerprint, report fingerprint, and validation outcomes

`--resume` may reuse only the isolated candidate in the same private output directory. A changed source base, policy, scanner, or candidate produces a new fingerprint and requires a new gate

## 3 Publication decisions

| Decision | Remote action |
|---|---|
| `allow` | Create a branch and pull request; auto-merge only after required checks and branch governance pass |
| `allow_with_risk` | Create a pull request for human review and never auto-merge |
| `deny` | Keep evidence local and perform no remote write |
| `incomplete` | Keep evidence local and repair the missing parser, validation, or coverage |

The command never pushes directly to the default branch and never uses an administrator bypass

## 4 Auto-merge boundary

Auto-merge requires a strict `allow`, complete project and README validation, an unchanged remote base, an exact remote tree match, and required status checks enforced by branch protection or an active ruleset

Missing governance returns `BRANCH_PROTECTION_MISSING` after the pull request is created. It does not weaken the gate or merge the pull request

History rewriting, Release replacement, ruleset changes, credential rotation, and destructive cleanup remain separate owner-approved operations
