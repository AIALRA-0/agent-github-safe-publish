---
name: github-safe-publish
description: Audit, sanitize, and gate repository content before it is sent to GitHub. Use whenever a task may push, publish, upload, sync, mirror, open-source, or create or update a GitHub Release, including Chinese requests such as 推送、发布、上传、同步、镜像、开源、全量发布, even when the user does not mention privacy or redaction. Do not use for read-only GitHub inspection or a purely local commit with no planned remote transfer.
---

# GitHub Safe Publish

Use one private policy and two explicit decisions across Agents: a strict audit result and a publication result that permits only reviewed noncritical risk. Keep periodic exposure discovery separate from the exact gate for an intended publication

## 1 Mandatory publication boundary

- Invoke this Skill as soon as a task may transfer repository content or artifacts to GitHub
- Loading the Skill never authorizes a write
- Before a write, create an isolated copy from the exact source commit and run `gate` against its working tree, visible Git history, LFS entities, submodules, and proposed Release assets
- Exact gates limit each Git-history slice to 900 seconds by default and save a private resumable checkpoint. Resume only when the repository, source commit, complete object inventory, scanner, and policy bindings still match
- Read both results from the exact copy: `decision` remains the strict audit result, while `publication_decision` controls the separately authorized write
- The default `permissive-noncritical` profile continues only for `allow` or `allow_with_risk`; `deny` stops the write
- Use the `strict` profile for high-sensitivity repositories, incident response, or final red-team review; it permits only a strict audit `pass`
- Read [the global invocation policy](references/global-invocation-policy.md) when installing or validating fleet-wide discovery

## 2 Choose the operating mode

- Exact publication: use `prepare` and `gate`; this is the only mode whose `publication_decision` can permit a separately authorized write
- Managed publication: use `managed-publish` only after explicit GitHub write authorization; it creates an isolated candidate, runs declared validations, executes the exact gate, and routes the result through a pull request. Read [the managed publication contract](references/managed-publish.md)
- Runtime diagnosis: use the read-only `doctor --source <repository>` before a gate, or `doctor --all` when validating a maintained runtime. Read [the runtime contract](references/runtime.md)
- Repository candidate discovery: use `policy-candidates`; raw values stay below `CODEX_HOME/private/github-safe-publish/`
- Local exposure audit: use `audit-local` for accessible Codex sessions and saved project roots; read [the local audit contract](references/local-audit.md)
- Fleet exposure audit: use `audit-fleet --surface-profile repository-associated --resume`; read [the fleet audit contract](references/fleet-audit.md)
- Policy distribution: use `compile-policy` to create a repository-scoped v3 policy from the private master policy

Periodic exposure audit results describe existing risk. They never authorize deletion, remote remediation, history rewriting, credential rotation, or publication

## 3 Private policy and evidence

- Load private policy from outside the source repository; repository-controlled files cannot broaden approvals
- Version 3 adds exact, expiring `risk_acceptances`; versions 1 and 2 remain readable through in-memory migration
- Exact binary approvals record object, digest, inspection layers, scanner versions, reviewer, reason, and review trigger
- Exact exceptions record rule, object, approver, reason, expiry, and review trigger
- Risk acceptances additionally lock the repository, whole-object SHA-256, scanner SHA-256, and `content-or-scanner-change` trigger
- Risk acceptances apply only to the fixed noncritical rule matrix and never override credentials, private identifiers, legal records, real data, critical infrastructure, or critical coverage gaps
- Never print, upload, hash into a public report, or place raw candidates in GitHub Actions
- Read [the private policy contract](references/private-policy.md) before candidate approval or policy compilation

## 4 Required inspection behavior

Check credentials, personal and contact information, addresses, sites, accounts, UIDs, device identifiers, URLs, domains, IP and MAC addresses, host names, ports, cloud resources, local paths, databases, backups, real records, logs, prompts, Agent transcripts, and full tool output

Inspect Git reference names, annotated tags, notes, author and committer data, signature payloads, historical submodule configuration, image metadata and pixels, QR and barcode payloads, PDF text and page images, Office embedded media and macros, Notebook output, archives, audio and video metadata plus extractable subtitles, attachments and cover art, binary format data and strings, LFS objects, repository metadata, collaboration content, retained automation output, and Release assets when the selected mode declares those surfaces

Apply Unicode normalization and bounded decoding only as declared by the private policy. Never turn generic name recognition into an automatic replacement rule

Unsupported formats, missing parsers, encrypted or oversized objects, missing LFS data, incomplete history, pagination failure, permission denial, and unavailable declared surfaces still produce the strict audit result `incomplete`

A Git-history time limit returns `incomplete` and publication `deny` for that slice while preserving redacted progress below `CODEX_HOME/private/github-safe-publish/`. A later identical run resumes from the saved object index. An invalid checkpoint or any binding mismatch also returns `incomplete` and `deny`; never delete or replace a stale checkpoint implicitly

For exact publication, failures in the working tree, Git history, LFS, submodules, proposed Release assets, private policy, or Gitleaks remain critical and produce publication `deny`. A declared auxiliary remote surface that is not transferred by the exact publication may produce `allow_with_risk`

Image OCR uses a bounded per-repository runtime budget. Budget exhaustion is a coverage gap and produces `incomplete`; a partial pixel scan never permits publication

Local session files run in isolated child processes with a 600-second default budget. A child crash, timeout, invalid result, or candidate-collection limit produces `incomplete` for the affected audit and must not terminate or pass the remaining fleet

Gitleaks uses both its 300-second internal limit and a 330-second parent-process timeout. Canary timeout, repository timeout, nonstandard exit, or an invalid report produces `incomplete`

Treat `LICENSE`, `NOTICE`, `CITATION`, copyright, third-party authorship, and provenance as protected legal records. They require exact human review and are never replaced automatically

## 5 Incident and mutation boundary

- A credential that may remain valid or has been public is an incident; revoke or rotate it before repository cleanup
- Require repository-specific approval for history rewriting, force-pushing, cache cleanup, Release replacement, ruleset changes, and credential rotation
- Never rewrite authors, tags, signatures, legal records, history, or an existing Release automatically
- Read [gate and incident handling](references/gate-and-incident.md) before any publication decision or credential response

## 6 Continuous integration

Repository-controlled GitHub Actions run public generic rules only and remain shadow evidence. They cannot receive the private master policy or return publication `allow`

The local trusted gate is authoritative until a separately approved trusted execution environment exists. A repository owner must approve any later ruleset or branch-protection requirement out of band

## 7 Managed pull requests

- Never push directly to the default branch and never use an administrator bypass
- `allow_with_risk` may create a pull request after explicit authorization, but it never auto-merges
- `allow` may auto-merge only when project checks, README checks, an unchanged base, an exact remote tree match, and required branch governance all pass
- Missing branch protection or required checks returns `BRANCH_PROTECTION_MISSING` and leaves the pull request for review
- A resumed run must recompute all bound fingerprints; read [the recovery contract](references/recovery.md) before retrying a partial remote operation
