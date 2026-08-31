---
name: github-safe-publish
description: Audit, sanitize, repair, verify, certify, and publish a safe repository derivative whenever a task may push, publish, upload, sync, mirror, open-source, or create or update a GitHub Release, including 推送、发布、上传、同步、镜像、开源 and 全量发布; use exposure mode for separate read-only fleet investigations
---

# GitHub Safe Publication Compiler

Convert an unsafe source project into a safe public derivative and publish the exact certified candidate; do not treat unsafe source content as a terminal failure

Stable legacy interface: `1.1.7`

Current compiler preview: `2.0.0-beta.1`

## 1. Product contract

- Load this Skill as soon as a task may transfer repository content or artifacts to GitHub
- Treat the original publication request as authorization for the declared ordinary publication transaction; loading the Skill alone does not create a broader write authorization
- Keep the source repository read-only and build a separate candidate outside it
- Map every unresolved `SourceFinding` to a `RemediationAction` or a resumable `needs_input` state
- Replace, externalize, parameterize, synthesize, rebuild, rename, repair references, remove, or stub any object that cannot safely enter the candidate
- Never publish by lowering severity, adding a wildcard approval, accepting private risk, or silently skipping an unreadable object
- Validate the functional contract and independently rescan the candidate after transformation
- Require the digest-bound Gitleaks 8.30.1 runtime to detect its synthetic canary and scan the complete candidate with full redaction
- Return a rejected candidate to the remediation planner; `deny` is not a v2 business terminal state
- Certify only when the candidate has zero unresolved security findings, complete coverage, a clean Git worktree, and an authorized `none` or `minor` degradation
- Continue from `certified` to publication while the original authorization remains valid
- Accept `published` as the only normal successful terminal state

Read [the v2 product contract](docs/architecture/PRODUCT_CONTRACT.md), [threat model](docs/architecture/THREAT_MODEL.md), and [architecture](docs/architecture/ARCHITECTURE_V2.md) before changing the workflow model

## 2. Choose the v2 command

- `run` performs snapshot, inspection, planning, sanitization, repair, validation, verification, certification, publication, and remote object verification
- `inspect` evaluates the bound source snapshot without creating a candidate
- `plan` maps findings to actions and reports owner decisions
- `sanitize` creates or continues the isolated candidate without publishing it
- `verify` runs the isolated functional contract, rescans the candidate, and signs an exact certification
- `publish` accepts only a signed certified candidate and an unexpired exact authorization
- `status` reports the current checkpoint without changing it
- `resume` recomputes source, policy, candidate, authorization, and remote bindings before continuing
- `exposure local` and `exposure fleet` run separate exposure investigations that never decide the result of one publication

Use Policy v4 for the compiler; versions 1, 2, and 3 may migrate in memory, but repository-controlled files cannot broaden private rules, signing trust, degradation permission, or remote scope

Create the private signing key with `keygen`; create a new non-overwriting private policy with `policy-init`, including the Gitleaks path, private temporary root, digest-pinned container image, functional commands, exact target, and authorized workflow or Release scope

## 3. Candidate and remediation rules

Use `new-publication` by default for first publication; create a new public root commit and never copy the private `.git` history

Use `update-existing-public` only from the exact public remote base; overlay the safe public tree without importing private history

Use `history-migration` only after separate authorization for history rewriting; inspect every commit, tag, note, signature, author, LFS entity, and submodule binding before a non-force migration or separately authorized force update

Automatic degradation may be only `none` or `minor`; optional real data, caches, internal demos, fixtures, or auxiliary resources may be removed when Policy v4 names their exact paths

Enter `needs_input` for a `major` or `skeleton` degradation, unknown publication rights, protected legal records, a required unsupported object, or a necessary private integration with no safe replacement

Treat the following files as protected legal records and never rewrite them automatically:

- `LICENSE`
- `NOTICE`
- `CITATION`
- copyright and third-party attribution records

An LFS pointer without a verified safe entity cannot enter the candidate; remove the pointer and its matching rule only when the object is explicitly optional

A private submodule must become a public replacement, a reviewed vendor snapshot, or an optional removed component with repaired references

## 4. Isolation and certification

Treat source projects as untrusted input; validation that executes project code requires a working container sandbox and may not fall back to an ordinary host process

Require the validation container to have:

- a digest-pinned, pre-fetched image
- no network
- a read-only root filesystem and candidate mount
- all Linux capabilities removed
- `no-new-privileges`
- bounded processes, memory, CPU, runtime, and temporary space
- a numeric non-root user
- no Docker Socket
- no GitHub, SSH, cloud, private-policy, or publication environment variables

Sign certification with an OS-protected Ed25519 private key; the trusted publisher must use a separately configured public-key fingerprint rather than trusting a key supplied by the certification itself

Bind certification to the exact candidate commit, tree, index, patch, Policy v4 digest, tool version, Gitleaks runtime, validation evidence, per-object coverage, degradation, authorization receipt, target repository, target branch, and expected remote base

An exact source-audit receipt may reuse completed deep coverage only for the same source commit, tree, object digest, scanner, policy, report, expiry, and review trigger; it may classify an ambiguous public example, but it never suppresses a high-confidence credential or a private entity named by Policy v4

Write the private publication proof as an in-toto Statement carrying an SLSA Verification Summary predicate; the proof describes only the fixed candidate, policy, tools, and coverage that were verified

## 5. Trusted publication

- The publisher receives only the candidate, certification, authorization, and preconfigured trust root; it never reads source private values
- The publisher never executes project code
- Verify authorization expiry, idempotency key, write type, maximum degradation, target repository, branch, expected base, workflow scope, and Release scope
- Re-read the remote branch immediately before writing
- Use a non-force push and read the remote commit and tree after publication
- Treat a repeated transaction whose remote already equals the certified commit and tree as an idempotent success
- Enter `retryable_failure` for temporary network or GitHub failure without weakening any binding

Push directly to the default branch only when the current user explicitly requests that exact route, the update is fast-forward, and the signed certification plus bound authorization permit publication; otherwise follow the repository's approved review route

Force-pushing, rewriting an existing public history, deleting a Release or branch, rotating a credential, and changing organization rules require separate authorization

## 6. Legacy v1 compatibility

Keep the legacy interface until v2 stable so existing repositories can continue bounded audits and incident response

- Exact legacy publication uses `prepare` and `gate`
- Local exposure investigation may still use `audit-local`
- Fleet exposure investigation may still use `audit-fleet --surface-profile repository-associated`
- Repository-scoped legacy policy output may still use `compile-policy`
- Runtime diagnosis may still use `doctor`
- `managed-publish` may create a review branch but never auto-merge

For legacy reports, `decision` remains the strict audit result and `publication_decision` controls only that legacy candidate; read `result_explanation` for count source, match reason, publication effect, and next step

The default legacy profile is `permissive-noncritical`; the `strict` profile allows only a strict audit pass

Legacy exact approvals and risk acceptances never override credentials, private identity, real data, protected legal records, critical infrastructure, or critical coverage gaps

Read [the private policy contract](references/private-policy.md), [gate and incident handling](references/gate-and-incident.md), and [recovery contract](references/recovery.md) before using legacy approval, incident, or resume behavior

## 7. Evidence and incidents

Keep raw candidates, private policy, signing keys, checkpoints, detailed findings, and publication attestations outside the repository in the approved private storage root

Do not print private values or their public hashes in stdout, stderr, GitHub Actions logs, commits, pull requests, Issues, Releases, or public summaries

If a credential may still be valid or was already public, revoke or rotate it before repository cleanup; removing it from the current tree does not invalidate the secret or retract old clones

Repository-controlled GitHub Actions run public generic checks only; they cannot receive the private policy or independently authorize publication

Exposure results authorize no deletion, remediation, history rewriting, credential rotation, or GitHub write
