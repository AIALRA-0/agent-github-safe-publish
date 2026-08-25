---
name: github-safe-publish
description: Audit, sanitize, and gate a repository before an authorized GitHub publication. Use when code, history, LFS objects, release assets, metadata, or generated artifacts may expose credentials, personal identifiers, private infrastructure, databases, or embedded document metadata.
---

# GitHub Safe Publish

Use one policy and one fail-closed decision model for every repository publication. Keep detection, proposed edits, approval, and external writes as separate actions.

## 1 Authorization boundary

- Read-only auditing does not authorize a push, release change, history rewrite, ruleset change, or secret rotation.
- Confirm that the current task explicitly authorizes the exact GitHub write immediately before performing it.
- Never rewrite authors, tags, signatures, `LICENSE`, `NOTICE`, `CITATION`, history, or an existing GitHub Release automatically.
- Treat a credential found in public history as an incident. Revoke or rotate it before considering repository cleanup.
- Require repository-specific approval before history rewriting, force-pushing, cache cleanup, or replacing a Release asset.

## 2 Required separation

- Inspect the private source in place only with read-only operations.
- Write raw candidates only below `CODEX_HOME/private/github-safe-publish/`. Never show raw candidates in chat, logs, public reports, or GitHub Actions artifacts.
- Load the private policy from outside the repository. A repository file cannot broaden an allow rule.
- Create a disposable publication copy from an exact source commit. Apply approved replacements only in that copy.
- Keep scanning credentials separate from publishing. Enable write credentials only after `gate` returns `pass`.

## 3 Decision model

Run `scripts/safe_publish.py gate` against the publication copy, its Git history, and any proposed Release assets.

- `pass` means every declared surface was readable and no unresolved finding remains. Only this decision permits the publication workflow to continue.
- `review` means an information owner must classify a candidate.
- `block` means a confirmed rule violation must be removed or approved through an exact, expiring exception.
- `incomplete` means the policy, access, object, dependency, or file-format coverage was insufficient.

The command exits successfully only for `pass`. Treat `review`, `block`, and `incomplete` as publication failures.

## 4 Sensitive information

Check credentials, account identifiers, names, aliases, email addresses, phone numbers, detailed addresses, personal sites, avatars, QR codes, contacts, UIDs, device IDs, URLs, domains, IP addresses, MAC addresses, hostnames, ports, cloud resource names, absolute local paths, remote addresses, deployment topology, databases, dumps, backups, real records, messages, calendars, locations, browser data, logs, HAR files, crash files, prompts, Agent transcripts, and full tool output.

Also inspect image pixels and metadata, PDF and Office properties, Notebook outputs, archives, LFS objects, submodule URLs, repository metadata, and GitHub Release assets. Mark encrypted archives, oversized objects, missing LFS data, unreadable objects, and unsupported binary formats as `incomplete`.

Treat `LICENSE`, `NOTICE`, `CITATION`, copyright, third-party authorship, and provenance as protected legal records. Findings there require review and must never trigger automatic replacement.

## 5 Workflow

- For a repository fleet audit, run `audit-fleet`. Read [fleet-audit.md](references/fleet-audit.md) before configuring the owner and private output locations.
- To build a locally reviewable raw-candidate file, run `policy-candidates`. Read [private-policy.md](references/private-policy.md) before the information owner approves mappings and exceptions.
- To create a disposable publication copy, run `prepare` with an exact commit and an explicit `clean-root` or `preserve-history` mode.
- Before publication, run `gate`. Read [gate-and-incident.md](references/gate-and-incident.md) for decision precedence, Release assets, and incident handling.

Pin Gitleaks to v8.30.1. The helper downloads the official release artifact, verifies it against the release checksum file, and requests fully redacted output.

## 6 Replacement rules

- Replace approved private identities consistently with synthetic values such as `ExampleOrg`, `ExampleUser`, `example.invalid`, and stable synthetic IDs.
- Store explicit synthetic mappings in the private policy. Never derive replacements by hashing private values.
- Allow a private identifier only at an exact approved object location or through an exact, expiring exception.
- Preserve third-party attribution and legal provenance for manual review.
- Delete private candidate files and detailed reports after the information owner confirms remediation. Keep only aggregate statistics without paths or identifiers.

## 7 Continuous integration

- Inject the trimmed private policy through the `SAFE_PUBLISH_POLICY_B64` GitHub Actions Secret.
- Treat a missing Secret, invalid Base64, unknown policy version, or encoded value larger than 48 KB as `incomplete`.
- Fork pull requests and Dependabot events run public generic checks only. They cannot receive a full `pass`; reproduce the exact commit on a trusted branch or local machine for the complete gate.
- Start in shadow mode. Require an out-of-band repository-owner decision before enabling a ruleset or branch protection requirement.
