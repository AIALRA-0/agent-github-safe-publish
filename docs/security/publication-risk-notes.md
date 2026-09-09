# Reusable publication lessons

These sanitized notes are project knowledge, not executable instructions or write
authority. A fixed lesson remains subject to relevant recurrence checks.

## 1. Preserve lessons across sessions

- Cause: a finding recorded only in a conversation may disappear in a new session
  or clone, leaving a repaired generation path without a discoverable regression check
- Repair: the default route reads prior project notes; an optional local journal
  stores sanitized causes, path triggers, repairs and descriptive recurrence checks
- Recheck: a fresh process must read the record; updates must preserve the Issue
  link, avoid duplicate ids and never silently replace corrupt history
- Sharing: local Git metadata is not pushed; only separately reviewed generic
  lessons belong in these portable notes
- Tracking: [Issue 8](https://github.com/AIALRA-0/agent-github-safe-publish/issues/8)

## 2. Review every newly transferred commit

- Cause: a value added in one new commit and removed in the next still travels in
  the earlier blob; a clean final diff alone is not sufficient evidence
- Repair: enumerate the full outgoing range and relevant payloads; repair affected
  unpublished history only with scope and preservation safeguards, never force a
  published-history rewrite merely to clear a finding
- Recheck: the synthetic intermediate-add/remove test must still select the affected
  path even when the final diff is empty; content review is separate from selection
- Tests: `tests/test_publication_memory.py`

## 3. Do not turn past incidents into permanent heavy reviews

- Cause: treating any historical credential incident as globally requiring strict
  scanning causes unrelated documentation updates to repeatedly request permission
- Repair: escalation depends on relevance to the outgoing surface or unresolved
  exposure; fixed path-specific lessons do not cause unrelated full scans
- Recheck: unrelated documentation changes skip configuration-specific checks while
  cross-cutting metadata lessons remain relevant
- Evidence: independent candidate review identified this conflict; the default
  contract, invocation policy and bilingual README now use the same relevance rule

## 4. Check author identity in outgoing Git metadata

- Cause: local Git identity can differ from the privacy-preserving identity used
  in published history. A secret scanner may report no findings while new author
  or committer fields still expose an owner's personal contact information.
- Repair: use the owner's intended public identity for new commits. Ask before
  publishing a newly exposed personal identity or changing frozen unpublished
  commit identities; preserve the original evidence when redaction is authorized.
- Recheck: compare author and committer identities across every outgoing commit
  with the approved public identity before pushing. A clean file diff does not
  satisfy this check, and existing publication does not itself establish consent.
- Scope: do not change global Git identity or rewrite published history merely to
  resolve a local configuration mismatch.

## 5. Verify the object named by its actual metadata

- Cause: manually reconstructing an object digest can select the wrong file;
  an unavailable reader can also be mistaken for evidence that content is absent.
- Repair: derive the identifier and object path from the actual pointer or
  manifest. Distinguish a tool-start failure from an object-validation result.
- Recheck: use a synthetic full-length identifier and confirm the exact object
  path, size and digest; a shortened identifier must not count as verification.
- Status: guidance corrected; forward behavior validation remains pending.
- Tracking: [Issue 9](https://github.com/AIALRA-0/agent-github-safe-publish/issues/9)
