# Publication recovery

## 1. v2 bound resume

`resume` reloads the private checkpoint and recomputes the source snapshot, Policy v4 digest, candidate binding, signing trust and publication authorization before continuing

The resumable states are:

- `needs_input`
  - Public rights, legal provenance, required-object handling or major degradation needs an owner decision
  - A changed Policy v4 preserves the prior candidate and evidence under a numbered private revision before rebuilding
- `retryable_failure`
  - Candidate construction, GitHub, network or another external dependency failed temporarily
  - A pre-certification retry preserves the failed workflow under a numbered private retry; a post-certification retry reuses the same signed candidate and idempotency key
- `internal_error`
  - A parser, transformer, convergence or evidence invariant failed
  - Repair the tool and resume the same bound checkpoint; do not lower coverage
- `operator_attention`
  - Candidate, authorization, workflow scope or remote Base differs from the certified transaction
  - Reconcile the exact object before any new publication attempt

`cancelled`, `superseded` and `legal_hold` are administrative terminal states; `resume` returns them unchanged and performs no work

## 2. Remote recovery

The publisher rereads the exact branch immediately before a non-force push; a changed Base produces `operator_attention`, while a temporary read or push failure produces `retryable_failure`

A repeated transaction whose remote Commit and Tree already equal the certified object is an idempotent success; the same idempotency key cannot authorize another candidate

Do not reuse certification after rebasing, amending, changing a workflow, changing the Policy, changing Gitleaks, changing the functional contract or changing the remote target

## 3. Evidence preservation

Source candidates, policies, keys, detailed findings, revisions, retries, certifications, authorizations and attestations remain under the approved private root

No recovery path deletes an earlier candidate or report automatically; private evidence can be removed only under the owner’s retention decision after the publication and incident boundary is understood

## 4. Legacy checkpoints

The v1 working tree, Git history and OCR layers continue to use separate content-bound checkpoints and bounded time slices

Legacy `incomplete`, `deny`, `SCANNER_CRASHED`, `GATE_REPORT_MISSING` and Git-history timeout results describe one old gate candidate; they do not become v2 terminal publication states

## 5. Incident boundary

A credential that may still be valid or may already be public must be revoked or rotated before repository cleanup

History rewriting, force-pushing, cache cleanup, Fork coordination, Release replacement, credential rotation and organization-rule changes require separate authorization and their own recovery plan
