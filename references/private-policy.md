# Private policy contract

## 1. Storage boundary

Keep Policy v4, signing keys, source-audit receipts, checkpoints, candidates, detailed findings, certifications, authorizations, and attestations under an absolute repository-external private root

The compiler rejects a private output directory below the source repository and refuses to overwrite an active workflow; repository-controlled files cannot broaden remediation, retention, signing trust, degradation, or remote write scope

Raw values, original private paths, value-derived hashes, and detailed object mappings may exist only in private evidence; public reports contain aggregate action counts and documented degradation without source identifiers

## 2. Policy v4 fields

Every Policy v4 document contains these top-level fields:

- `publication`
- `sensitive_entities`
- `synthetic_mappings`
- `remediation_defaults`
- `object_rules`
- `retention_rules`
- `history_strategy`
- `functional_contract`
- `degradation_policy`
- `validation`
- `security_runtime`
- `remote_target`

`publication` declares the candidate mode, allowed write types, idempotency key, authorization expiry, workflow and Release scope, and trusted certification-key fingerprint

`sensitive_entities` contains confirmed private literals or bounded regular expressions; regular expressions are length-limited and reject groups, lookarounds, backreferences, unbounded repetition, and broad wildcard constructs

`synthetic_mappings` assigns explicit stable public values to entity IDs; never derive a replacement from a private value by hashing

`remediation_defaults` maps each finding category to a real action such as `externalize`, `replace`, `parameterize`, `synthesize`, `strip-metadata`, `repack`, `remove-and-stub`, or `needs-owner-decision`

`object_rules` addresses one exact repository-relative path; wildcards, absolute paths, traversal, and a rename target that already exists are invalid

`retention_rules` may retain an object only when the evidence binds the exact object digest, scanner set, policy digest, issuer, issue time, expiry time, and review trigger; retention proves that an object was already public, not that a private object may bypass remediation

`history_strategy` must match the publication mode:

- `new-publication` uses `new-root`
- `update-existing-public` uses `public-base-overlay`
- `history-migration` uses `full-migration` and separate authorization

`functional_contract` lists the commands that prove the sanitized candidate still works; any command requires container isolation and a digest-pinned image

`degradation_policy` permits automatic `none` or `minor` degradation only; optional paths are exact, while `major` and `skeleton` outcomes require owner input

`security_runtime` binds the Ed25519 private key, Gitleaks 8.30.1 executable and SHA-256 digest, private temporary root, container backend, exact image digest or local image ID, numeric non-root user, and resource limits

`remote_target` binds the repository, branch, and expected remote base commit; publication rereads the base immediately before a non-force push

## 3. Source-audit receipts

An exact source-audit receipt may reuse completed deep inspection only when all bindings still match:

- source commit and tree
- file count and worktree completion
- report SHA-256
- scanner, policy, and report fingerprints
- zero critical findings and zero critical coverage gaps
- issuer, issue time, expiry time, and review trigger

The receipt may classify an ambiguous public example as a `PublicObservation`; it never suppresses a high-confidence credential or a private entity named by Policy v4

## 4. Migration from Policies v1 through v3

Policies v1, v2, and v3 remain readable through an in-memory migration that never edits the source file

The migration converts identifiers and replacements into sensitive entities and synthetic mappings; blocked paths become exact removal rules; old approvals become retention evidence only when every required binding is present

Exceptions and risk acceptances remain audit history; they cannot allow private content into a v2 candidate

## 5. Owner decisions and revisions

Use `needs_input` only when a required fact cannot be inferred safely, such as public rights, legal provenance, treatment of a required unsupported object, or a major capability change

When the owner supplies the minimum decision, write a new Policy v4 revision and preserve the former candidate, state, certification, authorization, degradation report, and evidence under a numbered private revision; resume only after recomputing every binding
