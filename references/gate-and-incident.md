# Gate and incident handling

## 1 Dual decision precedence

The strict audit `decision` is unchanged. Coverage gaps produce `incomplete` before findings are classified. With complete coverage, confirmed violations produce `block`, unresolved ownership produces `review`, and an empty unresolved set produces `pass`

Only `mode: exact-publication-gate` produces a `publication_decision`. The default `permissive-noncritical` profile returns `allow`, `allow_with_risk`, or `deny`. The optional `strict` profile returns `allow` only when the strict audit result is `pass`

Credentials, private identifiers, real data, legal records, critical infrastructure, unresolved candidate ownership, and coverage gaps in the working tree, Git history, LFS, submodules, proposed Release assets, private policy, or Gitleaks always produce `deny`

A fixed noncritical finding can produce `allow_with_risk` only when an exact risk acceptance is active. Auxiliary remote surfaces that are not transferred by the exact publication may also produce `allow_with_risk`. Periodic exposure audits never authorize mutation

Private machine reports contain both decisions, the release profile, rule IDs, exact object locations, severity, risk level, handling state, coverage gaps, source commit, scanner versions, policy fingerprint, and a deterministic report fingerprint. They exclude matched values and matched-value hashes

Public summaries contain only both decisions, the release profile, aggregate counts, commit and scanner identifiers, and report fingerprints. They exclude finding locations, rule IDs, private values, and private object digests

## 2 File and history handling

Office, PDF, images, SVG, audio, video, archives, Notebook files, and native binaries use format-specific layers. A missing layer, unavailable parser, encrypted object, expansion limit, unsupported type, incomplete Git history, or missing LFS entity produces `incomplete`

The pinned Gitleaks binary must detect a runtime-generated synthetic credential before it scans repository content. A silent or broken binary produces `gitleaks-runtime-canary-not-detected` and `incomplete`. The canary has a 60-second process timeout; repository scans keep Gitleaks' 300-second internal limit and add a 330-second parent-process timeout

Git scanning covers blob history, author and committer metadata, messages, reference names, annotated tag payloads, notes, and signature payloads. Legal provenance and third-party attribution remain review-only and are never rewritten automatically

Exact gates bound Git-history work to 900 seconds per run by default. When the budget expires, the scanner writes a private atomic checkpoint and returns `incomplete` plus publication `deny`. The checkpoint stores only redacted findings, coverage, object digests, and the next object index; it never stores matched values or matched-value hashes

Resume is allowed only when the repository name, source commit, complete Git object inventory digest and count, scanner digest, private policy fingerprint, and raw-candidate mode match exactly. Invalid or mismatched checkpoints fail closed and are not overwritten

## 3 Credential incident

If a credential may still be valid or was already public, stop publication and notify the credential owner without reproducing the value. Revoke or rotate it before repository cleanup because deleting repository content does not neutralize a copied credential

History rewriting, force-pushing, cache cleanup, fork coordination, Release replacement, settings changes, and credential rotation each require repository-specific approval and a recovery plan
