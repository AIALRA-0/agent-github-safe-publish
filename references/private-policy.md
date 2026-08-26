# Private policy contract

## 1 Storage boundary

Keep `candidates.private.json`, the master policy, compiled repository policies, checkpoints, and detailed reports below `CODEX_HOME/private/github-safe-publish/`. Never commit, upload, paste, publicly summarize, or hash raw candidate values into public artifacts

The gate rejects a policy located inside the source repository. Repository-controlled files cannot add approvals, replacements, or exceptions

## 2 Version 3 fields

Every policy contains `schema_version`, `identifiers`, `replacements`, `approved_locations`, `blocked_paths`, `binary_approvals`, `exceptions`, and `risk_acceptances`

Each identifier has `id`, `kind`, `value`, `severity`, `normalization`, and `scopes`. Supported normalization operations are `none`, `nfkc`, `casefold`, `zero-width`, and `confusable`. Scopes contain `all`, an exact scan surface, or a repository name used by `compile-policy`

Each binary approval contains `object`, `sha256`, `approved_by`, `reason`, `inspection_layers`, `tool_versions`, and `review_trigger`. A changed object digest, scanner version, declared inspection layer, or review trigger requires renewed approval

Approved locations and exceptions target exact object identifiers and reject wildcards. Exceptions also require a rule ID, approver, reason, expiry, and review trigger

Each risk acceptance requires `repository`, `rule_id`, `object`, `object_sha256`, `scanner_sha256`, `approved_by`, `reason`, `expires_at`, and the exact `content-or-scanner-change` review trigger. It may target only a rule in the fixed noncritical matrix. A wildcard, critical rule, expired approval, changed object digest, or changed scanner digest is inactive

Version 1 and version 2 policies remain readable through in-memory migration. The source file is not modified automatically

## 3 Candidate review and compilation

The information owner classifies raw candidates locally. Use literal rules for confirmed private values; use regular expressions only after a bounded false-positive test

Candidate discovery is bounded. Reaching the attempt limit preserves the private candidates already collected, records the exhausted state in the checkpoint, and returns `incomplete`; it never silently truncates candidates and returns `pass`

Stable synthetic mappings use explicit values such as `ExampleOrg`, `ExampleUser`, `example.invalid`, and synthetic IDs. Never derive them from private values by hashing

Run `compile-policy` to keep only rules and risk acceptances applicable to the selected repository. The Base64-encoded compiled policy must not exceed 48 KB

Working-tree objects use `working-tree:<path>`, history objects use `git:<object>:<path>`, Release assets use `release:<release-id>:<asset>`, repository fields use `metadata:<field>`, and LFS objects use `lfs:<oid>:<path>`
