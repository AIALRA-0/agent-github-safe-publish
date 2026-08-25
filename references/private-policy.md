# Private policy contract

## 1 Storage boundary

Store `candidates.private.json` and `policy.private.json` below `CODEX_HOME/private/github-safe-publish/`. Restrict the directory to the current operating-system user. Do not commit, upload, paste, summarize, or hash raw candidate values into public artifacts.

The gate rejects a policy file located inside the source repository. This prevents repository-controlled content from expanding private allow rules.

## 2 Policy fields

The JSON object uses `schema_version: 1` and contains all of these arrays:

- `identifiers`: private literal or regular-expression rules with `id`, `kind`, `value`, and `severity`
- `replacements`: stable mappings with `identifier_id` and `replacement`
- `approved_locations`: exact rules with `rule_id`, `object`, `approved_by`, and `reason`
- `blocked_paths`: path glob strings that must never be published
- `binary_approvals`: exact binary approvals with `object`, `sha256`, `approved_by`, and `reason`
- `exceptions`: exact, expiring exceptions with `rule_id`, `object`, `approved_by`, `reason`, `expires_at`, and `review_trigger`

`approved_locations.object` and `exceptions.object` are exact object identifiers. Wildcards are rejected. Repository files cannot add or override these entries.

## 3 Candidate review

The information owner reviews raw candidates locally. Convert only confirmed private values into `identifiers`, then assign stable synthetic replacements. Keep public third-party references out of the private identifier list.

Use `literal` for an exact private value. Use `regex` only when the information owner can explain the intended range and has tested false positives. A regex that matches the empty string is invalid.

## 4 Object identifiers

Working-tree files use `working-tree:<relative-path>`. Historical blobs use `git:<object-id>:<path>`. Release assets use `release:<release-id>:<asset-name>`. Repository fields use `metadata:<field>`. LFS entities use `lfs:<oid>:<path>`.
