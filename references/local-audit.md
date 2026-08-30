# Local exposure audit

## 1. Scope

`audit-local` reads accessible JSONL session records under `CODEX_HOME/sessions` and `CODEX_HOME/archived_sessions`, deduplicates them by `session_meta.id`, and scans every string field including messages, tool output, and attachment references

It also reads saved project roots from the Codex desktop state. Git projects contribute tracked and unignored files; non-Git roots exclude recognized dependency, build, and download caches. Real paths are deduplicated so directory junctions and aliases do not inflate the finite set

Deleted conversations, other machines, other accounts, unavailable attachments, corrupt records, and unreadable roots remain explicit coverage gaps

## 2. Private evidence

Raw candidates are deduplicated in a temporary private SQLite database, then written once to `candidates.private.json`. The temporary database and its journal files are removed after the document is complete

Candidate collection stops after 250,000 attempts and persists that exhaustion state. Non-raw rule and coverage checks continue, but the audit remains `incomplete`; restarting the same checkpoint does not reset the budget

Windows applies a current-user access control list. Other systems require owner-only permissions. If the private boundary cannot be established, the command stops without falling back to a public path

The public summary contains only counts and statuses. It excludes session titles, source values, source-value hashes, repository names, and private paths

## 3. Recovery

Use `--checkpoint` and `--resume` for multi-gigabyte histories. Version 3 stores file tokens, deduplicated session summaries, completed saved-project summaries, finding counts, candidate-budget state, the scanner digest, and the policy fingerprint; it never stores message text or candidate values

A checkpoint is reusable only when both the scanner digest and policy fingerprint match the current run. A mismatch restarts enumeration and discards the temporary candidate index instead of mixing evidence from different controls

An invalid JSONL record, unreadable file, missing project state, or failed format parser makes the affected surface `incomplete`

Each JSONL file runs in a separate child process with a 600-second default budget. A native crash, timeout, missing worker result, or changed file marks that file unreadable and lets the parent continue. Candidate data is committed before the corresponding file or project enters the checkpoint
