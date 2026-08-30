# Fleet exposure audit

## 1. Repository set

`audit-fleet` enumerates repositories owned by the authenticated GitHub identity and freezes each immutable repository ID. Local checkouts are discovered recursively and associated by normalized GitHub remote full name rather than folder name

Use `--surface-profile publication` for the original Git, LFS, submodule, repository metadata, and Release scope. Use `--surface-profile repository-associated` for the periodic exposure audit

## 2. Repository-associated profile

The expanded profile declares these surfaces:

- Git objects, reference names, annotated tags, notes, commit and tag signatures, LFS entities, and historical submodule configuration
- Repository description, homepage, topics, Release title, body, tag metadata, and Release assets
- Issues, pull requests, comments, reviews, Discussions, labels, milestones, Wiki, Pages metadata, and up to 100 same-origin rendered Pages resources
- Workflow runs, retained logs, artifacts, job-summary availability, cache metadata, repository variables, environment names, deployment status URLs, secret names, Actions permissions, rulesets, and repository security settings
- Repository-associated packages and container images when the authenticated identity and platform interface permit content access

Secrets and deployment-key private values are not readable by design. Audit their names and settings only. Cache content without a stable download interface is `unreadable`; metadata coverage cannot substitute for content coverage

## 3. Status and recovery

Every declared surface reports `checked`, `not_present`, `unreadable`, `permission_denied`, or `tool_failed`. A present or declared surface without complete inspection makes the repository `incomplete`

Use `--resume` to reuse repositories already written to the private checkpoint report only when the scanner digest and policy fingerprint match. Ordinary mirrors and downloaded Release or Actions assets use disposable directories. `--cache-mirrors` is an explicit opt-in for an approved secure cache

`--history-time-limit-seconds` bounds Git-history work for each repository. `--release-time-limit-seconds` bounds existing Release-asset downloads and parsing. `--associated-time-limit-seconds` separately bounds Issues, pull requests, Actions, Pages, Wiki, packages, settings, and other repository-associated surfaces. Expiry records the unfinished surface as a coverage gap; the strict audit remains `incomplete`, while repository-associated auxiliary gaps stay noncritical for an exact publication decision

The public summary contains aggregate counts only. Gists, GitHub Projects, Codespaces, billing data, external clones, and other accounts remain outside the repository-associated profile
