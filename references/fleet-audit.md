# Fleet audit

## 1 Declared surfaces

`audit-fleet` builds the owner repository set from the authenticated GitHub API. For each immutable repository ID it records visibility, fork and archive state, default-branch commit, visible references, repository security settings, and the status of these surfaces:

- ordinary Git objects across visible history
- Git LFS entities
- submodule URLs and pinned commits
- repository description, homepage, and topics
- GitHub Release assets

Each surface reports `checked`, `not_present`, `unreadable`, `permission_denied`, or `tool_failed`. Any present surface without `checked` coverage makes the repository decision `incomplete`.

## 2 Private outputs

The detailed report and raw candidate file must remain below `CODEX_HOME/private/github-safe-publish/`. The command prints aggregate counts only. Raw matches never enter standard output or standard error.

The optional public summary contains aggregate counts without repository names, paths, object IDs, candidate values, or policy details.

## 3 Forks and archives

Fork audits preserve upstream authorship and distinguish repository state through GitHub metadata. The tool never rewrites upstream history. Archived repositories remain read-only and receive an audit decision only.

## 4 Coverage limits

The first audit excludes Issues, pull-request text and comments, Discussions, Wiki, GitHub Pages, historical Actions logs and artifacts, Packages, container images, caches, Gists, and external clones. Record these as declared exclusions instead of implying they were checked.
