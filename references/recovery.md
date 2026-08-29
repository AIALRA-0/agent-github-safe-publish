# Managed publication recovery

## 1 Safe retry

Use the same private output directory with `--resume` only when the source HEAD, remote base, private policy, and intended candidate are unchanged

The command recomputes the candidate tree, patch, scanner, policy, runtime, and report fingerprints before any remote continuation

## 2 Stale base

When the remote default branch changes, stop the run, create a new isolated candidate from the new base, rerun project and README validation, and execute the exact gate again

Never rebase an already gated candidate and reuse its prior decision

## 3 Failed remote action

A failed branch push, pull-request creation, status check, tree comparison, or merge leaves the checkpoint outside the repository

Do not force-push or use administrator bypass. Inspect the checkpoint state, repair the external condition, then resume only if all bound fingerprints remain unchanged

## 4 Incident

A detected credential or private identifier stops publication. Rotate a credential before repository cleanup when it may have been valid or previously public

History rewriting, cache cleanup, fork coordination, Release replacement, and credential rotation require their own owner approval and recovery plan
