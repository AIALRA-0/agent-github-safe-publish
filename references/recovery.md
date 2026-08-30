# Managed publication recovery

## 1. Safe retry

Use the same private output directory with `--resume` only when the source HEAD, remote base, private policy, and intended candidate are unchanged

The command recomputes the candidate tree, patch, scanner, policy, runtime, and report fingerprints before any remote continuation

## 2. Stale base

When the remote default branch changes, stop the run, create a new isolated candidate from the new base, rerun project and README validation, and execute the exact gate again

Never rebase an already gated candidate and reuse its prior decision

## 3. Git-history slices

The working tree and Git history use separate checkpoints and time slices. Resume the working tree only when its complete path, kind, and content-digest inventory still matches; any changed file invalidates that checkpoint

An exact gate saves Git-history progress after bounded object intervals and again when its time budget expires. Rerun the same command with the same checkpoint to continue from the saved object index

Use the same `--ocr-checkpoint` for identical reruns. Completed image and PDF-page units replay their redacted results, while the next uncached unit consumes the new process budget. A changed repository, source commit, scanner, or policy invalidates the OCR checkpoint

OCR budget exhaustion in Git history keeps the history checkpoint on the current object. Do not manually advance it. Report and history finding pages are content-addressed and must pass digest and total-count verification before resume

The scanner re-enumerates the complete visible object inventory before every resume. A changed source commit, object inventory, scanner, policy, repository name, checkpoint schema, or candidate mode makes the checkpoint stale and returns `incomplete` plus publication `deny`

Do not overwrite a stale explicit checkpoint. Keep it as private evidence and select a new private checkpoint path for the changed publication candidate

## 4. Failed remote action

A failed branch push, pull-request creation, status check, tree comparison, or merge leaves the checkpoint outside the repository

Do not force-push or use administrator bypass. Inspect the checkpoint state, repair the external condition, then resume only if all bound fingerprints remain unchanged

## 5. Incident

A detected credential or private identifier stops publication. Rotate a credential before repository cleanup when it may have been valid or previously public

History rewriting, cache cleanup, fork coordination, Release replacement, and credential rotation require their own owner approval and recovery plan
