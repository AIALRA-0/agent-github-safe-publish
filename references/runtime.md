# Runtime and parser contract

## 1. v2 compiler runtime

Policy v4 binds the Gitleaks 8.30.1 executable path, SHA-256 digest, private temporary root, container backend, exact image digest or local image ID, resource limits, numeric non-Root user and functional commands

`policy-init` refuses a functional command without a digest-pinned image; `verify` refuses a missing or changed Gitleaks executable, failed credential canary, missing private temporary root or unavailable container engine

Project code never falls back to a host process; an unavailable isolation backend produces `needs_input`, leaves the candidate under private storage and performs no remote action

## 2. v2 resource boundary

- Candidate files larger than the policy object limit are streamed only for their digest and then remediated or removed
- ZIP and Office members have separate member-count, member-size and total-expansion limits
- Images have pixel and frame limits; PDF files have page and rendered-pixel limits
- Private regular expressions use a restricted linear subset without groups, unbounded quantifiers, lookarounds or backreferences
- Gitleaks reports use full redaction, remain under the private temporary root and are removed after parsing
- Candidate validation uses no network, a read-only root, a read-only candidate mount, a bounded writable temporary filesystem, no Linux capabilities, `no-new-privileges`, no Docker Socket and no inherited publication credentials

## 3. Legacy diagnosis

`doctor --source <repository>` requires only the legacy parser layers used by the current tracked object types

`doctor --all` verifies every legacy parser layer; both modes report component status and versions without printing installation paths

Windows can run `scripts/bootstrap-runtime.ps1 -Destination <private-runtime-directory>`; Ubuntu can run `scripts/bootstrap-runtime.sh <private-runtime-directory>`

The legacy installers create a repository-external Python environment and install `requirements-gate.txt`; Ubuntu also installs `libmagic`, Binutils, FFmpeg and Git LFS from the operating-system package manager

Legacy missing parsers, incompatible runtime results, encrypted objects, resource limits and malformed containers remain `incomplete`; these terms describe the v1 gate and do not replace v2 remediation, certification or recovery states
