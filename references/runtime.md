# Runtime and parser contract

## 1 Read-only diagnosis

`doctor --source <repository>` requires only the parser layers used by the current tracked object types

`doctor --all` verifies every supported parser layer. Both modes report component status and versions without printing installation paths

## 2 Isolated installation

- Windows: run `scripts/bootstrap-runtime.ps1 -Destination <private-runtime-directory>`
- Ubuntu: run `scripts/bootstrap-runtime.sh <private-runtime-directory>`

Both installers create a repository-external Python environment and install the versions in `requirements-gate.txt`

Ubuntu additionally installs `libmagic`, Binutils, FFmpeg, and Git LFS from the operating-system package manager

Gitleaks remains pinned to the version declared by `safe_publish.py`; the scanner downloads it into the Codex cache and verifies the official checksum before use

## 3 Fail-closed behavior

Missing parsers, incompatible runtime results, encrypted objects, resource limits, and malformed containers return `incomplete`

NPY and NPZ parsing always uses `allow_pickle=False`. Object dtypes, excessive members, excessive expansion, excessive elements, excessive memory size, excessive extracted text, and excessive nested dtype depth cannot pass the gate
