#!/usr/bin/env bash
set -euo pipefail

# Resolve the caller-provided repository-external runtime directory
runtime_root="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$1")"

# Install native parsers used by media, opaque binaries, Git LFS, and OCR support
sudo apt-get update
sudo apt-get install -y libmagic1 libmagic-dev binutils ffmpeg git-lfs

# Create an isolated Python runtime so project dependencies remain untouched
python3 -m venv "$runtime_root"

# Upgrade packaging support inside the isolated runtime
"$runtime_root/bin/python" -m pip install --upgrade pip

# Install the exact cross-platform Python parser versions
"$runtime_root/bin/python" -m pip install -r "$(dirname "$0")/../requirements-gate.txt"

# Run the read-only diagnostic and fail when a required parser remains unavailable
"$runtime_root/bin/python" "$(dirname "$0")/safe_publish.py" doctor --all
