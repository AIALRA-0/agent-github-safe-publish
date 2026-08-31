#!/usr/bin/env python3
"""Compatibility entry point for the legacy interface and the v2 compiler."""

from __future__ import annotations

from pathlib import Path
import sys


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from github_safe_publish import legacy  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in {"run", "inspect", "plan", "sanitize", "verify", "publish", "status", "resume", "exposure"}:
        from github_safe_publish.cli import main as v2_main

        raise SystemExit(v2_main())
    raise SystemExit(legacy.main())
else:
    legacy.legacy = legacy
    sys.modules[__name__] = legacy
