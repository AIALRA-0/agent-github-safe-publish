from __future__ import annotations

import os
from pathlib import Path
import subprocess
import time

from .sandbox import run_in_container


def sanitized_environment() -> dict[str, str]:
    blocked_prefixes = ("AWS_", "AZURE_", "GCP_", "GH_", "GITHUB_", "GOOGLE_", "SAFE_PUBLISH_", "SSH_")
    blocked_fragments = ("TOKEN", "PASSWORD", "SECRET", "PRIVATE_KEY", "CREDENTIAL", "API_KEY")
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(blocked_prefixes)
        and not any(fragment in key.upper() for fragment in blocked_fragments)
    }
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def validate_candidate(candidate: Path, policy: dict) -> list[dict]:
    timeout = int(policy["validation"].get("timeout_seconds", 900))
    results: list[dict] = []
    for command in policy["functional_contract"].get("commands", []):
        if policy["security_runtime"].get("container_required", False):
            results.append(run_in_container(candidate, command, policy))
            if results[-1]["exit_code"] != 0:
                break
            continue
        started = time.monotonic()
        completed = subprocess.run(
            command,
            cwd=candidate,
            shell=True,
            env=sanitized_environment(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        results.append({"command_id": __import__("hashlib").sha256(command.encode()).hexdigest()[:16], "exit_code": completed.returncode, "duration_ms": int((time.monotonic() - started) * 1000)})
        if completed.returncode != 0:
            break
    return results
