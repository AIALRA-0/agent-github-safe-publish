from __future__ import annotations

from pathlib import Path

from .sandbox import SandboxUnavailable, run_in_container


def validate_candidate(candidate: Path, policy: dict) -> list[dict]:
    commands = policy["functional_contract"].get("commands", [])
    if commands and not policy["security_runtime"].get("container_required", False):
        raise SandboxUnavailable("Functional validation requires the no-credential container sandbox")
    results: list[dict] = []
    for command in commands:
        results.append(run_in_container(candidate, command, policy))
        if results[-1]["exit_code"] != 0:
            break
    return results
