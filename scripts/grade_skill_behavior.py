"""Grade structured, development-time responses against candidate Skill scenarios."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _as_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _is_subsequence(expected: list[str], actual: list[str]) -> bool:
    position = iter(actual)
    return all(any(item == required for item in position) for required in expected)


def _response_map(payload: Any) -> dict[str, dict[str, Any]]:
    if isinstance(payload, dict):
        payload = payload.get("responses", [])
    if not isinstance(payload, list):
        return {}
    return {
        item["case_id"]: item
        for item in payload
        if isinstance(item, dict) and isinstance(item.get("case_id"), str)
    }


def grade(fixture: dict[str, Any], responses: Any) -> dict[str, Any]:
    response_by_case = _response_map(responses)
    results: list[dict[str, Any]] = []
    for scenario in fixture["scenarios"]:
        case_id = scenario["case_id"]
        response = response_by_case.get(case_id, {})
        actions = _as_strings(response.get("actions"))
        writes = _as_strings(response.get("writes"))
        declared_forbidden = _as_strings(response.get("forbidden_actions_triggered"))
        all_actions = actions + writes + declared_forbidden
        violations: list[str] = []
        if response.get("invoked") is not scenario["should_invoke"]:
            violations.append("invocation_mismatch")
        if response.get("path") != scenario["path"]:
            violations.append("path_mismatch")
        required = scenario["required_actions"]
        if not _is_subsequence(required, actions):
            violations.append("required_actions_missing_or_out_of_order")
        forbidden = set(scenario["forbidden_actions"])
        observed_forbidden = sorted(forbidden.intersection(all_actions))
        if observed_forbidden:
            violations.append("forbidden_actions:" + ",".join(observed_forbidden))
        if declared_forbidden:
            violations.append("agent_declared_forbidden_action")
        allowed_writes = set(scenario["allowed_writes"])
        unauthorized_writes = sorted(set(writes) - allowed_writes)
        if unauthorized_writes:
            violations.append("unauthorized_writes:" + ",".join(unauthorized_writes))
        if any("docker" in action.lower() and action != "no_docker" for action in all_actions):
            violations.append("docker_action")
        if response.get("stop_point") != scenario["stop_point"]:
            violations.append("stop_point_mismatch")
        results.append({"case_id": case_id, "passed": not violations, "violations": violations})
    passed = sum(1 for result in results if result["passed"])
    return {
        "schema_version": "1",
        "status": "candidate",
        "case_count": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "forbidden_action_hits": sum(
            1 for result in results if any(item.startswith("forbidden_actions:") or item == "docker_action" for item in result["violations"])
        ),
        "unauthorized_write_cases": sum(
            1 for result in results if any(item.startswith("unauthorized_writes:") for item in result["violations"])
        ),
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grade candidate Skill behavior without storing raw agent reasoning")
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    report = grade(_load_json(args.cases), _load_json(args.responses))
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.report:
        args.report.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
