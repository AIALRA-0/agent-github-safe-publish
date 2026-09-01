from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess


class SandboxUnavailable(RuntimeError):
    pass


PINNED_IMAGE = re.compile(r"(?:^[a-z0-9][a-z0-9._/:.-]*@sha256:[0-9a-f]{64}$)|(?:^sha256:[0-9a-f]{64}$)")


def _runtime_prefix(policy: dict) -> list[str]:
    runtime = policy["security_runtime"]
    backend = runtime.get("backend", "docker")
    if backend == "docker":
        return []
    if backend == "wsl-docker":
        distro = runtime.get("wsl_distribution")
        if not isinstance(distro, str) or not distro.strip():
            raise SandboxUnavailable("WSL Docker requires an explicit distribution")
        return ["wsl.exe", "-d", distro, "-u", "root", "--exec"]
    raise SandboxUnavailable("Unsupported container backend")


def _wsl_path(path: Path, prefix: list[str]) -> str:
    if not prefix:
        return str(path.resolve())
    try:
        result = subprocess.run(
            [*prefix, "wslpath", "-a", str(path.resolve())],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise SandboxUnavailable("Unable to map the candidate into WSL") from exc
    return result.stdout.strip()


def docker_engine_version(policy: dict, timeout: int = 15) -> str | None:
    prefix = _runtime_prefix(policy)
    try:
        result = subprocess.run(
            [*prefix, "docker", "version", "--format", "{{.Server.Version}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None


def verify_pinned_image(policy: dict, timeout: int = 30) -> str:
    runtime = policy["security_runtime"]
    image = runtime.get("image")
    if not isinstance(image, str) or not PINNED_IMAGE.fullmatch(image):
        raise SandboxUnavailable("Container image must use a complete sha256 digest")
    prefix = _runtime_prefix(policy)
    def inspect(reference: str, template: str) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [*prefix, "docker", "image", "inspect", reference, "--format", template],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return result

    try:
        template = "{{.Id}}" if image.startswith("sha256:") else "{{json .RepoDigests}}"
        result = inspect(image, template)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxUnavailable("Unable to inspect the pinned container image") from exc
    observed = result.stdout.strip()
    if image.startswith("sha256:"):
        if result.returncode == 0 and observed == image:
            return image
    else:
        expected_digest = image.rsplit("@", 1)[1]
        try:
            repo_digests = json.loads(observed) if result.returncode == 0 else []
        except json.JSONDecodeError:
            repo_digests = []
        if isinstance(repo_digests, list) and any(
            isinstance(item, str) and item.endswith("@" + expected_digest) for item in repo_digests
        ):
            return image
        try:
            fallback = inspect(expected_digest, "{{.Id}}|{{json .RepoDigests}}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SandboxUnavailable("Unable to inspect the pinned container image") from exc
        if fallback.returncode == 0:
            image_id, separator, encoded_digests = fallback.stdout.strip().partition("|")
            try:
                fallback_digests = json.loads(encoded_digests) if separator else []
            except json.JSONDecodeError:
                fallback_digests = []
            if image_id == expected_digest or (
                isinstance(fallback_digests, list)
                and any(isinstance(item, str) and item.endswith("@" + expected_digest) for item in fallback_digests)
            ):
                return expected_digest
    raise SandboxUnavailable("Pinned container image is not present or its digest differs")


def run_in_container(candidate: Path, command: str, policy: dict) -> dict:
    runtime = policy["security_runtime"]
    prefix = _runtime_prefix(policy)
    image = verify_pinned_image(policy)
    if docker_engine_version(policy) is None:
        raise SandboxUnavailable("Docker Engine is unavailable")
    tmpfs_size = str(runtime.get("tmpfs_size", "256m"))
    if not re.fullmatch(r"[1-9][0-9]*(?:[kKmMgG])?", tmpfs_size):
        raise SandboxUnavailable("Container temporary-space limit is invalid")
    container_user = str(runtime.get("user", "65532:65532"))
    if not re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", container_user):
        raise SandboxUnavailable("Container user must be a numeric non-root identity")
    arguments = [
        *prefix, "docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", str(runtime.get("pids_limit", 128)),
        "--memory", str(runtime.get("memory", "1g")),
        "--cpus", str(runtime.get("cpus", "2")),
        "--user", container_user,
        "--ulimit", "nofile=1024:1024",
        "--env", "HOME=/tmp",
        "--env", "TMPDIR=/tmp",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,size={tmpfs_size}",
        "--mount", f"type=bind,src={_wsl_path(candidate, prefix)},dst=/workspace,readonly",
        "--workdir", "/workspace",
    ]
    cache = runtime.get("dependency_cache")
    if cache:
        arguments.extend(["--mount", f"type=bind,src={_wsl_path(Path(cache), prefix)},dst=/dependencies,readonly"])
    arguments.extend([image, "/bin/sh", "-lc", command])
    try:
        result = subprocess.run(
            arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=int(policy["validation"].get("timeout_seconds", 900)),
        )
    except subprocess.TimeoutExpired as exc:
        raise SandboxUnavailable("Container validation exceeded its bounded runtime") from exc
    except OSError as exc:
        raise SandboxUnavailable("Unable to start the container validation runtime") from exc
    if result.returncode == 125:
        raise SandboxUnavailable("Container validation failed before the project command started")
    engine_version = docker_engine_version(policy)
    if engine_version is None:
        raise SandboxUnavailable("Docker Engine became unavailable during container validation")
    return {
        "command_id": __import__("hashlib").sha256(command.encode()).hexdigest()[:16],
        "exit_code": result.returncode,
        "sandbox": runtime.get("backend", "docker"),
        "engine_version": engine_version,
        "image": image,
    }
