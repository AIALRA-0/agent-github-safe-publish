"""Restricted Linux tool permissions for the separately isolated eval runtime.

This does not create the outer host boundary or certify a runtime. A matching
synthetic file/network canary must pass before model experiments are launched.
"""
import json
from pathlib import Path


def linux_permission_args(work: Path, writable: tuple[Path, ...] = (), *, readonly: tuple[Path, ...] = (),
                          scanner_available: bool = True) -> list[str]:
    if type(scanner_available) is not bool:
        raise ValueError("scanner availability must be an explicit boolean")
    filesystem = {":root": "deny", ":minimal": "read", ":tmpdir": "deny", ":slash_tmp": "deny"}
    for root in (work, *writable):
        absolute = root.resolve()
        if absolute == Path("/"):
            raise ValueError("evaluation write root cannot be the filesystem root")
        filesystem[str(absolute)] = "write"
    for root in readonly:
        absolute = root.resolve()
        if absolute == Path('/'):
            raise ValueError('evaluation read root cannot be the filesystem root')
        filesystem[str(absolute)] = 'read'
    # Codex protects .git by default even inside an otherwise writable root.
    # This is the synthetic fixture's metadata, not the product checkout.
    if (work / ".git").is_dir():
        filesystem[str((work / ".git").resolve())] = "write"
    # The dedicated outer runtime mounts only verified CLI executables here.
    if Path("/runtime").is_dir():
        filesystem["/runtime"] = "read"
    if not scanner_available:
        # A verified outer runtime has exactly this standalone scanner. Deny
        # its real path, not just PATH lookup; this must pass a runtime canary.
        filesystem["/runtime/gitleaks"] = "deny"
    helper = work.parent / ".fixture-no-hooks"
    if helper.is_dir():
        filesystem[str(helper.resolve())] = "read"
    entries = ",".join(json.dumps(key) + "=" + json.dumps(value) for key, value in filesystem.items())
    profile = 'permissions={behavior_eval={filesystem={' + entries + '},network={enabled=false}}}'
    return ["--config", profile, "--config", 'default_permissions="behavior_eval"',
            "--config", 'approval_policy="never"']
