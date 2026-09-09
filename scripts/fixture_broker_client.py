"""Eval-only controller client; stage as work/.eval/fixture_control.py.

The endpoint is always the sibling broker-io directory. Request JSON:
{"version": 1, "argv": ["branch-read", "--branch", "main"]}.
Reply: {"version": 1, "exit_code": <int>, "output": <delivered JSON>}.
No shell, state path, arbitrary file reader, retry, or remote transport exists.
32-hex random IDs correlate request/reply filenames. Replies are model-writable
convenience output, NOT an authoritative operation ledger. The private server
journal and parent state/tool verification supply that evidence.
"""

import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time

MAX_REQUEST = 65536
MAX_REPLY = 1048576


def request(endpoint: Path, argv: list[str], *, timeout: float = 10) -> dict:
    if not 0 < timeout <= 10:
        raise ValueError("request timeout must be in (0, 10] seconds")
    payload = json.dumps({"version": 1, "argv": argv}, ensure_ascii=False).encode() + b"\n"
    if len(payload) > MAX_REQUEST:
        raise ValueError("request too large")
    directory = os.open(endpoint, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    identifier = secrets.token_hex(16)
    temporary = "." + identifier + ".request.tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(temporary, identifier + ".request.json", src_dir_fd=directory, dst_dir_fd=directory)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fd = os.open(identifier + ".response.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                break
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("fixture reply uncertain; do not replay the write")
                time.sleep(min(0.02, max(0, deadline - time.monotonic())))
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("nonregular broker reply")
            data = stream.read(MAX_REPLY + 1)
        if len(data) > MAX_REPLY:
            raise ValueError("invalid broker reply")
        result = json.loads(data)
        if (not isinstance(result, dict) or set(result) != {"version", "exit_code", "output"}
                or type(result["version"]) is not int or result["version"] != 1
                or type(result["exit_code"]) is not int or not 0 <= result["exit_code"] <= 255):
            raise ValueError("invalid broker reply")
        return result
    finally:
        os.close(directory)


def main(argv=None) -> int:
    try:
        result = request(Path(__file__).resolve().with_name("broker-io"),
                         sys.argv[1:] if argv is None else argv)
    except (OSError, ValueError):
        # Do not retry: the operation may already have committed.
        print(json.dumps({"error": "fixture_broker_unavailable_or_uncertain"}))
        return 2
    print(json.dumps(result["output"], ensure_ascii=False, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
