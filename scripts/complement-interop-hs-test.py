#!/usr/bin/env python3
"""Tests for the COMPLEMENT_INTEROP_HS handling in `complement.sh`.

`docker` and `go` are stubs on PATH, so this runs anywhere in a second and
checks only what the script decides: which homeserver the peer image is
handed to, and what it refuses. The hub-mode failover test deploys three
servers and needs the peer to be hs3; the script once accepted only hs1 and
hs2, which failed the nightly compliance run before a single test started.

Usage: python3 scripts/complement-interop-hs-test.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "complement.sh"
PEER = "example.invalid/peer:latest"

DOCKER = """#!/usr/bin/env bash
case "$1" in
    image) echo "example.invalid/peer@sha256:0" ;;
esac
exit 0
"""

# Records every COMPLEMENT_BASE_IMAGE_* the harness would have seen.
GO = """#!/usr/bin/env bash
env | grep '^COMPLEMENT_BASE_IMAGE_' >> "$STUB_ENV_LOG" || true
exit 0
"""


def run(interop_hs: str | None) -> tuple[int, str, str]:
    """Run complement.sh against the stubs; return (status, stderr, peer env)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bindir = root / "bin"
        bindir.mkdir()
        for name, body in (("docker", DOCKER), ("go", GO)):
            stub = bindir / name
            stub.write_text(body)
            stub.chmod(0o755)
        (root / "src").mkdir()
        log = root / "env.log"
        log.touch()
        env = {
            **os.environ,
            "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "COMPLEMENT_IMAGE": "example.invalid/spindle:latest",
            "COMPLEMENT_INTEROP_IMAGE": PEER,
            "COMPLEMENT_SRC": str(root / "src"),
            "COMPLEMENT_PACKAGES": "./tests/spindle",
            "STUB_ENV_LOG": str(log),
        }
        env.pop("COMPLEMENT_INTEROP_HS", None)
        if interop_hs is not None:
            env["COMPLEMENT_INTEROP_HS"] = interop_hs
        done = subprocess.run(
            ["bash", str(SCRIPT), str(root / "results.jsonl")],
            env=env,
            capture_output=True,
            text=True,
        )
        return done.returncode, done.stderr, log.read_text()


def main() -> int:
    failures: list[str] = []

    def check(label: str, ok: bool, detail: str = "") -> None:
        if not ok:
            failures.append(f"{label}: {detail}")

    for given, want in (
        (None, "hs2"),
        ("hs1", "hs1"),
        ("hs2", "hs2"),
        ("hs3", "hs3"),
        ("HS3", "hs3"),
    ):
        status, err, seen = run(given)
        check(f"{given or 'default'} runs", status == 0, f"exit {status}: {err.strip()}")
        check(
            f"{given or 'default'} plays {want}",
            seen.strip() == f"COMPLEMENT_BASE_IMAGE_{want}={PEER}",
            repr(seen),
        )

    for bad in ("hs", "hs0", "peer", "hs1;ls", "../hs1"):
        status, err, seen = run(bad)
        check(f"{bad!r} is refused", status == 2, f"exit {status}")
        check(f"{bad!r} reaches no harness", seen == "", repr(seen))

    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        return 1
    print("complement-interop-hs-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
