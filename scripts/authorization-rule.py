#!/usr/bin/env python3
"""Run the room-authorization rule, and check the rule itself still works.

Five handlers shipped that authenticated the caller and then read a room
without asking whether that caller could see it (#258). Every one was found
by a person reading the file. Clippy cannot express the rule: it is not a
lint about a construct that is present, it is a rule about a call that is
*missing* on a path already holding the caller's identity.

This runs two checks, and the second is the one that keeps the first
honest:

1. `routes.rs` has no unguarded room read.
2. The rule still fires on the code it was written for, and still stays
   quiet on the fixed version of that same handler.

Without (2), a rule that silently stopped matching -- a refactor moves the
extractors, semgrep changes how it parses a Rust statement -- would keep
reporting a clean tree forever. A gate that cannot fail is not a gate, and
this one has already needed exact statement shapes once: semgrep matches
Rust structurally, so `may_read_room(...)` does not match
`may_read_room(...)?;` and the exclusion quietly matched nothing until that
was found.

Usage:
    scripts/authorization-rule.py
"""

from __future__ import annotations

import collections
import json
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
RULE = REPO / ".semgrep" / "room-authorization.yaml"
ROUTES = REPO / "crates" / "spindle-server" / "src" / "routes.rs"
FIXTURES = REPO / ".semgrep" / "fixtures"


def findings_by_file() -> collections.Counter[str]:
    """Scan the router and the fixtures, counting hits per file."""
    semgrep = shutil.which("semgrep")
    if semgrep is None:
        sys.exit(
            "authorization-rule: semgrep is not installed.\n"
            "  pip install semgrep  (CI does this; see .github/workflows/ci.yml)"
        )
    finished = subprocess.run(
        [
            semgrep,
            "scan",
            "--config",
            str(RULE),
            "--metrics=off",
            "--quiet",
            "--json",
            str(ROUTES),
            str(FIXTURES),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    # semgrep exits non-zero when it finds something, which is the normal
    # case here -- the vulnerable fixture is *supposed* to match. Only a
    # missing report is a failure of the run itself.
    if not finished.stdout.strip():
        sys.exit(f"authorization-rule: semgrep produced no report\n{finished.stderr}")
    report = json.loads(finished.stdout)
    return collections.Counter(
        pathlib.Path(result["path"]).name for result in report["results"]
    )


def main() -> int:
    hits = findings_by_file()
    problems: list[str] = []

    if hits["routes.rs"]:
        problems.append(
            f"{hits['routes.rs']} handler(s) in routes.rs read a room without "
            "checking who is asking. Run semgrep directly for the lines:\n"
            f"  semgrep scan --config {RULE.relative_to(REPO)} "
            f"{ROUTES.relative_to(REPO)}"
        )
    if not hits["vulnerable.rs"]:
        problems.append(
            "the rule no longer fires on .semgrep/fixtures/vulnerable.rs, which "
            "is the real pre-#258 handler. The rule has stopped guarding: a "
            "clean routes.rs now proves nothing."
        )
    if hits["guarded.rs"]:
        problems.append(
            "the rule fires on .semgrep/fixtures/guarded.rs, which calls "
            "may_read_room. It is flagging correct code, and a gate that "
            "cries wolf gets turned off."
        )

    if problems:
        for problem in problems:
            print(f"authorization-rule: {problem}", file=sys.stderr)
        return 1

    print(
        "authorization-rule: no unguarded room reads; the rule still fires on "
        "the pre-#258 handler and stays quiet on the fixed one"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
