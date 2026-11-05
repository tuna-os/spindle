#!/usr/bin/env python3
"""Run the room-authorization rules, and check the rules themselves still work.

Five handlers shipped that authenticated the caller and then read a room
without asking whether that caller could see it (#258). Every one was found
by a person reading the file. Clippy cannot express the rule: it is not a
lint about a construct that is present, it is a rule about a call that is
*missing* on a path already holding the caller's identity.

This runs two checks, and the second is the one that keeps the first
honest:

1. No module of the server crate has an unguarded room read, on the client
   door (`room-read-without-authorization`) or the federation one
   (`federation-room-read-without-membership`).
2. Each rule fires on exactly the fixture lines marked `// ruleid: <id>`
   and nowhere else in .semgrep/fixtures -- in particular not on the lines
   marked `// ok: <id>`, the fixed version of the same handler.

Without (2), a rule that silently stopped matching -- a refactor moves the
extractors, semgrep changes how it parses a Rust statement, somebody
narrows the include glob back to one file (#744) -- would keep reporting a
clean tree forever. A gate that cannot fail is not a gate, and this one has
already needed exact statement shapes once: semgrep matches Rust
structurally, so `may_read_room(...)` does not match `may_read_room(...)?;`
and the exclusion quietly matched nothing until that was found. The
fixtures sit at .semgrep/fixtures/crates/spindle-server/src/, the same
relative path as the modules they stand for, so they reach the rules only
through the same include glob the real modules do.

Every rule in the file must have at least one `ruleid:` fixture line: a
rule nobody has watched fire is a rule nobody knows works.

Usage:
    scripts/authorization-rule.py
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
RULE = REPO / ".semgrep" / "room-authorization.yaml"
SOURCE = REPO / "crates" / "spindle-server" / "src"
FIXTURES = REPO / ".semgrep" / "fixtures"

MARKER = re.compile(r"^\s*//\s*(ruleid|ok):\s*([\w-]+)\s*$")
RULE_ID = re.compile(r"^  - id: ([\w-]+)\s*$", re.MULTILINE)

# (path relative to the repository, line, rule id)
Finding = tuple[str, int, str]


def scan() -> set[Finding]:
    """Scan the server crate and the fixtures with every rule in the file."""
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
            str(SOURCE),
            str(FIXTURES),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    # semgrep exits non-zero when it finds something, which is the normal
    # case here -- the `ruleid:` fixtures are *supposed* to match. Only a
    # missing report, or one carrying engine errors, is a failure of the run
    # itself: a rule that failed to parse reports no findings either.
    if not finished.stdout.strip():
        sys.exit(f"authorization-rule: semgrep produced no report\n{finished.stderr}")
    report = json.loads(finished.stdout)
    if report.get("errors"):
        messages = "\n".join(error.get("message", "") for error in report["errors"])
        sys.exit(f"authorization-rule: semgrep reported errors\n{messages}")
    return {
        (
            str(pathlib.Path(result["path"]).resolve().relative_to(REPO)),
            result["start"]["line"],
            # semgrep prefixes the id with the config's dotted path.
            result["check_id"].rsplit(".", 1)[-1],
        )
        for result in report["results"]
    }


def markers() -> tuple[set[Finding], set[Finding]]:
    """The fixture lines each rule must fire on, and those it must not.

    A marker names the line under it, the convention `semgrep --test` uses,
    so a fixture reads the same to anyone who has written semgrep tests.
    """
    fire: set[Finding] = set()
    quiet: set[Finding] = set()
    for fixture in sorted(FIXTURES.rglob("*.rs")):
        relative = str(fixture.relative_to(REPO))
        lines = fixture.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            marked = MARKER.match(line)
            if marked is None:
                continue
            kind, rule = marked.groups()
            (fire if kind == "ruleid" else quiet).add((relative, number + 1, rule))
    return fire, quiet


def describe(findings: set[Finding]) -> str:
    return "\n".join(f"  {path}:{line} {rule}" for path, line, rule in sorted(findings))


def main() -> int:
    findings = scan()
    fire, quiet = markers()
    rules = set(RULE_ID.findall(RULE.read_text(encoding="utf-8")))
    fixture_root = str(FIXTURES.relative_to(REPO)) + "/"
    in_tree = {finding for finding in findings if not finding[0].startswith(fixture_root)}
    in_fixtures = findings - in_tree
    problems: list[str] = []

    if in_tree:
        problems.append(
            f"{len(in_tree)} handler read(s) of a room nobody checked the caller "
            "against. Gate each one, or, if it is deliberately open, say why on "
            "the line above a `// nosemgrep: <rule>` comment:\n" + describe(in_tree)
        )
    if missed := fire - in_fixtures:
        problems.append(
            "the rule no longer fires on fixture lines marked `ruleid:`. It has "
            "stopped guarding, and a clean tree now proves nothing:\n"
            + describe(missed)
        )
    if spurious := in_fixtures - fire:
        named_ok = spurious & quiet
        problems.append(
            "the rule fires on fixture lines it should stay quiet on"
            + (" (marked `ok:`, the gated version)" if named_ok else "")
            + ". It is flagging correct code, and a gate that cries wolf gets "
            "turned off:\n" + describe(spurious)
        )
    if untested := rules - {rule for _, _, rule in fire}:
        problems.append(
            "these rules have no `ruleid:` fixture line, so nothing shows they "
            "can fire: " + ", ".join(sorted(untested))
        )
    if unknown := {rule for _, _, rule in fire | quiet} - rules:
        problems.append(
            "fixture markers name rules the file does not define: "
            + ", ".join(sorted(unknown))
        )

    if problems:
        for problem in problems:
            print(f"authorization-rule: {problem}", file=sys.stderr)
        return 1

    print(
        f"authorization-rule: no unguarded room reads in {SOURCE.relative_to(REPO)}; "
        f"{len(rules)} rules fire on all {len(fire)} marked fixture lines and "
        f"stay quiet on the {len(quiet)} gated ones"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
