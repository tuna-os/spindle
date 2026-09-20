#!/usr/bin/env python3
"""Enforce the matrix-rust-sdk allowlist ratchet.

Reads the text `cargo test` wrote (one `test <path> ... <outcome>` line per
test) and contrib/rust-sdk/allowlist.txt. Every test named in the
allowlist must have passed; anything else fails this check with the name
of what regressed. Tests that pass but are not in the allowlist are
printed as candidates -- protected the moment someone adds them, which is
a reviewed decision rather than an automatic one, for the same reason
complement-check.py and element-call-check.py work that way.

Also writes a table of every outcome to $GITHUB_STEP_SUMMARY when that is
set, so a run's page says what the suite saw without opening the log.

Usage: scripts/rust-sdk-check.py <results.log> [--allowlist FILE]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = HERE.parent / "contrib" / "rust-sdk" / "allowlist.txt"

# `test a::b::c ... ok` / `... FAILED` / `... ignored`. cargo prints the
# outcome at the end of the line; a test that panics prints its output in
# between, so the match is anchored at both ends rather than on one line's
# shape.
LINE = re.compile(r"^test (\S+) \.\.\. (ok|FAILED|ignored)(?:, .*)?$")


def read_allowlist(path: Path) -> list[str]:
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def outcomes(log: Path) -> dict[str, str]:
    seen: dict[str, str] = {}
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        match = LINE.match(line.strip())
        if match:
            name, outcome = match.groups()
            seen[name] = {"ok": "pass", "FAILED": "fail", "ignored": "skip"}[outcome]
    return seen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", maxsplit=1)[0])
    parser.add_argument("results", type=Path)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    args = parser.parse_args()

    seen = outcomes(args.results)
    protected = read_allowlist(args.allowlist)
    if not seen:
        print(
            "rust-sdk-check: no test outcome in the log; the suite did not run",
            file=sys.stderr,
        )
        return 2

    passed = sorted(name for name, outcome in seen.items() if outcome == "pass")
    failed = sorted(name for name, outcome in seen.items() if outcome == "fail")
    skipped = sorted(name for name, outcome in seen.items() if outcome == "skip")
    regressed = [name for name in protected if seen.get(name) != "pass"]
    candidates = [name for name in passed if name not in protected]

    lines = [
        f"rust-sdk: {len(passed)} passed, {len(failed)} failed, {len(skipped)} ignored, "
        f"{len(protected)} protected",
    ]
    for name in regressed:
        lines.append(f"  REGRESSED  {name}  ({seen.get(name, 'not run')})")
    for name in candidates:
        lines.append(f"  candidate  {name}")
    for name in failed:
        if name not in protected:
            lines.append(f"  failing    {name}")
    print("\n".join(lines))

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write("## matrix-rust-sdk integration suite\n\n")
            out.write(
                f"{len(passed)} passed, {len(failed)} failed, {len(skipped)} ignored, "
                f"{len(protected)} protected, {len(regressed)} regressed\n\n"
            )
            out.write("| test | outcome |\n|---|---|\n")
            for name in sorted(seen):
                mark = {"pass": "pass", "fail": "**fail**", "skip": "ignored"}[
                    seen[name]
                ]
                if name in protected:
                    mark += " (protected)"
                out.write(f"| `{name}` | {mark} |\n")

    return 1 if regressed else 0


if __name__ == "__main__":
    sys.exit(main())
