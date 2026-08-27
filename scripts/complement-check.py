#!/usr/bin/env python3
"""Enforce the Complement allowlist ratchet.

Reads a `go test -json` ledger and complement/allowlist.txt. Every test named
in the allowlist must have passed; anything else fails this check with the
name of what regressed. Tests that pass but are not yet in the allowlist are
printed as candidates — they become protected the moment someone adds them,
which is a reviewed decision, not an automatic one, because a flaky test
promoted automatically would teach everyone to ignore this gate.

Usage: scripts/complement-check.py <results.jsonl> [--allowlist FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def read_ledger(path: Path) -> dict[str, str]:
    """Test name -> final action (pass/fail/skip), later lines winning."""
    outcomes: dict[str, str] = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue  # a torn line in a crashed run is not a result
            test = record.get("Test")
            action = record.get("Action")
            if test and action in {"pass", "fail", "skip"}:
                outcomes[test] = action
    return outcomes


def read_allowlist(path: Path) -> list[str]:
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "complement" / "allowlist.txt",
    )
    parser.add_argument(
        "--print-run-filter",
        action="store_true",
        help="print a go test -run regex covering the allowlist, and exit",
    )
    arguments = parser.parse_args()

    if arguments.print_run_filter:
        top_level = sorted(
            {name.split("/")[0] for name in read_allowlist(arguments.allowlist)}
        )
        print(f"^({'|'.join(top_level)})$" if top_level else "^$")
        return 0

    outcomes = read_ledger(arguments.results)
    allowlist = read_allowlist(arguments.allowlist)

    if not outcomes:
        print("complement-check: the ledger holds no results at all", file=sys.stderr)
        return 1

    regressed = [
        (name, outcomes.get(name, "absent"))
        for name in allowlist
        if outcomes.get(name) != "pass"
    ]
    passed = {name for name, action in outcomes.items() if action == "pass"}
    candidates = sorted(passed.difference(allowlist))

    if candidates:
        print(f"complement-check: {len(candidates)} passing but not yet protected:")
        for name in candidates:
            print(f"  + {name}")

    if regressed:
        print(
            f"complement-check: {len(regressed)} allowlisted tests did not pass:",
            file=sys.stderr,
        )
        for name, action in regressed:
            print(f"  - {name} ({action})", file=sys.stderr)
        return 1

    print(
        f"complement-check: all {len(allowlist)} protected tests pass "
        f"({len(passed)} passing overall)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
