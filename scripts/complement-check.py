#!/usr/bin/env python3
"""Enforce the Complement allowlist ratchet.

Reads a `go test -json` ledger and complement/allowlist.txt. Every test named
in the allowlist must have passed; anything else fails this check with the
name of what regressed. Tests that pass but are not yet in the allowlist are
printed as candidates — they become protected the moment someone adds them,
which is a reviewed decision, not an automatic one, because a flaky test
promoted automatically would teach everyone to ignore this gate.

When a protected test does not pass, its captured output is printed with it.
The ledger has always carried that text -- `go test -json` emits an `output`
record per line -- and this script used to drop it on the floor, so a red
ratchet said *which* tests broke and never *why*. Recovering the reason then
meant downloading the run's artifact, which is a different kind of task from
reading a CI log and is why it usually did not happen (#231 is the case that
forced this).

Usage: scripts/complement-check.py <results.jsonl> [--allowlist FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def read_ledger(path: Path) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Test name -> final action, and test name -> its captured output.

    Both come from the same pass, because the ledger is large enough that
    reading it twice to answer two questions about the same records is a
    waste, and because the output only matters for tests the first mapping
    says failed.
    """
    outcomes: dict[str, str] = {}
    output: dict[str, list[str]] = {}
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
            if not test:
                continue
            if action in {"pass", "fail", "skip"}:
                outcomes[test] = action
            elif action == "output":
                output.setdefault(test, []).append(record.get("Output", ""))
    return outcomes, output


# Enough to carry an assertion and the lines around it, and few enough that
# eight failing tests do not bury the summary they appear under. A test that
# needs more than this is one to open the artifact for.
MAX_OUTPUT_LINES = 25


def failure_detail(lines: list[str]) -> list[str]:
    """The tail of a failed test's output, trimmed for a CI log.

    The tail rather than the head: Go prints the assertion and its context at
    the point of failure, so the end of the capture is where the reason is.
    Blank lines and the runner's own PASS/FAIL bookkeeping are dropped, since
    the summary above already says which test this was.
    """
    kept = [
        line.rstrip()
        for line in lines
        if line.strip() and not line.lstrip().startswith(("=== RUN", "=== PAUSE", "=== CONT"))
    ]
    if len(kept) <= MAX_OUTPUT_LINES:
        return kept
    dropped = len(kept) - MAX_OUTPUT_LINES
    return [f"... {dropped} earlier lines, see the complement-results artifact"] + kept[
        -MAX_OUTPUT_LINES:
    ]


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

    outcomes, output = read_ledger(arguments.results)
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
        # The reason, under the roll-call. Printed after the full list so the
        # names stay together and readable when several tests break at once.
        for name, action in regressed:
            detail = failure_detail(output.get(name, []))
            if not detail:
                continue
            print(f"\ncomplement-check: {name} ({action}) said:", file=sys.stderr)
            for line in detail:
                print(f"    {line}", file=sys.stderr)
        return 1

    print(
        f"complement-check: all {len(allowlist)} protected tests pass "
        f"({len(passed)} passing overall)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
