#!/usr/bin/env python3
"""Fail unless a Complement test and every one of its subtests passed.

    scripts/complement-require.py TestName ledger.jsonl [ledger.jsonl ...]

Reads `go test -json` ledgers as scripts/complement.sh writes them. The
suite job gates on an allowlist of many tests; this gates on one test
(#563's contested-fork check) in each ledger given, so a run where the test
was skipped, never built, or lost a subtest fails as loudly as one where it
failed.
"""

import json
import sys


def verdicts(path, test):
    """Map each of `test`'s (sub)tests in the ledger to its last action."""
    out = {}
    with open(path, encoding="utf-8") as ledger:
        for line in ledger:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = record.get("Test") or ""
            if name != test and not name.startswith(test + "/"):
                continue
            if record.get("Action") in ("pass", "fail", "skip"):
                out[name] = record["Action"]
    return out


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    test, ledgers = sys.argv[1], sys.argv[2:]
    failed = False
    for path in ledgers:
        results = verdicts(path, test)
        if results.get(test) != "pass":
            print(f"{path}: {test} is {results.get(test, 'absent')}")
            failed = True
        subtests = {name: action for name, action in results.items() if name != test}
        if not subtests:
            print(f"{path}: {test} ran no subtests")
            failed = True
        for name, action in sorted(subtests.items()):
            print(f"{path}: {name}: {action}")
            if action != "pass":
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
