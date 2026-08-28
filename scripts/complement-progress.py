#!/usr/bin/env python3
"""Render a `go test -json` stream as it happens.

Complement writes its ledger to a file, which means a CI log shows three
minutes of image building and then ten minutes of nothing — a run that
tested 254 things is indistinguishable from a run that hung. This filter
sits in the pipe: the JSON still lands in the ledger byte for byte, and a
human-readable line appears here as each test finishes.

Reads the JSON stream on stdin, writes progress to stdout. Never fails a
build: a torn line is skipped, and the exit status is always 0 because
the gate is scripts/complement-check.py against the allowlist, not this.

  go test -json ./tests/csapi | tee -a results.jsonl | complement-progress.py

Only *protected* failures print their captured log. A full run fails
around a hundred tests that nobody has claimed yet — that is the debt
ledger working as intended, and dumping each one's server tracing buries
the failures that actually break the build under tens of thousands of
lines. Unprotected failures still get their one line; the ledger keeps
everything either way.

The parent of a protected failure prints its log too, and that is not a
tidiness point. Complement tears the deployment down at the end of the
*top-level* test and prints each homeserver's log there, so the server's
own account of what it refused is attributed to the parent — a name that
is usually not in the allowlist itself, only its subtests are. Without
this, a build fails on a protected subtest and the one log that says why
is discarded a second later. Found the hard way, on a subtest whose
failure said only that a homeserver returned 403.

Options:
  --heartbeat SECONDS   how often to print a still-running line (0 disables)
  --fail-output LINES   log lines to show under a protected failure
  --parent-output LINES log lines to show under its parent, which is where
                        the homeserver logs land (0 disables)
  --allowlist FILE      which tests are protected (default: the repo's)
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path


def read_allowlist(path: Path) -> set[str]:
    """Protected test names, or an empty set if the file is unreadable."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return set()
    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }


def is_protected(test: str, allowlist: set[str]) -> bool:
    """True for a protected test or any subtest of one.

    A protected parent implies its subtests: `TestFoo` failing because
    `TestFoo/Bar` failed is one failure, and the useful log is the
    subtest's.
    """
    parts = test.split("/")
    return any("/".join(parts[: n + 1]) in allowlist for n in range(len(parts)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--heartbeat", type=float, default=60.0)
    parser.add_argument("--fail-output", type=int, default=40)
    parser.add_argument("--parent-output", type=int, default=400)
    parser.add_argument(
        "--allowlist",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "complement" / "allowlist.txt",
    )
    args = parser.parse_args()
    allowlist = read_allowlist(args.allowlist)

    started = time.monotonic()
    last_beat = started
    counts: collections.Counter[str] = collections.Counter()
    # Output is buffered per test so a failure can show what led to it.
    # Only failures print theirs; passing tests would bury the log.
    buffered: dict[str, list[str]] = collections.defaultdict(list)
    running: set[str] = set()
    # Protected subtests that have already failed, so their parent knows to
    # surrender its log when it fails in turn. Go reports a subtest before
    # its parent, so by then this is complete for that parent.
    protected_failures: set[str] = set()

    def emit(line: str) -> None:
        elapsed = time.monotonic() - started
        print(f"[{elapsed:7.1f}s] {line}", flush=True)

    for line in sys.stdin:
        line = line.strip()
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                record = None  # a torn line in a crashed run is not a result
        else:
            record = None

        if record is None:
            # Anything that is not a JSON record is a build error or a
            # panic go test could not attribute. Those matter most, so
            # they pass through rather than being swallowed.
            if line:
                emit(line)
        else:
            test = record.get("Test")
            action = record.get("Action")
            if action == "output" and test:
                buffered[test].append(record.get("Output", "").rstrip("\n"))
            elif action == "run" and test:
                running.add(test)
            elif action in {"pass", "fail", "skip"} and test:
                running.discard(test)
                counts[action] += 1
                seconds = record.get("Elapsed", 0.0)
                mark = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP"}[action]
                protected = action == "fail" and is_protected(test, allowlist)
                if protected:
                    counts["protected-fail"] += 1
                    protected_failures.add(test)
                suffix = "" if protected or action != "fail" else "  [not protected]"
                emit(f"{mark} {test} ({seconds:.1f}s){suffix}")
                if protected:
                    for out in buffered[test][-args.fail_output :]:
                        print(f"          | {out}", flush=True)
                # The parent of a protected failure is where Complement put
                # the homeserver logs. It is counted as unprotected -- that
                # part is right, the subtest is the failure -- but its log
                # is the only place the server says what it refused.
                elif (
                    action == "fail"
                    and args.parent_output
                    and any(
                        failed.startswith(f"{test}/") for failed in protected_failures
                    )
                ):
                    print(
                        f"          | ---- deployment log for {test} ----",
                        flush=True,
                    )
                    for out in buffered[test][-args.parent_output :]:
                        print(f"          | {out}", flush=True)
                buffered.pop(test, None)
            elif action in {"pass", "fail"} and not test:
                # Package-level verdict: the run of a package is over.
                package = record.get("Package", "?")
                emit(f"---- {action} {package}")

        now = time.monotonic()
        if args.heartbeat and now - last_beat >= args.heartbeat:
            last_beat = now
            in_flight = ", ".join(sorted(running)[:3]) or "none"
            emit(
                f".... {counts['pass']} passed, {counts['fail']} failed, "
                f"{counts['skip']} skipped; in flight: {in_flight}"
            )

    # The protected count is the one that decides the build, so it is the
    # one the summary leads with when it is not zero.
    summary = (
        f"==== {counts['pass']} passed, {counts['fail']} failed "
        f"({counts['protected-fail']} protected), {counts['skip']} skipped"
    )
    emit(summary)
    # Deliberately 0: this renders results, it does not judge them.
    return 0


if __name__ == "__main__":
    sys.exit(main())
