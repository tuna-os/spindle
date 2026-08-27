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

Options:
  --heartbeat SECONDS   how often to print a still-running line (0 disables)
  --fail-output LINES   log lines to show under a failure (default 40)
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--heartbeat", type=float, default=60.0)
    parser.add_argument("--fail-output", type=int, default=40)
    args = parser.parse_args()

    started = time.monotonic()
    last_beat = started
    counts: collections.Counter[str] = collections.Counter()
    # Output is buffered per test so a failure can show what led to it.
    # Only failures print theirs; passing tests would bury the log.
    buffered: dict[str, list[str]] = collections.defaultdict(list)
    running: set[str] = set()

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
                emit(f"{mark} {test} ({seconds:.1f}s)")
                if action == "fail":
                    for out in buffered[test][-args.fail_output :]:
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

    emit(
        f"==== {counts['pass']} passed, {counts['fail']} failed, "
        f"{counts['skip']} skipped"
    )
    # Deliberately 0: this renders results, it does not judge them.
    return 0


if __name__ == "__main__":
    sys.exit(main())
