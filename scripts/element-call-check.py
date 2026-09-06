#!/usr/bin/env python3
"""Enforce the Element Call allowlist ratchet (#269).

Reads a Playwright JSON report and contrib/element-call/allowlist.txt.
Every test named in the allowlist must have passed; anything else fails
this check with the name of what regressed and the error Playwright
recorded for it. Tests that pass but are not in the allowlist are printed
as candidates -- they become protected the moment someone adds them, which
is a reviewed decision rather than an automatic one, for the same reason
complement-check.py works that way.

A test is named `<spec file> :: <title>`, the spec path relative to the
checkout's playwright/ directory, so the name survives a move of the
checkout and a project (browser) is not part of it: the ratchet is over
what Spindle does, not which browser asked.

Usage: scripts/element-call-check.py <results.json> [--allowlist FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ALLOWLIST = HERE.parent / "contrib" / "element-call" / "allowlist.txt"


def read_allowlist(path: Path) -> list[str]:
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def walk(suite: dict, file: str, outcomes: dict[str, str], errors: dict[str, str]) -> None:
    """Flatten Playwright's nested suites into name -> outcome."""
    file = suite.get("file") or file
    spec_file = file.removeprefix("playwright/")
    for spec in suite.get("specs", []):
        name = f"{spec_file} :: {spec.get('title', '')}"
        # Retries: the last result of any test is the outcome. `expected`
        # is a pass, `flaky` passed on a retry, and both count as passing
        # here; the ratchet asks whether Spindle can pass it, not whether
        # the run was smooth.
        outcome = "skip"
        messages: list[str] = []
        for test in spec.get("tests", []):
            status = test.get("status")
            if status in {"expected", "flaky"}:
                outcome = "pass"
            elif status == "unexpected":
                outcome = "fail"
            elif status == "skipped" and outcome != "fail":
                outcome = "skip"
            for result in test.get("results", []):
                for error in result.get("errors", []):
                    if error.get("message"):
                        messages.append(error["message"])
        previous = outcomes.get(name)
        if previous is None or outcome == "fail" or previous == "skip":
            outcomes[name] = outcome
        if messages:
            errors[name] = "\n".join(messages[-3:])
    for child in suite.get("suites", []):
        walk(child, file, outcomes, errors)


def read_report(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    report = json.loads(path.read_text(encoding="utf-8"))
    outcomes: dict[str, str] = {}
    errors: dict[str, str] = {}
    for suite in report.get("suites", []):
        walk(suite, "", outcomes, errors)
    return outcomes, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("results", type=Path)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    args = parser.parse_args()

    if not args.results.exists():
        print(f"element-call-check: no report at {args.results}", file=sys.stderr)
        return 2
    outcomes, errors = read_report(args.results)
    protected = read_allowlist(args.allowlist)

    regressed = [name for name in protected if outcomes.get(name) != "pass"]
    candidates = sorted(
        name for name, outcome in outcomes.items() if outcome == "pass" and name not in protected
    )
    failed = sorted(name for name, outcome in outcomes.items() if outcome == "fail")

    print(
        f"element-call-check: {len(outcomes)} tests ran, "
        f"{sum(1 for o in outcomes.values() if o == 'pass')} passed, "
        f"{len(failed)} failed, {len(protected)} protected"
    )
    for name in failed:
        print(f"  failed: {name}")
        for line in errors.get(name, "").splitlines()[:12]:
            print(f"      {line}")
    if candidates:
        print("  passing and not yet protected (add to the allowlist to protect):")
        for name in candidates:
            print(f"    {name}")
    if regressed:
        print("element-call-check: protected tests did not pass:", file=sys.stderr)
        for name in regressed:
            print(f"  {name}: {outcomes.get(name, 'did not run')}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
