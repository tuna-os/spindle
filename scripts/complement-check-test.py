#!/usr/bin/env python3
"""Tests for `complement-check.py`, run in CI as a plain script.

No pytest, and no new dependency for it, because this repository has no
Python test harness and one test file is not the reason to acquire one. Plain
asserts and a non-zero exit read the same way in a CI log.

What is worth testing here is narrow but real: the ratchet is the gate that
decides whether a Complement regression can merge, and its output is what
somebody reads at two in the morning. A gate that says the wrong thing, or
says the right thing unreadably, is the failure mode -- #228 is a case where
the ratchet was right and #231 a case where its output was not enough to act
on.

Usage: python3 scripts/complement-check-test.py
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "complement-check.py"


def load_module():
    """Import the script under test, whose name is not an identifier."""
    spec = importlib.util.spec_from_file_location("complement_check", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ledger(records: list[dict]) -> str:
    return "\n".join(json.dumps(record) for record in records) + "\n"


def output(test: str, text: str) -> dict:
    return {"Action": "output", "Test": test, "Output": text}


def run(records: list[dict], allowlist: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as work:
        results = Path(work) / "results.jsonl"
        names = Path(work) / "allowlist.txt"
        results.write_text(ledger(records), encoding="utf-8")
        names.write_text(allowlist, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(results), "--allowlist", str(names)],
            capture_output=True,
            text=True,
            check=False,
        )


def test_a_clean_run_passes():
    result = run(
        [output("TestGood", "ok\n"), {"Action": "pass", "Test": "TestGood"}],
        "TestGood\n",
    )
    assert result.returncode == 0, result.stderr
    assert "all 1 protected tests pass" in result.stdout, result.stdout


def test_a_failure_names_the_test_and_says_why():
    """The point of the whole file.

    Before this, a red ratchet said *which* protected tests broke and never
    *why* -- the reason sat in the run's artifact, which nobody downloads.
    """
    records = [
        output("TestKnock", "=== RUN   TestKnock\n"),
        output("TestKnock", "    knocking_test.go:131: got 502, want 403\n"),
        {"Action": "fail", "Test": "TestKnock"},
    ]
    result = run(records, "TestKnock\n")

    assert result.returncode == 1
    assert "- TestKnock (fail)" in result.stderr, result.stderr
    assert "got 502, want 403" in result.stderr, (
        "the failure reason is still missing from the log: " + result.stderr
    )
    # The `=== RUN` bookkeeping is noise next to the assertion, and the
    # summary above already named the test.
    assert "=== RUN" not in result.stderr, result.stderr


def test_a_protected_test_that_never_ran_is_a_failure():
    """Absent is not the same as passing, and must not read as it.

    A run filter that stops covering a protected name would otherwise make
    the ratchet quietly stop protecting it -- the exact failure #222's
    post-mortem named.
    """
    result = run(
        [{"Action": "pass", "Test": "TestGood"}],
        "TestGood\nTestNeverRan\n",
    )
    assert result.returncode == 1
    assert "- TestNeverRan (absent)" in result.stderr, result.stderr


def test_long_output_is_trimmed_to_the_end():
    """Go prints the assertion at the point of failure, so the tail is the
    part worth keeping, and eight failing tests must not bury the summary."""
    module = load_module()
    lines = [f"line {index}\n" for index in range(200)]
    lines.append("    the_test.go:9: the assertion that failed\n")
    detail = module.failure_detail(lines)

    assert len(detail) == module.MAX_OUTPUT_LINES + 1, detail
    assert detail[0].startswith("..."), detail[0]
    assert "the assertion that failed" in detail[-1], detail[-1]


def test_passing_but_unprotected_tests_are_offered_as_candidates():
    result = run(
        [
            {"Action": "pass", "Test": "TestGood"},
            {"Action": "pass", "Test": "TestNotYetProtected"},
        ],
        "TestGood\n",
    )
    assert result.returncode == 0, result.stderr
    assert "+ TestNotYetProtected" in result.stdout, result.stdout


def test_an_empty_ledger_is_refused():
    """A crashed run writes no results, and 'nothing failed' would be the
    worst possible reading of that."""
    result = run([], "TestGood\n")
    assert result.returncode == 1
    assert "no results at all" in result.stderr, result.stderr


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
        except AssertionError as error:
            failures += 1
            print(f"FAIL {test.__name__}: {error}", file=sys.stderr)
        else:
            print(f"ok   {test.__name__}")
    if failures:
        print(f"\n{failures} of {len(tests)} failed", file=sys.stderr)
        return 1
    print(f"\nall {len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
