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


# --- the interop board (scripts/complement-interop.py) -----------------------
#
# Same file, same reason: it reads the same ledger format and is run by the
# same CI step, and what it prints is what somebody reads to decide whether
# federating with Synapse broke something. Its piles are the whole point, so
# the piles are what is tested.

INTEROP = HERE / "complement-interop.py"


def load_interop():
    spec = importlib.util.spec_from_file_location("complement_interop", INTEROP)
    module = importlib.util.module_from_spec(spec)
    # Registered before it runs: a dataclass looks its module up by name
    # while the class is being built, and finds nothing otherwise.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_interop(
    baseline: list[dict],
    interop: list[dict],
    known: str = "",
    *extra: str,
) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as work:
        base_path = Path(work) / "baseline.jsonl"
        interop_path = Path(work) / "interop.jsonl"
        known_path = Path(work) / "known.txt"
        base_path.write_text(ledger(baseline), encoding="utf-8")
        interop_path.write_text(ledger(interop), encoding="utf-8")
        known_path.write_text(known, encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                str(INTEROP),
                "--baseline",
                str(base_path),
                "--interop",
                str(interop_path),
                "--known",
                str(known_path),
                *extra,
            ],
            capture_output=True,
            text=True,
            check=False,
        )


def test_interop_sorts_every_test_into_its_pile():
    """One test per pile, and the counts in the table say which is which."""
    module = load_interop()
    baseline = {
        "TestShared": "pass",
        "TestGap": "fail",
        "TestPeerSide": "pass",
        "TestRegression": "pass",
        "TestGained": "fail",
        "TestSkipped": "pass",
    }
    interop = {
        "TestShared": "pass",
        "TestGap": "fail",
        "TestPeerSide": "fail",
        "TestRegression": "fail",
        "TestGained": "pass",
        "TestSkipped": "skip",
    }
    report = module.compare(baseline, interop, {"TestPeerSide": "the peer 404s it"})
    assert report.shared == ["TestShared"], report
    assert report.gaps == ["TestGap"], report
    assert report.peer_side == [("TestPeerSide", "the peer 404s it")], report
    assert report.regressions == ["TestRegression"], report
    assert report.gained == ["TestGained"], report
    assert report.skipped == ["TestSkipped"], report


def test_a_test_absent_from_the_interop_run_is_not_a_pass():
    """Absent reads as failed, as the ratchet reads it: a package that fails
    to set up against the peer takes every test in it with it, and a report
    that showed those as anything but regressions would hide exactly the
    failure it exists to show."""
    module = load_interop()
    report = module.compare({"TestGone": "pass"}, {"TestOther": "pass"}, {})
    assert report.regressions == ["TestGone"], report
    assert report.gained == ["TestOther"], report


def test_a_known_name_covers_its_subtests_but_not_its_neighbours():
    module = load_interop()
    known = {"TestMedia": "peer deprecation"}
    assert module.known_reason("TestMedia", known) == "peer deprecation"
    assert module.known_reason("TestMedia/Parallel/Can_download", known) == "peer deprecation"
    assert module.known_reason("TestMediaConfig", known) is None


def test_interop_regressions_carry_their_reason_and_only_regressions_fail_the_run():
    baseline = [
        {"Action": "pass", "Test": "TestShared"},
        {"Action": "pass", "Test": "TestRegression"},
        {"Action": "pass", "Test": "TestPeerSide"},
    ]
    interop = [
        {"Action": "pass", "Test": "TestShared"},
        output("TestRegression", "    federation_test.go:40: got 502, want 200\n"),
        {"Action": "fail", "Test": "TestRegression"},
        {"Action": "fail", "Test": "TestPeerSide"},
    ]
    known = "# a comment\nTestPeerSide the peer 404s its own deprecated endpoint\n"

    result = run_interop(baseline, interop, known)
    assert result.returncode == 0, result.stderr
    assert "| Shared passes | 1 |" in result.stdout, result.stdout
    assert "| Peer-side | 1 |" in result.stdout, result.stdout
    assert "| **Regressions** | 1 |" in result.stdout, result.stdout
    assert "got 502, want 200" in result.stdout, (
        "the reason a test regressed is missing from the report: " + result.stdout
    )
    assert "`TestPeerSide`: the peer 404s its own deprecated endpoint" in result.stdout, result.stdout

    # Report-only by default; the flag is what makes the pile a gate.
    result = run_interop(baseline, interop, known, "--fail-on-regression")
    assert result.returncode == 1, result.stdout
    assert "1 tests pass between two Spindles and fail with the peer" in result.stderr, result.stderr

    # And with the regression explained, the flag has nothing to fail on.
    explained = known + "TestRegression the peer answers 502 to this by design\n"
    result = run_interop(baseline, interop, explained, "--fail-on-regression")
    assert result.returncode == 0, result.stderr
    assert "| **Regressions** | 0 |" in result.stdout, result.stdout


def test_an_interop_report_writes_the_markdown_it_printed():
    with tempfile.TemporaryDirectory() as work:
        report = Path(work) / "out" / "report.md"
        result = run_interop(
            [{"Action": "pass", "Test": "TestShared"}],
            [{"Action": "pass", "Test": "TestShared"}],
            "",
            "--report",
            str(report),
            "--peer",
            "synapse as hs2",
        )
        assert result.returncode == 0, result.stderr
        assert report.read_text(encoding="utf-8").strip() == result.stdout.strip()
        assert "## Complement interop: synapse as hs2" in result.stdout, result.stdout


def test_an_empty_interop_ledger_is_refused():
    """Same rule as the ratchet: a crashed run has no results, and 'nothing
    regressed' is the worst reading of that."""
    result = run_interop([{"Action": "pass", "Test": "TestShared"}], [], "")
    assert result.returncode == 1
    assert "interop ledger holds no results at all" in result.stderr, result.stderr


def test_a_peer_side_entry_without_a_reason_is_refused():
    result = run_interop(
        [{"Action": "pass", "Test": "TestPeerSide"}],
        [{"Action": "fail", "Test": "TestPeerSide"}],
        "TestPeerSide\n",
    )
    assert result.returncode == 1
    assert "has no reason" in result.stderr, result.stderr


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
