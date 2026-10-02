#!/usr/bin/env python3
"""Tests for `parity-gate.py`, run in CI as a plain script.

No pytest, for the reason complement-check-test.py gives: this repository
has no Python test harness and one test file is not the reason to acquire
one. Plain asserts and a non-zero exit read the same way in a CI log.

What is worth testing is the judgement: which cells count against which
line. A gate that calls noise a loss blocks for nothing; one that lets a
real Synapse loss through, or reports line 3 as a pass while workloads are
unmeasured, is the dishonest benchmark #42 was filed against.

Usage: python3 scripts/parity-gate-test.py
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "parity-gate.py"
DATA = HERE.parent / "docs" / "benchmarks" / "data"

sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("parity_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

OPERATIONS = ["send", "state", "sync_delta", "messages_page", "context_deep"]


def cells(rivals: dict[str, float], overrides=None) -> dict:
    """Three rounds a side, every operation at two sizes. Spindle sits at
    1.0 ms with a tight spread; each rival at `rivals[name]` times that,
    unless `overrides[(name, operation)]` says otherwise."""
    overrides = overrides or {}
    table = {}
    for operation in OPERATIONS:
        for size in (200, 3200):
            servers = {"spindle": [0.98e6, 1.0e6, 1.02e6]}
            for rival, factor in rivals.items():
                f = overrides.get((rival, operation), factor)
                servers[rival] = [0.98e6 * f, 1.0e6 * f, 1.02e6 * f]
            table[(operation, size)] = servers
    return table


def statuses(table: dict) -> list[str]:
    return [result["status"] for _, result in gate.evaluate(table)]


def test_clear_wins_pass_lines_one_and_two_and_leave_three_incomplete():
    # Line 3 cannot pass while the federated and concurrent workloads are
    # unmeasured, however large the measured wins are.
    assert statuses(cells({"synapse": 5, "tuwunel": 2})) == ["pass", "pass", "incomplete"]


def test_any_separated_loss_to_synapse_fails_line_one():
    table = cells({"synapse": 5, "tuwunel": 2}, {("synapse", "state"): 0.8})
    result = dict(gate.evaluate(table))
    assert result[gate.LINES[0][0]]["status"] == "fail"
    assert any(item.startswith("state/") for item in result[gate.LINES[0][0]]["failures"])


def test_overlapping_rounds_are_not_a_loss():
    # 0.99x with overlapping spreads is noise under the separation rule.
    table = cells({"synapse": 0.99, "tuwunel": 0.99})
    assert statuses(table)[:2] == ["pass", "pass"]


def test_tuwunel_may_be_up_to_the_allowance_faster_on_general_workloads():
    within = cells({"synapse": 5, "tuwunel": 2}, {("tuwunel", "sync_delta"): 0.88})
    beyond = cells({"synapse": 5, "tuwunel": 2}, {("tuwunel", "sync_delta"): 0.75})
    assert statuses(within)[1] == "pass"
    assert statuses(beyond)[1] == "fail"


def test_targeted_operations_are_held_to_line_three_not_line_two():
    # A 1.1x win on back-pagination passes line 2's bar but is not material.
    table = cells({"synapse": 5, "tuwunel": 2}, {("tuwunel", "messages_page"): 1.1})
    result = dict(gate.evaluate(table))
    assert result[gate.LINES[1][0]]["status"] == "pass"
    assert result[gate.LINES[2][0]]["status"] == "fail"
    assert any("messages_page" in item for item in result[gate.LINES[2][0]]["failures"])


def test_a_missing_rival_is_not_measured_rather_than_passed():
    assert statuses(cells({"tuwunel": 2}))[0] == "not measured"


def test_synapse_on_postgres_counts_as_synapse():
    assert statuses(cells({"synapse-postgres": 5, "tuwunel": 2}))[0] == "pass"


def test_unmeasured_workloads_are_named_every_time():
    result = dict(gate.evaluate(cells({"synapse": 5, "tuwunel": 2})))
    missing = " ".join(result[gate.LINES[2][0]]["missing"])
    assert "10,000-member" in missing and "catch-up" in missing and "concurrent" in missing


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False
    )


def test_the_committed_milestone_sitting_reads_as_the_issue_recorded():
    # #42's evaluation of m7-progress-2, done by hand: line 1 pass on 27
    # cells, line 2 pass, line 3 pass where measured with two federated
    # workloads outstanding.
    proc = run(str(DATA), "m7-progress-2")
    assert proc.returncode == 0, proc.stderr
    assert "| 1. Never slower than Synapse | **pass** | 27 |" in proc.stdout
    assert "**incomplete**" in proc.stdout
    assert run(str(DATA), "m7-progress-2", "--require-complete").returncode == 1


def test_a_failing_sitting_exits_non_zero_and_writes_the_report():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for server, factor in (("spindle", 1.0), ("synapse", 0.5)):
            for round_ in (1, 2, 3):
                (tmp / f"g.{server}.r{round_}.json").write_text(
                    json.dumps(
                        {
                            "server": server,
                            "benchmarks": {
                                "send/200": {"mean_ns": 1e6 * factor * (1 + round_ / 100)}
                            },
                        }
                    )
                )
        report = tmp / "report.md"
        proc = run(str(tmp), "g", "--markdown", str(report))
        assert proc.returncode == 1, proc.stdout
        assert "**fail**" in report.read_text()


def test_a_throughput_group_is_refused():
    proc = run(str(DATA), "concurrency")
    assert proc.returncode != 0
    assert "latency" in proc.stderr


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as error:
            failed += 1
            print(f"FAIL {test.__name__}: {error}")
        else:
            print(f"ok   {test.__name__}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
