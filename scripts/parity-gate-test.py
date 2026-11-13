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


# A targeted sitting's operations, at the sizes federated-benchmark.py
# measures them: members joined, events missed, clients writing.
TARGETED_CELLS = [
    ("federated_join", 1000),
    ("federated_join", 10000),
    ("partition_catchup", 200),
    ("send_throughput", 8),
]


def with_targeted(table: dict, rivals: dict[str, float], overrides=None) -> dict:
    overrides = overrides or {}
    for operation, size in TARGETED_CELLS:
        servers = {"spindle": [0.98e9, 1.0e9, 1.02e9]}
        for rival, factor in rivals.items():
            f = overrides.get((rival, operation), factor)
            servers[rival] = [0.98e9 * f, 1.0e9 * f, 1.02e9 * f]
        table[(operation, size)] = servers
    return table


def test_material_wins_on_every_targeted_workload_pass_line_three():
    table = with_targeted(cells({"synapse": 5, "tuwunel": 2}), {"synapse": 5, "tuwunel": 2})
    assert statuses(table) == ["pass", "pass", "pass"]


def test_a_targeted_win_that_is_not_material_fails_line_three():
    table = with_targeted(
        cells({"synapse": 5, "tuwunel": 2}),
        {"synapse": 5, "tuwunel": 2},
        {("tuwunel", "partition_catchup"): 1.1},
    )
    result = dict(gate.evaluate(table))
    assert result[gate.LINES[2][0]]["status"] == "fail"
    assert any(
        item.startswith("partition_catchup/200 vs tuwunel")
        for item in result[gate.LINES[2][0]]["failures"]
    )


def test_a_targeted_workload_without_a_named_rival_is_incomplete():
    # Beating Synapse alone on concurrent send was the record before #647;
    # it is not the line, which names Tuwunel too.
    table = with_targeted(cells({"synapse": 5, "tuwunel": 2}), {"synapse": 5})
    result = dict(gate.evaluate(table))
    assert result[gate.LINES[2][0]]["status"] == "incomplete"
    assert any("no tuwunel side" in item for item in result[gate.LINES[2][0]]["missing"])


def test_targeted_cells_are_held_out_of_line_two():
    # A targeted loss to Tuwunel inside line 2's allowance is still a line 3
    # failure, and line 2 never sees it.
    table = with_targeted(
        cells({"synapse": 5, "tuwunel": 2}),
        {"synapse": 5, "tuwunel": 2},
        {("tuwunel", "federated_join"): 0.9},
    )
    result = dict(gate.evaluate(table))
    assert result[gate.LINES[1][0]]["status"] == "pass"
    assert result[gate.LINES[2][0]]["status"] == "fail"


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


def write_group(directory: Path, group: str, dimension: str, cells_by_server: dict) -> None:
    for server, operations in cells_by_server.items():
        for round_ in (1, 2, 3):
            (directory / f"{group}.{server}.r{round_}.json").write_text(
                json.dumps(
                    {
                        "server": server,
                        "dimension": dimension,
                        "benchmarks": {
                            key: {"mean_ns": value * (1 + round_ / 100)}
                            for key, value in operations.items()
                        },
                    }
                )
            )


def test_a_targeted_group_is_judged_beside_the_sitting():
    sitting_cells = {"send/200": 1e6, "messages_page/200": 1e6, "context_deep/200": 1e6}
    targeted_cells = {
        "federated_join/10000": 1e9,
        "partition_catchup/200": 1e9,
        "send_throughput/8": 1e6,
    }
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        write_group(
            tmp,
            "g",
            "events",
            {
                server: {key: value * factor for key, value in sitting_cells.items()}
                for server, factor in (("spindle", 1), ("synapse", 5), ("tuwunel", 2))
            },
        )
        write_group(
            tmp,
            "t",
            "targeted",
            {
                server: {key: value * factor for key, value in targeted_cells.items()}
                for server, factor in (("spindle", 1), ("synapse", 5), ("tuwunel", 2))
            },
        )
        alone = run(str(tmp), "g")
        assert alone.returncode == 0, alone.stderr
        assert "`federated_join` absent" in alone.stdout
        beside = run(str(tmp), "g", "t", "--require-complete")
        assert beside.returncode == 0, beside.stdout + beside.stderr
        assert "| 3. Materially faster (>= 1.38x, separated) where targeted | **pass** | 10 |" in beside.stdout


def test_a_cell_measured_in_two_groups_is_refused():
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        for group in ("g", "h"):
            write_group(tmp, group, "events", {"spindle": {"send/200": 1e6}, "synapse": {"send/200": 5e6}})
        proc = run(str(tmp), "g", "h")
        assert proc.returncode != 0
        assert "send/200 is in both g and h" in proc.stderr


def test_a_throughput_group_is_refused():
    # The concurrency dimension's mean_ns is a per-request latency under
    # load, not a throughput; the targeted sitting records the throughput.
    proc = run(str(DATA), "concurrency")
    assert proc.returncode != 0
    assert "measures concurrency" in proc.stderr


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
