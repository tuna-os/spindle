#!/usr/bin/env python3
"""Judge one sitting against the three parity lines #42 drew.

#42 turned "comparable or faster than Tuwunel and Synapse" from an assertion
into three lines with a pass or a fail each:

1. **Never slower than Synapse**, on any workload. Synapse is Python; losing
   to it would falsify the premise.
2. **Within 1.2x of Tuwunel** on general workloads. Tuwunel is a mature,
   optimised Rust server; matching it is success.
3. **Materially faster on the workloads the architecture targets** --
   back-pagination, deep history, large-room join, federation catch-up and
   concurrent send. This is the real test; the first two are sanity checks.

Until now those lines were evaluated by hand, in an issue comment per
sitting. That is the failure docs/benchmarks.md warns about for figures
typed into prose: nothing holds the evaluation to the data, so it is redone
differently each time and rots silently between sittings. This script reads
the committed result files and prints the evaluation, so every sitting gets
the same one and the weekly shared-runner sitting carries it in its pull
request.

Every cell is decided by `sitting.verdict` -- the separation rule (#171)
that colours the published page -- at **every** room size the sitting
measured, not at the largest alone: a parity claim that holds at 3,200
events and fails at 200 does not hold. A cell the rounds do not separate is
not a loss on any line, because calling it one would be reading noise.

**Line 3 is never reported as a pass while a targeted workload is
unmeasured.** Two of them (the 10,000-member federated join and catch-up
after a partition) need a fork workload that no client-server driver can
construct, and concurrent send has no competitor beside it yet. Those are
listed by name every time, so the gap cannot quietly drop out of the
report. A line with a failed cell exits non-zero; an incomplete line only
does so under `--require-complete`.

Usage:
    scripts/parity-gate.py docs/benchmarks/data m7-progress-2
    scripts/parity-gate.py docs/benchmarks/data ci-20260906 --markdown out.md
"""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import sys

import sitting

# Line 2's allowance: Tuwunel may be up to this much faster before a cell
# counts against us. From #42 verbatim.
TUWUNEL_ALLOWANCE = 1.2

# Line 3's "materially". #42 does not put a number on it, so this is a
# choice, made here and stated: a separated win whose median ratio clears
# the single-round repeatability this host was measured to have. Anything
# smaller is a win the next sitting could plausibly reverse, which is not
# what "the architecture is earning its cost" means.
MATERIAL = sitting.SINGLE_ROUND_REPEATABILITY

# The workloads line 3 names, and the driver operation that measures each,
# or None with the reason it is not measured. An operation listed here is
# held out of line 2 -- it is judged by the stricter line instead.
# #16's federated rig proves fork handling is correct; nothing yet times it.
FORK_WORKLOAD = "needs a federated fork workload, which no client-server driver can construct"

TARGETED = [
    ("back-pagination, deep room", "messages_page", None),
    ("state at the oldest event (deep history)", "context_deep", None),
    (
        "join a 10,000-member federated room",
        None,
        FORK_WORKLOAD,
    ),
    (
        "federation catch-up after a partition",
        None,
        FORK_WORKLOAD,
    ),
    (
        "concurrent send",
        None,
        "throughput is measured for Spindle and Synapse only, outside the sitting",
    ),
]
TARGETED_OPERATIONS = {operation for _, operation, _ in TARGETED if operation}


def load_group(data_dir: pathlib.Path, group: str) -> tuple[dict, dict]:
    """(operation, size) -> {server: [mean_ns per round]}, and the sidecar.

    Same layout render-comparisons.py reads: `<group>.<server>[.rN].json`,
    with `<group>.sitting.json` beside them as provenance.
    """
    cells: dict[tuple[str, int], dict[str, list[float]]] = {}
    sidecar: dict = {}
    for path in sorted(data_dir.glob(f"{group}.*.json")):
        if path.name.endswith(".sitting.json"):
            sidecar = json.loads(path.read_text())
            continue
        document = json.loads(path.read_text())
        if document.get("dimension", "events") != "events":
            sys.exit(
                f"parity-gate: {path.name} measures {document['dimension']}, "
                "not latency by room size; the parity lines read latency"
            )
        for key, entry in document["benchmarks"].items():
            operation, _, size = key.rpartition("/")
            cells.setdefault((operation, int(size)), {}).setdefault(
                document["server"], []
            ).append(entry["mean_ns"])
    if not cells:
        sys.exit(f"parity-gate: no result files for group {group} in {data_dir}")
    ours = {s for servers in cells.values() for s in servers if s.startswith("spindle")}
    if len(ours) != 1:
        sys.exit(
            f"parity-gate: group {group} needs exactly one spindle server, "
            f"found {len(ours)}"
        )
    return cells, sidecar


def rival_cells(cells: dict, prefix: str, operations=None):
    """Every (operation, size, ours, theirs) against the first rival named
    `prefix*`. `synapse` and `synapse-postgres` are one rival measured two
    ways; a sitting carries one of them, and either is Synapse."""
    for (operation, size), servers in sorted(cells.items()):
        if operations is not None and operation not in operations:
            continue
        ours = next(v for s, v in servers.items() if s.startswith("spindle"))
        theirs = next(
            (v for s, v in sorted(servers.items()) if s.startswith(prefix)), None
        )
        if theirs is not None:
            yield operation, size, ours, theirs


def ratio(ours: list[float], theirs: list[float]) -> float:
    return statistics.median(theirs) / statistics.median(ours)


def line_never_slower_than_synapse(cells: dict) -> dict:
    judged = list(rival_cells(cells, "synapse"))
    failures = [
        f"{op}/{size}: {sitting.verdict(o, t)[1]}"
        for op, size, o, t in judged
        if sitting.verdict(o, t)[0] == "loss"
    ]
    return outcome(judged, failures, [])


def line_within_tuwunel(cells: dict) -> dict:
    general = {op for op, _ in cells} - TARGETED_OPERATIONS
    judged = list(rival_cells(cells, "tuwunel", general))
    failures = [
        f"{op}/{size}: {sitting.verdict(o, t)[1]}"
        for op, size, o, t in judged
        if sitting.verdict(o, t)[0] == "loss" and ratio(o, t) < 1 / TUWUNEL_ALLOWANCE
    ]
    return outcome(judged, failures, [])


def line_materially_faster(cells: dict) -> dict:
    rivals = sorted(
        {s for servers in cells.values() for s in servers if not s.startswith("spindle")}
    )
    judged, failures, missing = [], [], []
    for workload, operation, reason in TARGETED:
        if operation is None:
            missing.append(f"{workload}: {reason}")
            continue
        if not any(op == operation for op, _ in cells):
            missing.append(f"{workload}: `{operation}` absent from this sitting")
            continue
        for rival in rivals:
            for op, size, o, t in rival_cells(cells, rival, {operation}):
                judged.append(op)
                call, label = sitting.verdict(o, t)
                if call != "win" or ratio(o, t) < MATERIAL:
                    failures.append(f"{op}/{size} vs {rival}: {label} ({call})")
    return outcome(judged, failures, missing)


def outcome(judged: list, failures: list[str], missing: list[str]) -> dict:
    if not judged:
        status = "not measured"
    elif failures:
        status = "fail"
    elif missing:
        status = "incomplete"
    else:
        status = "pass"
    return {"status": status, "cells": len(judged), "failures": failures, "missing": missing}


LINES = [
    ("1. Never slower than Synapse", line_never_slower_than_synapse),
    (f"2. Within {TUWUNEL_ALLOWANCE}x of Tuwunel, general workloads", line_within_tuwunel),
    (f"3. Materially faster (>= {MATERIAL}x, separated) where targeted", line_materially_faster),
]


def evaluate(cells: dict) -> list[tuple[str, dict]]:
    return [(title, judge(cells)) for title, judge in LINES]


def render(group: str, sidecar: dict, results: list[tuple[str, dict]], rounds: int) -> str:
    lines = [f"## Parity gate (#42): `{group}`", ""]
    if sidecar:
        host = sidecar.get("host", {})
        lines.append(
            f"Host: {host.get('runner', 'unknown')}, {host.get('cores', '?')} cores. "
            f"Versions: {', '.join(sidecar.get('versions', [])) or 'unrecorded'}."
        )
        lines.append("")
    if rounds < sitting.MIN_ROUNDS:
        lines.append(
            f"Only {rounds} round(s) per server: below {sitting.MIN_ROUNDS}, cells are "
            "read against the assumed single-round band, not a measured spread."
        )
        lines.append("")
    lines += ["| Line | Status | Cells judged |", "| --- | --- | ---: |"]
    for title, result in results:
        lines.append(f"| {title} | **{result['status']}** | {result['cells']} |")
    for title, result in results:
        if result["failures"] or result["missing"]:
            lines += ["", f"### {title}", ""]
            lines += [f"- failed: {item}" for item in result["failures"]]
            lines += [f"- not measured: {item}" for item in result["missing"]]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("data_dir", type=pathlib.Path)
    parser.add_argument("group")
    parser.add_argument("--markdown", type=pathlib.Path, help="also write the report here")
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="exit non-zero while any line is incomplete or not measured",
    )
    args = parser.parse_args()

    cells, sidecar = load_group(args.data_dir, args.group)
    counts: dict[str, int] = {}
    for servers in cells.values():
        for server, values in servers.items():
            counts[server] = max(counts.get(server, 0), len(values))
    results = evaluate(cells)
    report = render(args.group, sidecar, results, sitting.rounds_in(counts))
    print(report, end="")
    if args.markdown:
        args.markdown.write_text(report)

    statuses = {result["status"] for _, result in results}
    if "fail" in statuses:
        return 1
    if args.require_complete and statuses - {"pass"}:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
