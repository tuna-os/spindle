#!/usr/bin/env python3
"""Print two sides of a sitting side by side, round by round.

Each side is one `api-benchmark.py` result file, or a glob matching one file
per round of the same server -- `'tmp/bench/compare.spindle.r*.json'`. Two
numbers per operation per room size, and the ratio between them, exactly as
before; what changed is what the numbers are worth. A single round cannot
tell a real difference from this host's run-to-run variance (#171), so with
rounds present every cell is a median over rounds with the observed range
beside it, and the verdict comes from `sitting.verdict`: the same separation
rule that colours the published page, so the terminal and the page never
disagree about a cell.

Reports the *growth* separately from the absolute cost, because they answer
different questions: the ratio says which server is faster today, and the
growth says which one will still be fast in a room ten times the size. SPEC
18.1's claims are all of the second kind.
"""

from __future__ import annotations

import argparse
import glob
import json
import pathlib
import signal
import statistics

import sitting


def load_side(pattern: str) -> tuple[str, dict[str, dict[int, list[float]]]]:
    """Every round of one server: operation -> size -> [median_ns per round].

    A plain path is one round. A glob is however many rounds it matches, and
    they must all be the same server -- mixing two servers on one side would
    print a spread that is really a difference.
    """
    paths = sorted(glob.glob(pattern)) or [pattern]
    servers: set[str] = set()
    results: dict[str, dict[int, list[float]]] = {}
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
        servers.add(document.get("server", pathlib.Path(path).name))
        for key, value in document["benchmarks"].items():
            name, size = key.rsplit("/", 1)
            results.setdefault(name, {}).setdefault(int(size), []).append(
                value["mean_ns"] / 1e6
            )
    if len(servers) != 1:
        raise SystemExit(
            f"compare-benchmarks: {pattern} matches more than one server "
            f"({', '.join(sorted(servers))}); one side is one server"
        )
    return servers.pop(), results


def describe(values: list[float]) -> str:
    """`1.18`, or with rounds `1.18 (1.10–1.31)`: median, then range."""
    summary = sitting.spread(values)
    if summary["rounds"] < 2:
        return f"{summary['median']:.2f}"
    return f"{summary['median']:.2f} ({summary['low']:.2f}–{summary['high']:.2f})"


WORDS = {"win": "faster", "loss": "slower", "noise": "overlapping"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", help="ours: a result file, or a glob over its rounds")
    parser.add_argument("second", help="theirs: a result file, or a glob over its rounds")
    args = parser.parse_args()

    name_a, a = load_side(args.first)
    name_b, b = load_side(args.second)
    shared = sorted(set(a) & set(b))
    if not shared:
        print("no operations in common")
        return 1
    sizes = sorted(
        {size for name in shared for size in a[name]}
        & {size for name in shared for size in b[name]}
    )
    rounds = min(
        len(a[name][size]) for name in shared for size in sizes if size in a[name]
    )
    rounds = min(
        rounds,
        min(len(b[name][size]) for name in shared for size in sizes if size in b[name]),
    )
    resolved = rounds >= sitting.MIN_ROUNDS

    print(
        f"milliseconds, median over {rounds} round(s)"
        + (" (low–high across rounds)" if rounds > 1 else "")
        + f"; lower is better; ratio = {name_b} / {name_a}"
    )
    if resolved:
        print(
            "a cell is called only when the rounds separate: the band is the "
            "ratio their fastest round allows against our slowest, to their "
            "slowest against our fastest, and a call is a band that excludes 1.0×"
        )
    else:
        print(
            f"fewer than {sitting.MIN_ROUNDS} rounds a side: no spread to read, "
            f"so a cell is called only past the {sitting.SINGLE_ROUND_REPEATABILITY}× "
            "this host was measured to move between rounds of identical code (#171); "
            "everything inside that is unresolved, not a tie"
        )

    comparable = called = 0
    for size in sizes:
        print(f"\n== {size} ==")
        header = (
            "operation".ljust(16)
            + name_a[:20].rjust(22)
            + name_b[:20].rjust(22)
            + "ratio".rjust(9)
        )
        if resolved:
            header += "  rounds allow"
        print(header)
        for name in shared:
            ours, theirs = a[name].get(size), b[name].get(size)
            if not ours or not theirs:
                continue
            css, _ = sitting.verdict(ours, theirs)
            ratio = statistics.median(theirs) / statistics.median(ours)
            row = (
                name.ljust(16)
                + describe(ours).rjust(22)
                + describe(theirs).rjust(22)
                + f"{ratio:8.2f}×"
            )
            if resolved:
                low, high = sitting.ratio_band(ours, theirs)
                row += f"  {low:.2f}–{high:.2f}×".ljust(15)
            word = WORDS[css] if resolved or css != "noise" else "unresolved"
            print(f"{row}  {word}")
            comparable += 1
            called += css != "noise"

    if resolved:
        expected = sitting.expected_false_calls(comparable, rounds)
        print(
            f"\n{comparable} cells, {called} called; at {rounds} rounds two "
            f"identical servers separate by chance "
            f"{sitting.chance_of_separating(rounds):.1%} of the time, so about "
            f"{expected:.1f} of these would be called with no difference at all"
        )

    if len(sizes) > 1:
        print(f"\ngrowth from {sizes[0]} to {sizes[-1]} (flat is the claim), medians:")
        for name in shared:
            if sizes[0] not in a[name] or sizes[-1] not in a[name]:
                continue
            if sizes[0] not in b[name] or sizes[-1] not in b[name]:
                continue
            ga = statistics.median(a[name][sizes[-1]]) / statistics.median(a[name][sizes[0]])
            gb = statistics.median(b[name][sizes[-1]]) / statistics.median(b[name][sizes[0]])
            print(f"  {name:16} {name_a:14} {ga:5.2f}×   {name_b:14} {gb:5.2f}×")
    return 0


if __name__ == "__main__":
    # Meant to be read in a terminal, so `| head` must not end in a traceback.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    raise SystemExit(main())
