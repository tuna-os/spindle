#!/usr/bin/env python3
"""What a repeated sitting can and cannot say, in one place.

A sitting used to be one round: every server measured once, one file per
server, a cell decided by the ratio of two numbers. #171 measured what one
round is worth -- six rounds of an *identical* binary on the same idle host
moved the median cell by 1.38x and the worst by 2.80x -- so a sitting is now
several rounds, every round is kept, and a cell is a list per server rather
than a number.

The arithmetic for reading those lists lives here, because two scripts need
it and it must not drift between them: `render-comparisons.py` colours the
published page with it, and `compare-benchmarks.py` prints a fresh sitting
with it. A page that called a cell the terminal would not, or the reverse,
is the kind of disagreement nobody notices until it matters.

Nothing here reads a file or knows a server's name. Lists of nanoseconds in,
verdicts and summaries out.
"""

from __future__ import annotations

import math
import statistics

# For a sitting that ran a single round there is no spread to read, so the
# band has to be assumed rather than measured -- and the assumption is the
# one docs/benchmarks.md actually measured: six rounds of the *same binary*
# on the same idle host moved the median cell by 1.38x, and 21 of 21 cells
# varied by more than the +/-10% band that used to colour the page.
#
# So a single-round cell below 1.38x is not a result in either direction,
# and colouring it was the page contradicting its own caption -- the legend
# said "treat anything inside roughly +/-0.4x as unmeasured" directly under
# cells painted green at 1.19x and red at 0.90x. The band now matches the
# evidence: only ratios that clear this host's own repeatability get a
# colour. Nothing about the underlying numbers changes, and the large
# ratios are untouched; what changes is which of them the page claims.
#
# A sitting with three rounds or more never reaches this: it has a real
# spread, and `verdict` reads it instead of assuming one.
SINGLE_ROUND_REPEATABILITY = 1.38
NOISE_LOW_SINGLE_ROUND = (1 / SINGLE_ROUND_REPEATABILITY, SINGLE_ROUND_REPEATABILITY)

# Below this many rounds a side the separation rule says nothing: see
# `chance_of_separating`. Two rounds mis-colour a third of the ties.
MIN_ROUNDS = 3

# What a sitting runs when nobody says otherwise. Three is the floor that
# makes the rule meaningful; five puts a chance separation at one cell in
# 126 rather than one in ten, which on a 27-cell table is the difference
# between expecting three spurious calls and expecting none. The cost is
# linear in rounds and the collection scripts take `--rounds` for when the
# hour is not available.
DEFAULT_ROUNDS = 5


def spread(values: list[float]) -> dict:
    """Median and the observed range of one cell across rounds.

    Min and max rather than a standard deviation: at three to five rounds
    there is no distribution to estimate, only the extremes actually seen,
    and the extremes are what the separation rule reads. The quartiles are
    kept for a sitting long enough to have them (five rounds or more); at
    fewer they collapse onto the extremes and say nothing new.
    """
    ordered = sorted(values)
    summary = {
        "median": statistics.median(ordered),
        "low": ordered[0],
        "high": ordered[-1],
        "rounds": len(ordered),
    }
    if len(ordered) >= 5:
        q1, _, q3 = statistics.quantiles(ordered, n=4, method="inclusive")
        summary["q1"], summary["q3"] = q1, q3
    return summary


def ratio_band(ours: list[float], theirs: list[float]) -> tuple[float, float]:
    """The range of ratios the observed rounds allow, theirs over ours.

    From their fastest round against our slowest to their slowest against
    our fastest. The separation rule in `verdict` is exactly the question
    of whether this band excludes 1.0: a win is a band entirely above it,
    a loss entirely below, and anything straddling it is unresolved. So
    printing the band beside the ratio shows the reader the rule at work
    rather than asking them to trust a colour.
    """
    return min(theirs) / max(ours), max(theirs) / min(ours)


def chance_of_separating(rounds: int) -> float:
    """Odds two *identical* servers separate by luck, at this many rounds.

    2/C(2n, n): one in three at n=2, one in ten at n=3, one in thirty-five
    at n=4, one in a hundred and twenty-six at n=5.
    """
    if rounds < 1:
        return 1.0
    return 2 / math.comb(2 * rounds, rounds)


def expected_false_calls(cells: int, rounds: int) -> float:
    """How many of `cells` should separate by chance alone.

    The separation rule bounds the false-call rate for *one* cell. A table
    is many cells, and nothing in the rule accounts for that: at three
    rounds a side the per-cell rate is one in ten, so eighteen cells expect
    close to two spurious calls. Reading a lone called cell as a result is
    then reading noise, which is the mistake #171 was filed for one level
    down. Stating the number is the cheap half of the fix (#183); the other
    half is `stands_alone` in render-comparisons.py.
    """
    return cells * chance_of_separating(rounds)


def verdict(ours: list[float], theirs: list[float]) -> tuple[str, str]:
    """Colour and label for one cell, decided by whether the rounds separate.

    With repeated rounds there is no noise band to pick: a cell is a win
    only if our *slowest* round beat their *fastest*, and a loss only if our
    fastest lost to their slowest. Anything else is two overlapping ranges,
    which is not a result however far apart the medians happen to sit. That
    replaces a +/-10% constant that was narrower than the harness's own
    repeatability, so every cell on the page cleared it by construction.

    Three rounds a side is the minimum, and that is arithmetic rather than
    taste. If the two servers were identical, the chance that all of one
    side's rounds happen to land below all of the other's is 2/C(2n, n):
    **one in three at n=2**, one in ten at n=3, one in thirty-five at n=4.
    Calling cells on two rounds would mis-colour about a third of the ties,
    which is the +/-10% band's mistake wearing a better disguise. So two
    rounds is treated as unresolved, and more rounds is how a smaller
    difference gets resolved.

    With fewer than three rounds each -- every sitting committed before
    #171 -- there is no spread to read, so the band is the repeatability
    this host was measured to have (see `SINGLE_ROUND_REPEATABILITY`) and
    the group is labelled unresolved.
    """
    ratio = statistics.median(theirs) / statistics.median(ours)
    if len(ours) < MIN_ROUNDS or len(theirs) < MIN_ROUNDS:
        if ratio >= NOISE_LOW_SINGLE_ROUND[1]:
            return "win", f"{ratio:.2f}×"
        if ratio <= NOISE_LOW_SINGLE_ROUND[0]:
            return "loss", f"{1 / ratio:.2f}× slower"
        return "noise", f"{ratio:.2f}×"
    if max(ours) < min(theirs):
        return "win", f"{ratio:.2f}×"
    if min(ours) > max(theirs):
        return "loss", f"{1 / ratio:.2f}× slower"
    return "noise", f"{ratio:.2f}×"


def rounds_in(counts: dict[str, int]) -> int:
    """How many rounds the thinnest server in a group was measured for.

    A comparison is only as resolved as its least-measured side.
    """
    return min(counts.values(), default=0)
