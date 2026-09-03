#!/usr/bin/env python3
"""Render the competitive-comparison page for the benchmark site.

The inputs are the raw result files `scripts/api-benchmark.py` wrote,
committed under docs/benchmarks/data/ exactly as measured. This script only
arranges them: every number on the page traces to a committed JSON, and
regenerating the page cannot change a measurement. Charts are inline SVG
computed from the same numbers as the tables — one source, two renderings.

Honesty rules, inherited from render-benchmarks.py and kept on purpose:
losses render with the same prominence as wins, a missing endpoint is an
honest dash rather than a fabricated column, and cells inside the measured
noise band say so instead of claiming a win either way. The runs happen on
a developer machine at milestone close (docs/benchmarks.md explains why a
shared CI runner cannot host both sides honestly), and the page says where
the numbers came from.

File naming: `<group>.<server>.r<N>.json` — one file per server per round
of a sitting — where `<group>` sorts by milestone (`m1-…`, `m2-…`) and
exactly one server per group is `spindle*`, the side ratios are computed
against. The older `<group>.<server>.json` is a single-round sitting and
still loads; the page labels those unresolved rather than pretending they
have a spread to read. The arithmetic for reading the rounds -- median,
observed range, the separation rule and its false-call rate -- is in
`sitting.py`, shared with `compare-benchmarks.py`.

Usage:
    scripts/render-comparisons.py docs/benchmarks/data comparisons.html
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import sys

import sitetheme
import sitting
from sitting import (
    MIN_ROUNDS,
    SINGLE_ROUND_REPEATABILITY,
    chance_of_separating,
    expected_false_calls,
    verdict,
)

SERVER_COLORS = sitetheme.SERVER_COLORS

# What each benchmarked operation actually asks the server to do, and why the
# storage architecture shows up in it. Rendered beside the latest charts so a
# reader never has to guess what a row measures.
# What the x-axis counts, per dimension. The driver records which one it
# measured; this is how that reaches the label.
AXIS = {"events": "events in room", "members": "joined members in room"}

OPERATIONS = {
    "send": (
        "Send a message",
        "One event appended to a room. Spindle assigns the next index in the "
        "room's linear log and folds one state snapshot forward; a DAG server "
        "must pick extremities, and its cost tends to grow with the room.",
    ),
    "sync_initial": (
        "Initial /sync",
        "A client's first sync: full state plus recent timeline for every "
        "room. Materialized state makes 'the state now' one content-addressed "
        "read instead of a resolution.",
    ),
    "sync_poll": (
        "Incremental /sync, nothing new",
        "The request a running client makes over and over: since=<token>, "
        "and the answer is usually \u201cnothing\u201d. It is the most common "
        "request a homeserver ever serves, and until M5 no sitting measured "
        "it at all.",
    ),
    "sync_delta": (
        "Incremental /sync, one event",
        "The same request when a room does have something waiting. It takes a "
        "different path from the empty poll -- the server skips rooms with no "
        "new events entirely -- so the two are measured separately rather "
        "than averaged into one misleading number.",
    ),
    "sliding_window": (
        "Sliding sync (MSC4186)",
        "The request Element X makes where classic clients call /sync: a "
        "sorted room-list window plus per-room state. The room-list question "
        "is one point read per room on Spindle's storage.",
    ),
    "messages_page": (
        "Paginate history",
        "A /messages page walking backwards. The linear log makes this a "
        "bounded range read — no topological sort at request time.",
    ),
    "state": (
        "Read room state",
        "The full current state of a room. The log's head entry carries the "
        "state root; answering is one rehydration of a hash trie.",
    ),
    "context_deep": (
        "Event context, deep",
        "The /context of an event far back in history. On a linear log an "
        "old event's neighbourhood is an index range, not a graph walk.",
    ),
    "join": (
        "Join a room",
        "A local user joins: one membership event through the same append "
        "path as any other, authorized against materialized state.",
    ),
}

# The record of every investigated slow cell: the roadmap treats a slower
# column as a defect until explained, and this is where the explanations
# live. Keyed by (group, operation) — a note renders under the group's
# heatmap and any red cell links down to it.
INVESTIGATIONS = {
    ("m3-progress", "sliding_window"): (
        "0.90× and 0.88× vs Continuwuity at 800 and 3,200 events — and the "
        "same cell sat at 0.83× in the M2 close-out, so two sittings agreed "
        "this was repeatable, not noise. A component probe on the live bench "
        "server found the room list's recency sort reading each room's head "
        "event body from the store and parsing its JSON on every request, "
        "for one i64. #126 moved the sort key into memory, refreshed by the "
        "append that changes it; re-measured on the same idle machine the "
        "cells recover to 0.96× and 1.00×, and Spindle's own growth curve "
        "flattens from 1.28× to 1.13× across a 16× room-size increase.",
    ),
    ("m3-final", "sliding_window"): (
        "0.77× vs Continuwuity at 3,200 events, and 0.85× in the same "
        "day's discarded loaded run — repeatable by the two-sitting rule, "
        "so it got the full second look. Both servers were probed live "
        "minutes after the sitting, same client, same instant, two "
        "shapes: like-for-like the gap does not exist (creator shape "
        "0.844 ms vs 0.854 ms, parity; the driver's exact observer shape "
        "0.785 ms vs 0.874 ms, Spindle 1.11× faster). The two sitting "
        "legs caught opposite sides of the machine's same-day swing. No "
        "fix ships because no defect was found; the cell keeps its "
        "measured value and links here — the honest kind of red.",
    ),
    ("m3-final", "sync_initial"): (
        "0.89× vs Tuwunel at 200 events in this sitting — and 1.21× in "
        "the same day's discarded run, with 800 and 3,200 in noise both "
        "times. A cell that flips sign between sittings hours apart is "
        "run-to-run variance, published as measured.",
    ),
    ("m2-final", "state"): (
        "0.85× vs Tuwunel at 200 events, and 0.93× again at M3 progress — "
        "the one cell Tuwunel held across two sittings, so the investigation "
        "started in their tree. Their /state serves each event through "
        "RocksDB's block cache; ours paid a room-lock acquisition, a body "
        "read and a JSON parse per state event, per request. Component "
        "probes showed their state machinery was never actually faster — "
        "their per-request pipeline is just leaner. #129 caches the rendered "
        "/state body under its BLAKE3 state root (content-addressed, so a "
        "hit is provably current and a root mismatch is the only "
        "invalidation); re-measured against the live Tuwunel binary the "
        "cell flips to 1.91× and 1.33× in Spindle's favour.",
    ),
    ("m2-final", "sliding_window"): (
        "0.87× vs Continuwuity at 3,200 events was the one real loss of the "
        "M2 close-out, and the only curve growing with room size. Bisecting "
        "a live server pinned it in one probe: the unread counter was "
        "reading every event body after the receipt floor. #113 replaced "
        "that walk with two binary searches over a per-room sender index — "
        "11.79 ms → 1.00 ms on the pathological case — and the M3 rows "
        "below show the cell recovered.",
    ),
}


def load_groups(data_dir: pathlib.Path) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for path in sorted(data_dir.glob("*.json")):
        # `group.server.json`, or `group.server.rN.json` for one round of a
        # repeated sitting. The group is the first segment either way, which
        # is why group names must not contain a dot.
        group = path.name.split(".")[0]
        document = json.loads(path.read_text())
        document["_file"] = path.name
        groups.setdefault(group, []).append(document)
    if not groups:
        # Refuse to render nothing: a blank page reads as "no losses".
        sys.exit(f"render-comparisons: no result files in {data_dir}")
    for group, documents in groups.items():
        ours = {
            d["server"] for d in documents if d["server"].startswith("spindle")
        }
        if len(ours) != 1:
            sys.exit(
                f"render-comparisons: group {group} needs exactly one spindle "
                f"server, found {len(ours)} — a ratio needs a fixed side"
            )
    return groups


def color_for(server: str) -> str:
    for prefix, color in SERVER_COLORS.items():
        if server.startswith(prefix):
            return color
    return "#888888"


def short_name(server: str) -> str:
    return server.split("-")[0]


def cells_for(documents: list[dict]):
    """(operation, size) -> {server: [mean_ns per round]}.

    A list, not a number, because one round cannot tell a real difference
    from this host's run-to-run variance: six rounds of an identical binary
    move the median cell by 1.38x and the worst by 2.80x (#171). Keeping
    every round is what lets `verdict` below decide from the data rather
    than from a constant.
    """
    table: dict[tuple[str, int], dict[str, list[float]]] = {}
    for document in documents:
        for key, entry in document["benchmarks"].items():
            operation, _, size = key.rpartition("/")
            table.setdefault((operation, int(size)), {}).setdefault(
                document["server"], []
            ).append(entry["mean_ns"])
    return table


def rounds_in(documents: list[dict]) -> int:
    """How many rounds the thinnest server in this group was measured for."""
    counts: dict[str, int] = {}
    for document in documents:
        counts[document["server"]] = counts.get(document["server"], 0) + 1
    return sitting.rounds_in(counts)


def describe_ms(values: list[float]) -> str:
    """`1.18 ms`, or with rounds `1.18 ms (5 rounds, 1.10–1.31)`.

    The median is the number; the range is what it is worth. Both sides of
    a cell get this, because a spread printed for one server and not the
    other invites reading the other as exact.
    """
    summary = sitting.spread(values)
    text = f"{summary['median'] / 1e6:.2f} ms"
    if summary["rounds"] >= 2:
        text += (
            f" ({summary['rounds']} rounds, {summary['low'] / 1e6:.2f}–"
            f"{summary['high'] / 1e6:.2f})"
        )
    return text


def stands_alone(calls: dict[int, str], measured: set[int], size: int) -> bool:
    """Is this call unsupported by the same operation at any other size?

    A real difference in a per-item cost shows up across the size axis --
    that is what makes it a cost rather than a coincidence. A call standing
    alone at one size, with the same operation unresolved on either side of
    it, is exactly the shape a multiplicity artifact takes: #181's sitting
    called `joined_members/200` a regression while 50 and 800 showed
    nothing, and there was no code path from the change to that endpoint at
    all.

    An operation measured at a *single* size is not evidence either way, and
    is never marked. The question this asks is whether the size axis
    corroborates the call, and a sweep of one has no size axis to ask -- a
    marker there would read as doubt drawn from data that was never
    collected.

    This never overturns a call. The arithmetic says roughly how many cells
    in a table separate by chance, never which, so the verdict stands and
    the marker records that nothing else supports it.
    """
    if len(measured) < 2:
        return False
    mine = calls.get(size)
    return not any(
        other == mine for at_size, other in calls.items() if at_size != size
    )


def svg_chart(
    operation: str,
    sizes: list[int],
    series: dict[str, list[dict | None]],
    dimension: str = "events",
) -> str:
    """One small-multiple: median latency across room sizes, a line per server.

    Each point is a `sitting.spread` -- the median over rounds, and the
    lowest and highest round -- and the range is drawn as a band behind the
    line whenever there is more than one round to draw it from. A line on
    its own says the medians differ; the bands say whether that difference
    is bigger than either server's own round-to-round movement, which is
    the only question the separation rule asks.

    `dimension` is what the x-axis counts -- events in the room, or joined
    members in it. It is read from the results rather than assumed, because
    the two are different questions and a chart that labels one as the other
    is a wrong chart, not a mislabelled one.

    Linear y from zero, per-chart scale: honest about relative gaps within an
    operation, labelled so charts are never compared to each other by eye
    without reading the axis.
    """
    width, height = 320, 190
    left, right, top, bottom = 46, 10, 26, 34
    plot_w, plot_h = width - left - right, height - top - bottom
    peak = max(
        (v["high"] for values in series.values() for v in values if v is not None),
        default=1.0,
    )
    peak *= 1.08

    def x(index: int) -> float:
        return left + plot_w * (index / max(1, len(sizes) - 1))

    def y(value: float) -> float:
        return top + plot_h * (1 - value / peak)

    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{html.escape(operation)} latency by "'
        f'{html.escape(AXIS[dimension])}">'
    ]
    title = OPERATIONS.get(operation, (operation, ""))[0]
    parts.append(
        f'<text x="{left}" y="15" class="ctitle">{html.escape(title)}</text>'
    )
    # Gridlines at 0, half, peak.
    for value in (0.0, peak / 2, peak):
        parts.append(
            f'<line x1="{left}" y1="{y(value):.1f}" x2="{width - right}" '
            f'y2="{y(value):.1f}" class="grid"/>'
        )
        parts.append(
            f'<text x="{left - 4}" y="{y(value) + 3:.1f}" class="tick" '
            f'text-anchor="end">{value / 1e6:.1f}</text>'
        )
    parts.append(
        f'<text x="12" y="{top + plot_h / 2:.0f}" class="tick" '
        f'transform="rotate(-90 12 {top + plot_h / 2:.0f})" '
        f'text-anchor="middle">ms</text>'
    )
    for index, size in enumerate(sizes):
        parts.append(
            f'<text x="{x(index):.1f}" y="{height - 18}" class="tick" '
            f'text-anchor="middle">{size:,}</text>'
        )
    parts.append(
        f'<text x="{left + plot_w / 2:.0f}" y="{height - 4}" class="tick" '
        f'text-anchor="middle">{html.escape(AXIS[dimension])}</text>'
    )
    # Spindle last, so it draws over the rivals rather than under them, and
    # heavier. Every line used to be 2.2px in its own colour, which left the
    # reader matching hues against a legend to find the one line the page
    # exists to show. Ours is the subject; theirs is the context.
    ordered = sorted(series.items(), key=lambda item: item[0].startswith("spindle"))
    for server, values in ordered:
        mine = server.startswith("spindle")
        color = color_for(server)
        measured = [(x(i), v) for i, v in enumerate(values) if v is not None]
        if not measured:
            continue
        points = [(px, y(v["median"])) for px, v in measured]
        path = " ".join(
            f"{'M' if i == 0 else 'L'}{px:.1f},{py:.1f}"
            for i, (px, py) in enumerate(points)
        )
        safe = html.escape(server, quote=True)
        group = "series mine" if mine else "series"
        stroke = "3.4" if mine else "1.6"
        radius = "3.2" if mine else "2.2"
        fade = "" if mine else ' opacity="0.62"'
        parts.append(f'<g class="{group}" data-server="{safe}">')
        # The observed range across rounds, behind the line. Drawn only when
        # there is a range: a single-round sitting has none, and a band of
        # zero height would claim a precision it never measured.
        if any(v["rounds"] >= 2 for _, v in measured):
            upper = [f"{px:.1f},{y(v['high']):.1f}" for px, v in measured]
            lower = [f"{px:.1f},{y(v['low']):.1f}" for px, v in reversed(measured)]
            parts.append(
                f'<polygon class="band" points="{" ".join(upper + lower)}" '
                f'fill="{color}" opacity="{0.18 if mine else 0.11}"/>'
            )
        parts.append(
            f'<path d="{path}" fill="none" stroke="{color}" '
            f'stroke-width="{stroke}" stroke-linejoin="round" '
            f'stroke-linecap="round"{fade}/>'
        )
        for (px, py), (_, value) in zip(points, measured):
            # Ours get a halo so the marker reads against a crossing line.
            if mine:
                parts.append(
                    f'<circle cx="{px:.1f}" cy="{py:.1f}" r="4.6" '
                    f'fill="var(--bg)"/>'
                )
            tip = f"{value['median'] / 1e6:.2f} ms"
            if value["rounds"] >= 2:
                tip += (
                    f" ({value['rounds']} rounds, {value['low'] / 1e6:.2f}–"
                    f"{value['high'] / 1e6:.2f})"
                )
            parts.append(
                f'<circle cx="{px:.1f}" cy="{py:.1f}" r="{radius}" '
                f'fill="{color}"{fade}>'
                f"<title>{safe}: {tip}</title></circle>"
            )
        # Named on the line itself, at its last point: the one series worth
        # identifying without a trip to the legend.
        if mine:
            end_x, end_y = points[-1]
            anchor = "end" if end_x > left + plot_w * 0.6 else "start"
            nudge = -6 if anchor == "end" else 6
            parts.append(
                f'<text x="{end_x + nudge:.1f}" y="{end_y - 8:.1f}" '
                f'class="mine-label" text-anchor="{anchor}">Spindle</text>'
            )
        parts.append("</g>")
    parts.append("</svg>")
    return "".join(parts)


def scoreboard(documents: list[dict]):
    """Count won / within-noise / lost cells for one group."""
    us = next(d["server"] for d in documents if d["server"].startswith("spindle"))
    table = cells_for(documents)
    won = noise = lost = 0
    for by_server in table.values():
        mine = by_server.get(us)
        if not mine:
            continue
        for server, theirs in by_server.items():
            if server == us:
                continue
            css, _ = verdict(mine, theirs)
            if css == "win":
                won += 1
            elif css == "loss":
                lost += 1
            else:
                noise += 1
    return won, noise, lost


def render_heatmap(group: str, documents: list[dict]) -> list[str]:
    ours = next(d for d in documents if d["server"].startswith("spindle"))
    # One column group per *server*, not per document. A multi-round sitting
    # contributes one file per round, and taking them all would render the
    # same rival two or three times over -- invisible while every published
    # group was a single round, and wrong the moment one is not. The rounds
    # are already gathered by `cells_for`; this only needs the names.
    seen: dict[str, dict] = {}
    for document in documents:
        if not document["server"].startswith("spindle"):
            seen.setdefault(document["server"], document)
    theirs = [seen[server] for server in sorted(seen)]
    table = cells_for(documents)
    sizes = sorted({size for _, size in table})
    operations = sorted({operation for operation, _ in table})

    lines = ['<div class="scroll"><table class="heatmap"><thead><tr><th>operation</th>']
    for document in theirs:
        lines.append(
            f'<th colspan="{len(sizes)}">vs {html.escape(document["server"])}</th>'
        )
    lines.append("</tr><tr><th></th>")
    for _ in theirs:
        for size in sizes:
            lines.append(f'<th class="num">{size:,}</th>')
    lines.append("</tr></thead><tbody>")

    # Every cell's verdict up front, because whether a call stands alone is a
    # property of its row rather than of the cell: the marker below needs the
    # same operation's other sizes, which the emitting loop has not reached
    # yet.
    verdicts: dict[tuple[str, str, int], tuple[str, str]] = {}
    for operation in operations:
        for document in theirs:
            for size in sizes:
                cell = table.get((operation, size), {})
                mine = cell.get(ours["server"])
                other = cell.get(document["server"])
                if mine and other:
                    verdicts[operation, document["server"], size] = verdict(mine, other)
    comparable = len(verdicts)
    called = sum(1 for css, _ in verdicts.values() if css != "noise")
    # The multiplicity arithmetic describes the *separation* rule -- it is
    # the chance that n rounds a side fall clear of each other. A group with
    # fewer rounds than that is coloured by the old band instead, where
    # 2/C(2n, n) says nothing, so neither the count nor the marker applies.
    # Every sitting published before #171 is in that case.
    resolved = rounds_in(documents) >= MIN_ROUNDS

    for operation in operations:
        title = OPERATIONS.get(operation, (operation, ""))[0]
        lines.append(
            f"<tr><td><strong>{html.escape(title)}</strong> "
            f"<code>{html.escape(operation)}</code></td>"
        )
        for document in theirs:
            measured = {
                at_size
                for at_size in sizes
                if (operation, document["server"], at_size) in verdicts
            }
            calls = {
                at_size: verdicts[operation, document["server"], at_size][0]
                for at_size in measured
                if verdicts[operation, document["server"], at_size][0] != "noise"
            }
            for size in sizes:
                cell = table.get((operation, size), {})
                mine = cell.get(ours["server"])
                other = cell.get(document["server"])
                if not mine or not other:
                    lines.append('<td class="num absent">—</td>')
                    continue
                note_id = None
                if (group, operation) in INVESTIGATIONS:
                    note_id = f"note-{group}-{operation}"
                css, label = verdict(mine, other)
                # An investigation outranks the size axis: the marker means
                # "nothing corroborates this call", and a cell whose cause
                # has been found in the other server's code is corroborated
                # by something better than a neighbouring cell. `state` vs
                # Tuwunel is a real lead with a real mechanism, not a chance
                # separation that happens to sit at one size.
                #
                # Only for losses, because only losses carry notes -- the
                # roadmap treats a loss as a defect until explained, and
                # nothing writes an investigation for a win. Exempting wins
                # on a note written about the losing cell in the same row
                # would be reading someone else's evidence.
                explained = note_id is not None and css == "loss"
                lone = (
                    resolved
                    and css in ("win", "loss")
                    and not explained
                    and stands_alone(calls, measured, size)
                )
                body = html.escape(label)
                if css == "loss" and note_id:
                    body = f'<a href="#{note_id}">{body}</a>'
                if lone:
                    css = f"{css} lone"
                    body += " <span class='lone-mark'>†</span>"
                tip = (
                    f"spindle {describe_ms(mine)} · "
                    f'{html.escape(document["server"])} {describe_ms(other)}'
                )
                # The ratio is a median against a median; the band under it
                # is what the rounds actually allow, from their fastest
                # against our slowest to their slowest against our fastest.
                # A call is exactly a band that excludes 1.0x, so the reader
                # can see the rule applied rather than take the colour on
                # trust. Single-round cells have no band, and printing one
                # would be printing a spread that was never measured.
                if len(mine) >= 2 and len(other) >= 2:
                    low, high = sitting.ratio_band(mine, other)
                    body += f'<span class="band">{low:.2f}–{high:.2f}×</span>'
                    tip += f" · the rounds allow {low:.2f}–{high:.2f}×"
                if lone:
                    tip += (
                        " · stands alone: this operation is not called the "
                        "same way at any other size"
                    )
                lines.append(
                    f'<td class="num {css}" data-tip="{tip}" title="{tip}">'
                    f"{body}</td>"
                )
        lines.append("</tr>")
    lines.append("</tbody></table></div>")
    rounds = rounds_in(documents)
    if rounds >= MIN_ROUNDS:
        lines.append(
            f'<p class="legend">Measured over <strong>{rounds} rounds</strong> '
            "per server. The large figure in a cell is the median over rounds "
            "against the median over rounds; the small range under it is the "
            "band the rounds allow — their fastest round against our slowest, "
            "to their slowest against our fastest. A cell is called only when "
            "that band excludes 1.0×, which is the same as saying the two "
            "servers' rounds <em>separate</em>: "
            '<span class="chip win">win</span> our slowest round beat their '
            'fastest · <span class="chip noise">overlapping</span> the ranges '
            "cross, so the difference is not resolved by this many rounds, "
            'whatever the medians say · <span class="chip loss">loss</span> '
            "our fastest round lost to their slowest — every such cell links "
            "to its investigation, because the roadmap treats it as a defect "
            "until explained. Hover any cell for both servers' medians and "
            "observed ranges in milliseconds.</p>"
        )
        expected = expected_false_calls(comparable, rounds)
        lines.append(
            f'<p class="legend">That rule bounds the false-call rate for '
            f"<em>one</em> cell, and this table has <strong>{comparable}"
            "</strong>. Two identical servers separate by luck "
            f"{chance_of_separating(rounds):.1%} of the time at {rounds} "
            f"rounds, so about <strong>{expected:.1f}</strong> of these cells "
            f"should be called by chance alone — against {called} actually "
            "called. The arithmetic cannot say <em>which</em> ones, so a call "
            "marked <span class=\"chip lone\">†</span> is one that stands "
            "alone: the same operation is not called the same way at any "
            "other size. A cost that is real in a per-item measure normally "
            "shows across the size axis, so an isolated call is the shape a "
            "chance separation takes. Read those as unconfirmed rather than "
            "as results (#183).</p>"
        )
    else:
        lines.append(
            f'<p class="legend"><strong>{rounds} round(s) per server — not '
            "resolved.</strong> Three rounds a side is the minimum that means "
            "anything: if two servers were identical, all of one side's rounds "
            "landing below all of the other's happens by chance 2/C(2n, n) of "
            "the time — one in three at two rounds, one in ten at three. "
            "With no spread to read, the cells below are coloured by the "
            "repeatability this host was <em>measured</em> to have: six "
            "rounds of the same binary moved the median cell "
            f"<strong>{SINGLE_ROUND_REPEATABILITY:.2f}&times;</strong>, and "
            "21 of 21 cells varied by more than the &plusmn;10% band this "
            "page used to use. So: "
            f'<span class="chip win">&ge;{SINGLE_ROUND_REPEATABILITY:.2f}'
            "&times;</span> · "
            f'<span class="chip noise">{1 / SINGLE_ROUND_REPEATABILITY:.2f}'
            f'–{SINGLE_ROUND_REPEATABILITY:.2f}×</span> · '
            f'<span class="chip loss">&le;'
            f'{1 / SINGLE_ROUND_REPEATABILITY:.2f}&times;</span>. '
            "A grey cell is not a tie — it is a difference this sitting "
            "cannot see, and only more rounds can (#171). The large ratios "
            "are unaffected. Hover any cell for the raw milliseconds.</p>"
        )
    notes = [
        (operation, text)
        for (note_group, operation), (text,) in sorted(INVESTIGATIONS.items())
        if note_group == group
    ]
    # A note exists because a cell read red and the roadmap treats that as a
    # defect until explained. Under the measured band some of those cells no
    # longer read as anything, and two of these notes concluded exactly that
    # on their own evidence -- so the notes stay, and say why they stay.
    # Dropping them would delete the reason we know the cell was not real.
    if notes and not any(css == "loss" for css, _ in verdicts.values()):
        lines.append(
            '<p class="legend">Nothing in this sitting reads as a loss under '
            "the band above. The investigations below were written when it "
            "did, and are kept because they are the evidence for the "
            "conclusion, not a footnote to it.</p>"
        )
    for operation, text in notes:
        title = OPERATIONS.get(operation, (operation, ""))[0]
        lines.append(
            f'<p class="investigation" id="note-{group}-{operation}">'
            f"<strong>Investigated — {html.escape(title)}:</strong> "
            f"{html.escape(text)}</p>"
        )
    return lines


def dimension_of(documents: list[dict]) -> str:
    """What this group's x-axis counts.

    Absent from every file written before the members sweep existed, and
    those all measured events -- so the default is not a guess, it is what
    those runs did.
    """
    found = {document.get("dimension", "events") for document in documents}
    if len(found) != 1:
        sys.exit(
            "render-comparisons: one group mixes "
            f"{', '.join(sorted(found))} on one axis -- they are different "
            "questions and cannot share a chart"
        )
    return found.pop()


def render_charts(documents: list[dict]) -> list[str]:
    table = cells_for(documents)
    sizes = sorted({size for _, size in table})
    operations = sorted({operation for operation, _ in table})
    servers = sorted(
        (d["server"] for d in documents),
        key=lambda s: (not s.startswith("spindle"), s),
    )
    lines = ['<div class="charts">']
    for operation in operations:
        series = {
            server: [
                (
                    sitting.spread(rounds)
                    if (rounds := table.get((operation, size), {}).get(server))
                    else None
                )
                for size in sizes
            ]
            for server in servers
        }
        explainer = OPERATIONS.get(operation, (operation, ""))[1]
        lines.append('<figure class="chart">')
        lines.append(svg_chart(operation, sizes, series, dimension_of(documents)))
        if explainer:
            lines.append(f"<figcaption>{html.escape(explainer)}</figcaption>")
        lines.append("</figure>")
    lines.append("</div>")
    # Ours first and marked, matching the charts: the reader should meet the
    # subject before the field it is being compared against.
    legend = " ".join(
        f'<span class="serverchip{" mine" if server.startswith("spindle") else ""}" '
        f'data-server="{html.escape(server, quote=True)}">'
        f'<span class="dot" style="background:{color_for(server)}"></span>'
        f"{html.escape(server)}</span>"
        for server in sorted(servers, key=lambda s: not s.startswith("spindle"))
    )
    legend += (
        '<span class="legend"> — hover a server to isolate its line in every '
        "chart</span>"
    )
    lines.insert(1, f'<p class="serverlegend">{legend}</p>')
    return lines


ARCHITECTURE = """
<section class="arch" id="architecture">
<h2>Why the shape of the storage shows up in every row</h2>
<p>Watch the same six events arrive at both designs, then watch one read
ask <em>"what is the state?"</em> The loop below plays the whole
difference: on one side the answer must be computed; on the other it was
already written down.</p>
<div class="archgrid anim">
<div class="archcol">
<h3>A conventional homeserver</h3>
<svg viewBox="0 0 300 220" role="img"
     aria-label="events form a DAG; a state read runs state resolution across the branches before it can answer">
  <g class="a p1"><circle class="node" cx="150" cy="25" r="9"/></g>
  <g class="a p2"><line class="edge" x1="150" y1="34" x2="150" y2="51"/>
    <circle class="node" cx="150" cy="60" r="9"/></g>
  <g class="a p3"><line class="edge" x1="150" y1="69" x2="103" y2="87"/>
    <circle class="node" cx="100" cy="95" r="9"/></g>
  <g class="a p4"><line class="edge" x1="150" y1="69" x2="197" y2="87"/>
    <circle class="node" cx="200" cy="95" r="9"/>
    <text class="archlabel" x="238" y="99">a fork &#8212; normal</text></g>
  <g class="a p5"><line class="edge" x1="100" y1="104" x2="87" y2="122"/>
    <circle class="node" cx="85" cy="130" r="9"/></g>
  <g class="a p6"><line class="edge" x1="200" y1="104" x2="213" y2="122"/>
    <circle class="node" cx="215" cy="130" r="9"/></g>
  <g class="a pask"><text class="ask" x="16" y="170">read: "what is the state?"</text></g>
  <g class="a pring"><circle class="ring" cx="0" cy="0" r="14"/></g>
  <g class="a presolve"><text class="resolve" x="16" y="188">resolving branches&#8230;</text></g>
  <g class="a pdagdone"><text class="done" x="222" y="188">state ready</text></g>
  <rect class="track" x="16" y="198" width="268" height="7" rx="3.5"/>
  <rect class="a pbarslow fill-slow" x="16" y="198" width="268" height="7" rx="3.5"
        style="transform-origin: 16px 198px"/>
</svg>
<p>Rooms are a directed graph of events. Forks are normal, so answering
"what is the state?" means running <em>state resolution</em> over the
branches — work that grows with the room and sits on the hot path of
sync, send, and join.</p>
</div>
<div class="archcol">
<h3>Spindle</h3>
<svg viewBox="0 0 300 220" role="img"
     aria-label="events append to one log; every entry already carries its state root, so a state read answers immediately">
  <g class="a p1"><rect class="cellr" x="16" y="85" width="38" height="26" rx="4"/></g>
  <g class="a p2"><rect class="cellr" x="61" y="85" width="38" height="26" rx="4"/></g>
  <g class="a p3"><rect class="cellr" x="106" y="85" width="38" height="26" rx="4"/></g>
  <g class="a p4"><rect class="cellr" x="151" y="85" width="38" height="26" rx="4"/>
    <text class="archlabel" x="170" y="130" text-anchor="middle">ordered at</text>
    <text class="archlabel" x="170" y="142" text-anchor="middle">the door</text></g>
  <g class="a p5"><rect class="cellr" x="196" y="85" width="38" height="26" rx="4"/></g>
  <g class="a p6"><rect class="cellr" x="241" y="85" width="38" height="26" rx="4"/>
    <line class="edge" x1="260" y1="85" x2="260" y2="62"/>
    <rect class="rootc" x="228" y="40" width="64" height="22" rx="5"/>
    <text class="roott" x="260" y="54" text-anchor="middle">state root</text></g>
  <g class="a pask"><text class="ask" x="16" y="170">read: "what is the state?"</text></g>
  <g class="a plogdone"><text class="done" x="222" y="188">state ready</text>
    <text class="archlabel" x="16" y="188">one content-addressed read</text></g>
  <rect class="track" x="16" y="198" width="268" height="7" rx="3.5"/>
  <rect class="a pbarfast fill-fast" x="16" y="198" width="268" height="7" rx="3.5"
        style="transform-origin: 16px 198px"/>
</svg>
<p>Each room is an append-only log with <em>materialized state</em>: every
entry carries the content address (BLAKE3 hash trie) of the state after
it. "The state now" is one read; history is a range; nothing resolves on
the hot path. Federation forks are collapsed at the door, bounded, and
never taxed on reads.</p>
</div>
</div>
<p class="lineage">
<span><b>append-only log</b> &#183; Kafka, Raft</span>
<span><b>content-addressed state</b> &#183; git, Merkle trees</span>
<span><b>HAMT snapshots</b> &#183; Clojure, CHAMP</span>
<span><b>single-writer order</b> &#183; LMAX, TigerBeetle</span>
<span><b>losses published</b> &#183; every red cell links its investigation</span>
</p>
<p>That is the bet these pages test. The comparisons below measure the same
client operations against the same workloads on Synapse (the reference
implementation) and on Continuwuity and Tuwunel (the two Rust siblings,
both descended from Conduit) — and when a cell goes the wrong way, the
roadmap's rule is that it gets investigated, not explained away.</p>
</section>
"""

METHOD = """
<section id="method">
<h2>Method</h2>
<ul>
<li><strong>Same host, same sitting, same load.</strong> All servers in one
run on one idle machine — a leg once ran beside a compiler and read ~25%
slow across the board, so idleness is part of the method, and it is checked,
not assumed.</li>
<li><strong>Cold databases, verified binaries.</strong> Every leg starts
from an empty store, and the serving process is pgrep-verified before
measuring — a stale process once served an old binary on the right port.</li>
<li><strong>Curves, not points.</strong> Every operation is measured at
200, 800 and 3,200 events per room, because the failure mode worth catching
is the cost that grows with the room. Room size has a second axis —
<em>joined members</em> — and the sweep held it at two until M5, which hid
a sliding-window read that grew linearly with the member list. Membership
is now its own sweep, on its own chart, labelled by what it counts.</li>
<li><strong>A sitting is several rounds, not one.</strong> Each round
takes the median of 25 samples after warmup, per cell; a sitting repeats
that five times per server by default (three is the minimum that means
anything — see below), reversing the order of the servers every round so a
drift in the machine becomes spread the page can see rather than bias it
cannot. Every round is committed exactly as the driver wrote it
(<code>docs/benchmarks/data/&lt;group&gt;.&lt;server&gt;.r&lt;N&gt;.json</code>);
a published cell is the median across rounds with the observed range
beside it, and this page is regenerated from those files and cannot change
a measurement.</li>
<li><strong>Losses publish with the same prominence as wins.</strong>
A cell is called, either way, only when the two servers' rounds separate,
and a loss links to its investigation.</li>
<li><strong>The instrument's own spread is on the page, because it is
wider than the band this page used to colour by.</strong> Six rounds of
the same binary on the same idle host moved the median cell by 1.38× and
the worst by 2.80×, so every cell varied more between runs of identical
code than the ±10% that used to decide its colour. That is why the band
was replaced rather than tuned
(<a href="https://github.com/tuna-os/spindle/issues/171">#171</a>): a cell
is now decided by whether the two servers' own round-to-round ranges
overlap, and the range is printed under every ratio so a reader can see
what it had to clear. Sittings collected before #171 are one round each,
have no range to read, and are coloured by the measured 1.38× floor
instead — labelled unresolved, and never given the count and marker that
only the separation rule can justify.</li>
</ul>
<p>Versions measured, ports, registration quirks and the full narrative per
sitting: <a href="https://github.com/tuna-os/spindle/blob/main/docs/benchmarks.md">
docs/benchmarks.md</a>.</p>
</section>
"""

STYLE = """
/* ---------- hero ---------- */
.hero { position: relative; overflow: hidden; border-radius: 0 0 18px 18px;
  background: linear-gradient(135deg, var(--hero-a), var(--hero-b));
  padding: 46px 28px 34px; margin: 0 -20px; }
.hero h1 { font-size: clamp(1.9rem, 4.5vw, 2.9rem); margin: 0 0 6px;
  letter-spacing: -0.02em;
  background: linear-gradient(90deg, var(--accent), var(--accent2));
  -webkit-background-clip: text; background-clip: text; color: transparent; }
.hero .sub { color: var(--fg); opacity: .78; max-width: 62ch; margin: 0 0 18px;
  font-size: 1.05rem; }
.ticker { display: flex; gap: 6px; align-items: center; height: 26px;
  margin-bottom: 10px; }
.ticker .cell { width: 22px; height: 16px; border-radius: 4px;
  background: var(--accent); opacity: .16; }
.ticker .cell.on { animation: tick 4.8s linear infinite; }
.ticker .cell.on:nth-child(2) { animation-delay: .6s; }
.ticker .cell.on:nth-child(3) { animation-delay: 1.2s; }
.ticker .cell.on:nth-child(4) { animation-delay: 1.8s; }
.ticker .cell.on:nth-child(5) { animation-delay: 2.4s; }
.ticker .cell.on:nth-child(6) { animation-delay: 3.0s; }
.ticker .cell.on:nth-child(7) { animation-delay: 3.6s; }
.ticker .root-chip { font-size: .72rem; color: var(--accent);
  border: 1px solid var(--accent); border-radius: 5px; padding: 0 6px;
  animation: pulse 4.8s ease-in-out infinite; white-space: nowrap; }
@keyframes tick { 0% { opacity: .16 } 8% { opacity: 1 } 55% { opacity: .85 }
  100% { opacity: .16 } }
@keyframes pulse { 0%,100% { transform: scale(1); opacity: .75 }
  8% { transform: scale(1.12); opacity: 1 } }

.scoreline { display: flex; gap: 14px; flex-wrap: wrap; margin: 18px 0 0; }
.score { background: color-mix(in srgb, var(--bg) 78%, transparent);
  border: 1px solid var(--line); border-radius: 12px; padding: 10px 18px;
  text-align: center; box-shadow: var(--shadow); }
.score b { display: block; font-size: 1.7rem; font-variant-numeric: tabular-nums; }
.score.win b { color: var(--win-fg); } .score.loss b { color: var(--loss-fg); }
.score.noise b { color: var(--noise-fg); }

/* ---------- charts ---------- */
.charts { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 18px; margin-top: 14px; }
.chart { margin: 0; background: var(--card); border: 1px solid var(--line);
  border-radius: 12px; padding: 10px; box-shadow: var(--shadow);
  opacity: 0; transform: translateY(14px);
  transition: opacity .5s ease, transform .5s ease; }
.chart.in { opacity: 1; transform: none; }
.chart svg { width: 100%; height: auto; }
.chart figcaption { font-size: 0.82rem; color: var(--muted); padding: 4px 6px 2px; }
.ctitle { font-size: 13px; font-weight: 600; fill: var(--fg); }
.tick { font-size: 10px; fill: var(--muted); }
.grid { stroke: var(--line); stroke-width: 1; }
.series { transition: opacity .18s ease; }
.series.dim { opacity: .14; }
/* Ours is named on the line. The rivals stay in the legend, where context
   belongs; the subject of the chart should not need looking up. */
.mine-label { font-size: 10px; font-weight: 700; fill: var(--accent);
  paint-order: stroke; stroke: var(--bg); stroke-width: 3px;
  stroke-linejoin: round; }
.serverchip.mine { color: var(--fg); font-weight: 650;
  border-color: var(--accent); background: var(--card); }
.serverlegend { margin: 6px 0 0; }
.serverchip { margin-right: 12px; font-size: 0.9rem; color: var(--muted);
  cursor: pointer; border: 1px solid transparent; border-radius: 8px;
  padding: 2px 8px; display: inline-block; }
.serverchip:hover { border-color: var(--line); background: var(--card);
  color: var(--fg); }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
  margin-right: 6px; }

/* ---------- heatmap ---------- */
.heatmap tbody tr:hover td { filter: brightness(1.06); }
.heatmap td.win { background: var(--win-bg); color: var(--win-fg); }
.heatmap td.loss { background: var(--loss-bg); color: var(--loss-fg); }
.heatmap td.loss a { color: inherit; }
.heatmap td.noise { background: var(--noise-bg); color: var(--noise-fg); }
.heatmap td.absent { color: var(--muted); }
/* The range the rounds allow, under the ratio of medians. Quiet on
   purpose: it is the evidence for the colour, not a second headline. */
.heatmap td .band { display: block; font-size: .68rem; font-weight: 400;
  opacity: .72; line-height: 1.2; font-variant-numeric: tabular-nums; }
.heatmap td[data-tip] { position: relative; cursor: help; }
.heatmap td[data-tip]:hover::after { content: attr(data-tip);
  position: absolute; right: 0; bottom: calc(100% + 6px); z-index: 6;
  background: var(--fg); color: var(--bg); padding: 5px 10px;
  border-radius: 8px; font-size: .8rem; white-space: nowrap;
  box-shadow: var(--shadow); pointer-events: none; }
/* A called cell with no agreeing call at another size. Marked rather than
   recoloured: the arithmetic says roughly how many calls in a table are
   chance, never which, so overriding the verdict would be inventing a
   certainty the numbers do not carry. */
.chip.lone { background: transparent; border: 1px dashed var(--muted);
  color: var(--muted); }
.heatmap td.lone { background-image: repeating-linear-gradient(
  45deg, transparent, transparent 5px,
  rgba(127, 127, 127, 0.22) 5px, rgba(127, 127, 127, 0.22) 10px); }
.lone-mark { opacity: 0.75; font-size: 0.85em; vertical-align: super; }
.investigation { background: var(--card); border-left: 4px solid var(--accent);
  padding: 10px 14px; border-radius: 6px; }

/* ---------- architecture animation ---------- */
.arch p { max-width: 70ch; }
.archgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px; }
.archcol { background: var(--card); border: 1px solid var(--line); border-radius: 12px;
  padding: 14px 18px; box-shadow: var(--shadow);
  opacity: 0; transform: translateY(14px);
  transition: opacity .5s ease, transform .5s ease; }
.archcol.in { opacity: 1; transform: none; }
.archcol svg { width: 100%; height: auto; }
.archlabel { font-size: 11px; fill: var(--muted); }
.archsmall { font-size: 10px; fill: var(--fg); }
.anim .node { fill: var(--card); stroke: var(--muted); stroke-width: 2; }
.anim .edge { stroke: var(--muted); stroke-width: 1.4; }
.anim .cellr { fill: var(--card); stroke: var(--muted); stroke-width: 2; }
.anim .rootc { fill: none; stroke: var(--accent); stroke-width: 1.6; }
.anim .roott { font-size: 9px; fill: var(--accent); }
.anim .ask { font-size: 11px; font-weight: 600; fill: var(--fg); }
.anim .resolve { font-size: 10px; fill: var(--loss-fg); font-weight: 600; }
.anim .done { font-size: 10px; fill: var(--win-fg); font-weight: 700; }
.anim .track { fill: var(--noise-bg); }
.anim .fill-slow { fill: var(--loss-fg); transform-origin: 0 0; }
.anim .fill-fast { fill: var(--win-fg); transform-origin: 0 0; }
.anim .ring { fill: none; stroke: var(--loss-fg); stroke-width: 2.5;
  stroke-dasharray: 4 3; }
/* Shared 12s loop; every element hides itself before the restart. */
.anim .a { animation-duration: 12s; animation-iteration-count: infinite;
  animation-timing-function: linear; }
@keyframes ap1 { 0%,2% {opacity:0} 4%,96% {opacity:1} 99%,100% {opacity:0} }
@keyframes ap2 { 0%,7% {opacity:0} 9%,96% {opacity:1} 99%,100% {opacity:0} }
@keyframes ap3 { 0%,12% {opacity:0} 14%,96% {opacity:1} 99%,100% {opacity:0} }
@keyframes ap4 { 0%,17% {opacity:0} 19%,96% {opacity:1} 99%,100% {opacity:0} }
@keyframes ap5 { 0%,22% {opacity:0} 24%,96% {opacity:1} 99%,100% {opacity:0} }
@keyframes ap6 { 0%,27% {opacity:0} 29%,96% {opacity:1} 99%,100% {opacity:0} }
@keyframes ask { 0%,33% {opacity:0} 35%,96% {opacity:1} 99%,100% {opacity:0} }
@keyframes resolving { 0%,35% {opacity:0} 38% {opacity:1} 42% {opacity:.35}
  46% {opacity:1} 50% {opacity:.35} 54% {opacity:1} 58% {opacity:.35}
  62% {opacity:1} 66% {opacity:.35} 70% {opacity:1} 74%,76% {opacity:0}
  100% {opacity:0} }
@keyframes ringwalk {
  0%,35% { opacity:0; transform: translate(100px,95px) }
  37% { opacity:1; transform: translate(100px,95px) }
  45% { transform: translate(200px,95px) }
  53% { transform: translate(85px,130px) }
  61% { transform: translate(215px,130px) }
  69% { opacity:1; transform: translate(150px,95px) }
  74%,100% { opacity:0; transform: translate(150px,95px) }
}
@keyframes dagdone { 0%,74% {opacity:0} 77%,96% {opacity:1} 99%,100% {opacity:0} }
@keyframes logdone { 0%,36% {opacity:0} 39%,96% {opacity:1} 99%,100% {opacity:0} }
@keyframes barslow { 0%,35% {transform:scaleX(0)} 75%,96% {transform:scaleX(1)}
  99%,100% {transform:scaleX(0)} }
@keyframes barfast { 0%,35% {transform:scaleX(0)} 39%,96% {transform:scaleX(1)}
  99%,100% {transform:scaleX(0)} }
.anim .p1 { animation-name: ap1; } .anim .p2 { animation-name: ap2; }
.anim .p3 { animation-name: ap3; } .anim .p4 { animation-name: ap4; }
.anim .p5 { animation-name: ap5; } .anim .p6 { animation-name: ap6; }
.anim .pask { animation-name: ask; }
.anim .presolve { animation-name: resolving; }
.anim .pring { animation-name: ringwalk; }
.anim .pdagdone { animation-name: dagdone; }
.anim .plogdone { animation-name: logdone; }
.anim .pbarslow { animation-name: barslow; }
.anim .pbarfast { animation-name: barfast; }
@media (prefers-reduced-motion: reduce) {
  .anim .a, .ticker .cell.on, .ticker .root-chip { animation: none !important; }
  .chart, .archcol { opacity: 1; transform: none; transition: none; }
}
.lineage { display: flex; gap: 10px; flex-wrap: wrap; margin: 14px 0 0; }
.lineage span { background: var(--card); border: 1px solid var(--line);
  border-radius: 999px; padding: 3px 12px; font-size: .85rem;
  color: var(--muted); }
.lineage b { color: var(--fg); font-weight: 600; }
details { margin: 16px 0; }
summary { cursor: pointer; font-weight: 600; }
code { background: var(--card); padding: 1px 5px; border-radius: 4px; font-size: 0.85em; }
"""


SCRIPT = """
<script>
(function () {
  "use strict";
  // Count-up scoreboard numbers on first sight.
  var counted = new WeakSet();
  function countUp(el) {
    if (counted.has(el)) return;
    counted.add(el);
    var target = parseInt(el.dataset.count, 10);
    if (!isFinite(target)) return;
    var start = null;
    function step(ts) {
      if (start === null) start = ts;
      var t = Math.min(1, (ts - start) / 900);
      el.textContent = String(Math.round(target * (1 - Math.pow(1 - t, 3))));
      if (t < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  // Reveal cards as they scroll in; count when the scoreline appears.
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (!entry.isIntersecting) return;
      entry.target.classList.add("in");
      entry.target.querySelectorAll("[data-count]").forEach(countUp);
      io.unobserve(entry.target);
    });
  }, { rootMargin: "0px 0px -8% 0px" });
  document.querySelectorAll(".chart, .archcol, .scoreline").forEach(function (el) {
    io.observe(el);
  });
  // Hovering a server chip isolates that server's line in every chart.
  var chips = document.querySelectorAll(".serverchip[data-server]");
  var series = document.querySelectorAll(".series[data-server]");
  chips.forEach(function (chip) {
    chip.addEventListener("mouseenter", function () {
      series.forEach(function (g) {
        g.classList.toggle("dim", g.dataset.server !== chip.dataset.server);
      });
    });
    chip.addEventListener("mouseleave", function () {
      series.forEach(function (g) { g.classList.remove("dim"); });
    });
  });
})();
</script>
"""


def sitting_order(group: str) -> tuple[int, int, str]:
    """Chronological rank of a sitting name like `m3-final`.

    Plain reverse-lexicographic sorting filed the M3 close-out *under* the
    M3 progress sitting, because "p" > "f" — a bug the page shipped with.
    A sitting's place in time is its milestone number first and its phase
    within the milestone second; anything unparseable sorts last and keeps
    its name as the tiebreak, so an unexpected file cannot displace the
    real latest sitting.
    """
    milestone, _, phase = group.partition("-")
    try:
        number = int(milestone.lstrip("m"))
    except ValueError:
        return (-1, -1, group)
    ranks = {"progress": 0, "final": 1}
    return (number, ranks.get(phase, -1), group)


def render(groups: dict[str, list[dict]]) -> str:
    ordered = sorted(groups, key=sitting_order, reverse=True)
    latest, older = ordered[0], ordered[1:]

    documents = groups[latest]
    won, noise, lost = scoreboard(documents)
    ticker = (
        '<div class="ticker" aria-hidden="true">'
        + '<div class="cell on"></div>' * 7
        + '<span class="root-chip">state root &#10003;</span></div>'
    )
    parts = [
        sitetheme.head("Spindle vs the field", STYLE),
        sitetheme.nav("comparisons.html", [
            ("#architecture", "How it works"),
            ("#latest", "Latest sitting"),
            ("#method", "Method"),
        ]),
        "<main>",
        '<header class="hero">',
        ticker,
        "<h1>Spindle vs the field</h1>",
        '<p class="sub">A linearized Matrix homeserver: an append-only log '
        "per room, materialized state, and no state resolution on the hot "
        "path. Every milestone, the same client operations are measured "
        "against Synapse and both Rust siblings — wins, noise and losses "
        "all published from the committed raw numbers.</p>",
        '<div class="scoreline">'
        f'<div class="score win"><b data-count="{won}">0</b>cells faster</div>'
        f'<div class="score noise"><b data-count="{noise}">0</b>within noise</div>'
        f'<div class="score loss"><b data-count="{lost}">0</b>slower — '
        "investigated</div></div>",
        "</header>",
        ARCHITECTURE,
    ]
    provenance = " · ".join(
        f"{html.escape(d['server'])} <span class=\"provenance\">"
        f"({html.escape(d['_file'])})</span>"
        for d in sorted(documents, key=lambda d: d["server"])
    )
    parts.append(
        f'<h2 id="latest">Latest sitting — {html.escape(latest)}</h2>'
    )
    parts.append(f'<p class="provenance">{provenance}</p>')
    parts.extend(render_charts(documents))
    parts.append("<h3>Every cell</h3>")
    parts.extend(render_heatmap(latest, documents))

    if older:
        parts.append("<h2>Earlier sittings</h2>")
        parts.append(
            '<p class="legend">The trail matters: each milestone re-measures '
            "the same operations, so a regression shows up as a cell that "
            "changed color between sittings.</p>"
        )
    for group in older:
        won, noise, lost = scoreboard(groups[group])
        parts.append(
            f"<details><summary>{html.escape(group)} — {won} faster · "
            f"{noise} within noise · {lost} slower</summary>"
        )
        parts.extend(render_heatmap(group, groups[group]))
        parts.append("</details>")

    parts.append(METHOD)
    parts.append("</main>")
    parts.append(sitetheme.footer(
        "numbers from the raw results committed under docs/benchmarks/data/"
    ))
    parts.append(SCRIPT)
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_dir", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()

    groups = load_groups(args.data_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(groups))
    print(
        f"render-comparisons: {sum(len(v) for v in groups.values())} result "
        f"files across {len(groups)} sittings -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
