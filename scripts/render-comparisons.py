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

File naming: `<group>.<server>.json`, where `<group>` sorts by milestone
(`m1-…`, `m2-…`) and exactly one file per group has server `spindle*` — the
side ratios are computed against.

Usage:
    scripts/render-comparisons.py docs/benchmarks/data comparisons.html
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import sys

# Cells whose ratio lands inside this band are called what they are: within
# the run-to-run variance this host measures (docs/benchmarks.md records the
# variance evidence), not a win for either side.
NOISE_LOW, NOISE_HIGH = 0.90, 1.10

SERVER_COLORS = {
    "spindle": "#7c3aed",
    "synapse": "#e05252",
    "continuwuity": "#d9930d",
    "tuwunel": "#0d9d6d",
}

# What each benchmarked operation actually asks the server to do, and why the
# storage architecture shows up in it. Rendered beside the latest charts so a
# reader never has to guess what a row measures.
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
        group = path.name.rsplit(".", 2)[0]
        document = json.loads(path.read_text())
        document["_file"] = path.name
        groups.setdefault(group, []).append(document)
    if not groups:
        # Refuse to render nothing: a blank page reads as "no losses".
        sys.exit(f"render-comparisons: no result files in {data_dir}")
    for group, documents in groups.items():
        ours = [d for d in documents if d["server"].startswith("spindle")]
        if len(ours) != 1:
            sys.exit(
                f"render-comparisons: group {group} needs exactly one spindle "
                f"file, found {len(ours)} — a ratio needs a fixed side"
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
    """(operation, size) -> {server: mean_ns} across one group's documents."""
    table: dict[tuple[str, int], dict[str, float]] = {}
    for document in documents:
        for key, entry in document["benchmarks"].items():
            operation, _, size = key.rpartition("/")
            table.setdefault((operation, int(size)), {})[document["server"]] = entry[
                "mean_ns"
            ]
    return table


def svg_chart(operation: str, sizes: list[int], series: dict[str, list[float | None]]) -> str:
    """One small-multiple: mean latency across room sizes, a line per server.

    Linear y from zero, per-chart scale: honest about relative gaps within an
    operation, labelled so charts are never compared to each other by eye
    without reading the axis.
    """
    width, height = 320, 190
    left, right, top, bottom = 46, 10, 26, 34
    plot_w, plot_h = width - left - right, height - top - bottom
    peak = max(
        (v for values in series.values() for v in values if v is not None),
        default=1.0,
    )
    peak *= 1.08

    def x(index: int) -> float:
        return left + plot_w * (index / max(1, len(sizes) - 1))

    def y(value: float) -> float:
        return top + plot_h * (1 - value / peak)

    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" '
        f'aria-label="{html.escape(operation)} latency by room size">'
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
        f'text-anchor="middle">events in room</text>'
    )
    for server, values in series.items():
        color = color_for(server)
        points = [
            (x(i), y(v)) for i, v in enumerate(values) if v is not None
        ]
        if not points:
            continue
        path = " ".join(
            f"{'M' if i == 0 else 'L'}{px:.1f},{py:.1f}"
            for i, (px, py) in enumerate(points)
        )
        parts.append(
            f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2.2"/>'
        )
        for px, py in points:
            parts.append(f'<circle cx="{px:.1f}" cy="{py:.1f}" r="3" fill="{color}"/>')
    parts.append("</svg>")
    return "".join(parts)


def scoreboard(documents: list[dict]):
    """Count won / within-noise / lost cells for one group."""
    ours = next(d for d in documents if d["server"].startswith("spindle"))
    won = noise = lost = 0
    for document in documents:
        if document is ours:
            continue
        for key, entry in document["benchmarks"].items():
            mine = ours["benchmarks"].get(key)
            if not mine:
                continue
            ratio = entry["mean_ns"] / mine["mean_ns"]
            if ratio >= NOISE_HIGH:
                won += 1
            elif ratio <= NOISE_LOW:
                lost += 1
            else:
                noise += 1
    return won, noise, lost


def render_heatmap(group: str, documents: list[dict]) -> list[str]:
    ours = next(d for d in documents if d["server"].startswith("spindle"))
    theirs = sorted(
        (d for d in documents if not d["server"].startswith("spindle")),
        key=lambda d: d["server"],
    )
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

    for operation in operations:
        title = OPERATIONS.get(operation, (operation, ""))[0]
        lines.append(
            f"<tr><td><strong>{html.escape(title)}</strong> "
            f"<code>{html.escape(operation)}</code></td>"
        )
        for document in theirs:
            for size in sizes:
                cell = table.get((operation, size), {})
                mine = cell.get(ours["server"])
                other = cell.get(document["server"])
                if mine is None or other is None:
                    lines.append('<td class="num absent">—</td>')
                    continue
                ratio = other / mine
                note_id = None
                if (group, operation) in INVESTIGATIONS:
                    note_id = f"note-{group}-{operation}"
                if ratio >= NOISE_HIGH:
                    css, label = "win", f"{ratio:.2f}×"
                elif ratio <= NOISE_LOW:
                    css, label = "loss", f"{1 / ratio:.2f}× slower"
                else:
                    css, label = "noise", f"{ratio:.2f}×"
                body = html.escape(label)
                if css == "loss" and note_id:
                    body = f'<a href="#{note_id}">{body}</a>'
                lines.append(
                    f'<td class="num {css}" title="spindle {mine / 1e6:.2f} ms · '
                    f'{html.escape(document["server"])} {other / 1e6:.2f} ms">'
                    f"{body}</td>"
                )
        lines.append("</tr>")
    lines.append("</tbody></table></div>")
    lines.append(
        '<p class="legend"><span class="chip win">≥1.10×</span> Spindle is '
        'faster by at least the noise band · <span class="chip noise">0.90–1.10×'
        "</span> within this host's measured run-to-run variance · "
        '<span class="chip loss">≤0.90×</span> Spindle is slower — every such '
        "cell links to its investigation, because the roadmap treats it as a "
        "defect until explained. Hover any cell for the raw milliseconds.</p>"
    )
    for (note_group, operation), (text,) in sorted(INVESTIGATIONS.items()):
        if note_group != group:
            continue
        title = OPERATIONS.get(operation, (operation, ""))[0]
        lines.append(
            f'<p class="investigation" id="note-{group}-{operation}">'
            f"<strong>Investigated — {html.escape(title)}:</strong> "
            f"{html.escape(text)}</p>"
        )
    return lines


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
            server: [table.get((operation, size), {}).get(server) for size in sizes]
            for server in servers
        }
        explainer = OPERATIONS.get(operation, (operation, ""))[1]
        lines.append('<figure class="chart">')
        lines.append(svg_chart(operation, sizes, series))
        if explainer:
            lines.append(f"<figcaption>{html.escape(explainer)}</figcaption>")
        lines.append("</figure>")
    lines.append("</div>")
    legend = " ".join(
        f'<span class="serverchip"><span class="dot" '
        f'style="background:{color_for(server)}"></span>{html.escape(server)}</span>'
        for server in servers
    )
    lines.insert(1, f'<p class="serverlegend">{legend}</p>')
    return lines


ARCHITECTURE = """
<section class="arch">
<h2>Why the shape of the storage shows up in every row</h2>
<div class="archgrid">
<div class="archcol">
<h3>A conventional homeserver</h3>
<svg viewBox="0 0 300 170" role="img" aria-label="event DAG with state resolution">
  <g class="dag">
    <circle cx="150" cy="20" r="9"/>
    <circle cx="100" cy="60" r="9"/><circle cx="200" cy="60" r="9"/>
    <circle cx="70" cy="100" r="9"/><circle cx="140" cy="100" r="9"/><circle cx="230" cy="100" r="9"/>
    <circle cx="150" cy="140" r="9" class="hot"/>
    <line x1="150" y1="29" x2="103" y2="52"/><line x1="150" y1="29" x2="197" y2="52"/>
    <line x1="100" y1="69" x2="73" y2="92"/><line x1="100" y1="69" x2="137" y2="92"/>
    <line x1="200" y1="69" x2="227" y2="92"/><line x1="200" y1="69" x2="143" y2="93"/>
    <line x1="73" y1="108" x2="146" y2="133"/><line x1="140" y1="109" x2="149" y2="131"/><line x1="228" y1="109" x2="155" y2="133"/>
  </g>
  <text x="150" y="163" class="archlabel" text-anchor="middle">events form a DAG — reads resolve state across branches</text>
</svg>
<p>Rooms are a directed graph of events. Forks are normal, so answering
"what is the state?" means running <em>state resolution</em> over the
branches — work that grows with the room and sits on the hot path of
sync, send, and join.</p>
</div>
<div class="archcol">
<h3>Spindle</h3>
<svg viewBox="0 0 300 170" role="img" aria-label="append-only log with materialized state">
  <g class="log">
    <rect x="18" y="55" width="36" height="26" rx="4"/>
    <rect x="62" y="55" width="36" height="26" rx="4"/>
    <rect x="106" y="55" width="36" height="26" rx="4"/>
    <rect x="150" y="55" width="36" height="26" rx="4"/>
    <rect x="194" y="55" width="36" height="26" rx="4"/>
    <rect x="238" y="55" width="36" height="26" rx="4" class="hot"/>
    <line x1="256" y1="55" x2="256" y2="30"/>
    <rect x="226" y="8" width="60" height="22" rx="4" class="root"/>
    <text x="256" y="23" class="archsmall" text-anchor="middle">state root</text>
  </g>
  <text x="150" y="110" class="archlabel" text-anchor="middle">an append-only log — each entry carries its state's address</text>
  <text x="150" y="128" class="archlabel" text-anchor="middle">reads are index lookups; state is one rehydration</text>
</svg>
<p>Each room is an append-only log with <em>materialized state</em>: every
entry carries the content address (BLAKE3 hash trie) of the state after
it. "The state now" is one read; history is a range; nothing resolves on
the hot path. Federation forks are collapsed at the door, bounded, and
never taxed on reads.</p>
</div>
</div>
<p>That is the bet these pages test. The comparisons below measure the same
client operations against the same workloads on Synapse (the reference
implementation) and on Continuwuity and Tuwunel (the two Rust siblings,
both descended from Conduit) — and when a cell goes the wrong way, the
roadmap's rule is that it gets investigated, not explained away.</p>
</section>
"""

METHOD = """
<section>
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
is the cost that grows with the room.</li>
<li><strong>Means over 25 samples after warmup</strong>, raw results
committed to the repository exactly as the driver wrote them
(<code>docs/benchmarks/data/</code>); this page is regenerated from those
files and cannot change a measurement.</li>
<li><strong>Losses publish with the same prominence as wins.</strong>
Cells within the measured noise band say so; cells below it link to their
investigation.</li>
</ul>
<p>Versions measured, ports, registration quirks and the full narrative per
sitting: <a href="https://github.com/tuna-os/spindle/blob/main/docs/benchmarks.md">
docs/benchmarks.md</a>.</p>
</section>
"""

STYLE = """
<style>
:root {
  --bg: #ffffff; --fg: #1a1a20; --muted: #667; --line: #e2e2ea;
  --card: #f7f7fb; --win-bg: #e7f6ec; --win-fg: #14683a;
  --loss-bg: #fdeaea; --loss-fg: #a02020; --noise-bg: #f0f0f4;
  --noise-fg: #556; --accent: #7c3aed;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #131318; --fg: #e8e8ee; --muted: #99a; --line: #2c2c36;
    --card: #1b1b23; --win-bg: #12301e; --win-fg: #6fd39a;
    --loss-bg: #391616; --loss-fg: #ef9a9a; --noise-bg: #22222c;
    --noise-fg: #99a; --accent: #a78bfa;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1080px; margin: 0 auto; padding: 0 20px 60px; }
nav { display: flex; gap: 18px; padding: 14px 20px; border-bottom: 1px solid var(--line);
  max-width: 1080px; margin: 0 auto; align-items: baseline; flex-wrap: wrap; }
nav .brand { font-weight: 700; color: var(--accent); }
nav a { color: var(--fg); text-decoration: none; }
nav a:hover { color: var(--accent); }
h1 { font-size: 1.9rem; margin: 28px 0 4px; }
h2 { margin-top: 40px; border-bottom: 1px solid var(--line); padding-bottom: 6px; }
.sub { color: var(--muted); margin-top: 0; }
.scoreline { display: flex; gap: 14px; flex-wrap: wrap; margin: 18px 0; }
.score { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 10px 18px; text-align: center; }
.score b { display: block; font-size: 1.6rem; }
.score.win b { color: var(--win-fg); } .score.loss b { color: var(--loss-fg); }
.score.noise b { color: var(--noise-fg); }
.charts { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 18px; margin-top: 14px; }
.chart { margin: 0; background: var(--card); border: 1px solid var(--line);
  border-radius: 10px; padding: 10px; }
.chart svg { width: 100%; height: auto; }
.chart figcaption { font-size: 0.82rem; color: var(--muted); padding: 4px 6px 2px; }
.ctitle { font-size: 13px; font-weight: 600; fill: var(--fg); }
.tick { font-size: 10px; fill: var(--muted); }
.grid { stroke: var(--line); stroke-width: 1; }
.serverlegend { margin: 6px 0 0; }
.serverchip { margin-right: 16px; font-size: 0.9rem; color: var(--muted); }
.dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%;
  margin-right: 6px; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 0.92rem; }
th, td { border: 1px solid var(--line); padding: 6px 9px; text-align: left; }
th.num, td.num { text-align: right; font-variant-numeric: tabular-nums; }
.heatmap td.win { background: var(--win-bg); color: var(--win-fg); }
.heatmap td.loss { background: var(--loss-bg); color: var(--loss-fg); }
.heatmap td.loss a { color: inherit; }
.heatmap td.noise { background: var(--noise-bg); color: var(--noise-fg); }
.heatmap td.absent { color: var(--muted); }
.chip { padding: 1px 8px; border-radius: 6px; font-size: 0.85rem; }
.chip.win { background: var(--win-bg); color: var(--win-fg); }
.chip.loss { background: var(--loss-bg); color: var(--loss-fg); }
.chip.noise { background: var(--noise-bg); color: var(--noise-fg); }
.legend, .provenance { color: var(--muted); font-size: 0.88rem; }
.investigation { background: var(--card); border-left: 4px solid var(--accent);
  padding: 10px 14px; border-radius: 6px; }
.arch p { max-width: 70ch; }
.archgrid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px; }
.archcol { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 14px 18px; }
.archcol svg { width: 100%; height: auto; }
.dag circle { fill: none; stroke: var(--muted); stroke-width: 2; }
.dag line { stroke: var(--muted); stroke-width: 1.4; }
.dag .hot { stroke: var(--loss-fg); }
.log rect { fill: none; stroke: var(--muted); stroke-width: 2; }
.log line { stroke: var(--muted); stroke-width: 1.4; }
.log .hot { stroke: var(--accent); }
.log .root { stroke: var(--accent); }
.archlabel { font-size: 11px; fill: var(--muted); }
.archsmall { font-size: 10px; fill: var(--fg); }
details { margin: 16px 0; }
summary { cursor: pointer; font-weight: 600; }
code { background: var(--card); padding: 1px 5px; border-radius: 4px; font-size: 0.85em; }
</style>
"""


def render(groups: dict[str, list[dict]]) -> str:
    ordered = sorted(groups, reverse=True)
    latest, older = ordered[0], ordered[1:]

    parts = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<title>Spindle vs the field</title>",
        STYLE,
        "</head><body>",
        '<nav><span class="brand">Spindle</span>'
        '<a href="index.html">Micro-benchmarks</a>'
        '<a href="comparisons.html">vs the field</a>'
        '<a href="dashboard.html">Coverage dashboard</a>'
        '<a href="https://github.com/tuna-os/spindle">GitHub</a></nav>',
        "<main>",
        "<h1>Spindle vs the field</h1>",
        '<p class="sub">The same client operations, the same workloads, '
        "measured against Synapse and both Rust siblings at every milestone "
        "— wins, noise and losses all published from the committed raw "
        "numbers.</p>",
        ARCHITECTURE,
    ]

    documents = groups[latest]
    won, noise, lost = scoreboard(documents)
    provenance = " · ".join(
        f"{html.escape(d['server'])} <span class=\"provenance\">"
        f"({html.escape(d['_file'])})</span>"
        for d in sorted(documents, key=lambda d: d["server"])
    )
    parts.append(f"<h2>Latest sitting — {html.escape(latest)}</h2>")
    parts.append(f'<p class="provenance">{provenance}</p>')
    parts.append(
        '<div class="scoreline">'
        f'<div class="score win"><b>{won}</b>cells faster</div>'
        f'<div class="score noise"><b>{noise}</b>within noise</div>'
        f'<div class="score loss"><b>{lost}</b>slower — investigated</div>'
        "</div>"
    )
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
    parts.append("</main></body></html>")
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
