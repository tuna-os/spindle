#!/usr/bin/env python3
"""Render the per-milestone competitive comparisons as a page.

The inputs are the raw result files `scripts/api-benchmark.py` wrote, committed
under docs/benchmarks/data/ exactly as measured. This script only arranges
them: every number on the page traces to a committed JSON, and regenerating
the page cannot change a measurement.

The same honesty rules as render-benchmarks.py, plus one: these runs happen
on a developer machine at milestone close (docs/benchmarks.md explains why a
shared CI runner cannot host both sides honestly), so the page says where the
numbers came from instead of implying CI produced them.

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


def milliseconds(nanoseconds: float) -> str:
    return f"{nanoseconds / 1e6:.3f}"


def render_group(group: str, documents: list[dict]) -> list[str]:
    ours = next(d for d in documents if d["server"].startswith("spindle"))
    theirs = [d for d in documents if not d["server"].startswith("spindle")]

    lines = [f"<h2>{html.escape(group)}</h2>"]
    provenance = " · ".join(
        f"<code>{html.escape(d['server'])}</code> ({html.escape(d['_file'])})"
        for d in documents
    )
    lines.append(
        f"<p class=\"meta\">{provenance} · sizes {html.escape(str(ours['sizes']))}"
        f" · {ours['samples']} samples/point · medians</p>"
    )

    operations: list[str] = []
    for key in ours["benchmarks"]:
        operation = key.rsplit("/", 1)[0]
        if operation not in operations:
            operations.append(operation)

    header = "<th>operation / room size</th><th>spindle (ms)</th>" + "".join(
        f"<th>{html.escape(d['server'])} (ms)</th><th>ratio</th>" for d in theirs
    )
    lines.append(f"<table><tr>{header}</tr>")
    for operation in operations:
        for size in sorted(ours["sizes"]):
            key = f"{operation}/{size}"
            if key not in ours["benchmarks"]:
                continue
            our_ns = ours["benchmarks"][key]["mean_ns"]
            cells = [f"<td><code>{html.escape(key)}</code></td>", f"<td>{milliseconds(our_ns)}</td>"]
            for document in theirs:
                mark = document["benchmarks"].get(key)
                if mark is None:
                    # An honest hole: this operation was not measured on that
                    # server (e.g. an endpoint it lacks). A fabricated column
                    # would be worse than a gap.
                    cells.append("<td>—</td><td>—</td>")
                    continue
                ratio = mark["mean_ns"] / our_ns
                cells.append(f"<td>{milliseconds(mark['mean_ns'])}</td>")
                # Losses get the same rendering as wins; the ratio simply
                # dips below 1 in public.
                cells.append(f"<td>{ratio:.2f}×</td>")
            lines.append(f"<tr>{''.join(cells)}</tr>")
    lines.append("</table>")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_dir", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    arguments = parser.parse_args()

    groups = load_groups(arguments.data_dir)
    body: list[str] = [
        "<h1>Spindle vs siblings, per milestone</h1>",
        '<nav><a href="./index.html">← micro-benchmarks</a> · '
        '<a href="./dashboard.html">coverage dashboard</a></nav>',
        "<p>Client-Server API workloads, both sides driven by the same script "
        "(<code>scripts/api-benchmark.py</code>) on the same host in the same "
        "sitting, at milestone close. Raw results are committed under "
        "<code>docs/benchmarks/data/</code>; this page is arranged from them "
        "and cannot change a measurement. Ratio is the other server's median "
        "over ours — above 1× we are faster, below 1× we are slower, and both "
        "render the same. Method, caveats, and what these numbers do "
        "<em>not</em> establish: "
        '<a href="https://github.com/tuna-os/spindle/blob/main/docs/benchmarks.md">docs/benchmarks.md</a>.</p>',
    ]
    for group, documents in sorted(groups.items()):
        body.extend(render_group(group, documents))

    arguments.output.write_text(
        """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Spindle competitive benchmarks</title>
<style>
body { font: 15px/1.5 system-ui, sans-serif; max-width: 64rem; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
table { border-collapse: collapse; margin: 1rem 0; }
th, td { border: 1px solid #ccc; padding: .35rem .6rem; text-align: right; }
th:first-child, td:first-child { text-align: left; }
code { background: #f3f3f3; padding: .1rem .3rem; border-radius: 3px; font-size: .9em; }
.meta { color: #555; font-size: .9em; }
nav { margin-bottom: 1rem; }
</style>
"""
        + "\n".join(body)
        + "\n"
    )
    print(
        f"render-comparisons: {len(groups)} comparison groups -> {arguments.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
