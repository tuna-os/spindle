#!/usr/bin/env python3
"""Render collected benchmark results as a page.

Two things this deliberately does, both of which follow from what
docs/benchmarks.md already says about honest measurement:

**Ratios are shown as the result, wall times as context.** Absolute times do not
survive a change of runner. A shared CI runner is noisy and slower than a
workstation by an amount that varies run to run, so a number from one is not
comparable to a number from another. A ratio measured inside a single run is.

**Comparisons we lose are rendered the same as ones we win.** The suite exists
to be evidence, and a dashboard that highlights only the favourable rows is not
evidence, it is marketing with a build step.

Usage:
    scripts/render-benchmarks.py latest.json index.html
"""

from __future__ import annotations

import argparse
import os
import html
import json
import pathlib

# Head-to-head pairs, as (label, ours, theirs). Both sides must be in the same
# run, so the ratio is measured on one machine at one moment.
COMPARISONS = [
    (
        "Fork resolution vs ruma-state-res",
        "fork resolution/spindle window merge/{}",
        "fork resolution/ruma-state-res/{}",
        ["1", "4", "16", "64", "256"],
    ),
    (
        "State updates: our HAMT vs the im crate",
        "state_retained_updates/hamt/{}",
        "state_retained_updates/im/{}",
        ["100", "1000", "10000"],
    ),
    (
        "State lookup: our HAMT vs HashMap",
        "state_lookup/hamt/{}",
        "state_lookup/hashmap/{}",
        ["1000", "50000"],
    ),
]


def humanise(nanoseconds: float | None) -> str:
    if nanoseconds is None:
        return "—"
    for limit, unit, scale in (
        (1_000, "ns", 1),
        (1_000_000, "µs", 1_000),
        (1_000_000_000, "ms", 1_000_000),
    ):
        if nanoseconds < limit:
            return f"{nanoseconds / scale:.3g} {unit}"
    return f"{nanoseconds / 1_000_000_000:.3g} s"


def comparison_rows(benchmarks: dict, ours_key: str, theirs_key: str, sizes: list[str]):
    for size in sizes:
        ours = benchmarks.get(ours_key.format(size))
        theirs = benchmarks.get(theirs_key.format(size))
        if not ours or not theirs:
            continue
        ratio = theirs["mean_ns"] / ours["mean_ns"] if ours["mean_ns"] else None
        yield size, ours, theirs, ratio


def render(document: dict, repository: str) -> str:
    benchmarks = document.get("benchmarks", {})
    parts: list[str] = []
    add = parts.append

    add("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    add("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    add("<title>Spindle benchmarks</title><style>")
    add("""
:root { color-scheme: light dark; --fg:#111; --muted:#666; --line:#ddd; --bg:#fff; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e8e8e8; --muted:#9a9a9a; --line:#333; --bg:#111; }
}
body { font: 15px/1.55 ui-sans-serif, system-ui, sans-serif; margin: 0 auto; padding: 2rem 1rem 4rem;
       max-width: 60rem; color: var(--fg); background: var(--bg); }
h1 { font-size: 1.6rem; margin-bottom: .25rem; }
h2 { font-size: 1.1rem; margin-top: 2.5rem; }
.meta { color: var(--muted); font-size: .85rem; }
table { border-collapse: collapse; width: 100%; margin: .75rem 0 0; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid var(--line); }
th { font-weight: 600; font-size: .8rem; text-transform: uppercase; letter-spacing: .03em; color: var(--muted); }
td.num { text-align: right; }
.win { color: #1a7f37; font-weight: 600; }
.loss { color: #b35900; font-weight: 600; }
.note { color: var(--muted); font-size: .85rem; border-left: 3px solid var(--line);
        padding-left: .8rem; margin: .75rem 0 0; }
details { margin-top: .75rem; }
code { font-size: .85em; }
""")
    add("</style></head><body>")
    add("<h1>Spindle benchmarks</h1>")
    add(
        f"<p class=\"meta\">Commit <code>{html.escape(document.get('commit','?')[:12])}</code> "
        f"on <code>{html.escape(document.get('ref','?'))}</code> · "
        f"{html.escape(document.get('timestamp','?'))} · "
        f"runner <code>{html.escape(document.get('runner','?'))}</code></p>"
    )
    add(
        "<p class=\"note\">Generated from Criterion output on every push to "
        "<code>main</code>. <strong>Ratios are the result; wall times are context.</strong> "
        "Absolute times do not survive a change of runner, and a shared CI runner is both "
        "slower and noisier than a workstation by an amount that varies run to run. "
        "Everything here is algorithmic, measured inside the library — none of it is a "
        "server throughput figure and none of it should be quoted as one.</p>"
    )

    for title, ours_key, theirs_key, sizes in COMPARISONS:
        rows = list(comparison_rows(benchmarks, ours_key, theirs_key, sizes))
        if not rows:
            continue
        add(f"<h2>{html.escape(title)}</h2>")
        add("<table><thead><tr><th>Size</th><th class=\"num\">Spindle</th>"
            "<th class=\"num\">Comparison</th><th class=\"num\">Ratio</th></tr></thead><tbody>")
        for size, ours, theirs, ratio in rows:
            if ratio is None:
                verdict = "—"
            else:
                # A loss is rendered exactly like a win, in the same table, with
                # the same prominence. That is the whole point of publishing.
                css = "win" if ratio >= 1 else "loss"
                verdict = (
                    f"<span class=\"{css}\">{ratio:.2f}x</span>"
                    if ratio >= 1
                    else f"<span class=\"{css}\">{1 / ratio:.2f}x slower</span>"
                )
            add(
                f"<tr><td>{html.escape(size)}</td>"
                f"<td class=\"num\">{humanise(ours['mean_ns'])}</td>"
                f"<td class=\"num\">{humanise(theirs['mean_ns'])}</td>"
                f"<td class=\"num\">{verdict}</td></tr>"
            )
        add("</tbody></table>")

    add("<h2>Every measurement</h2>")
    add("<details><summary>All benchmarks in this run</summary>")
    add("<table><thead><tr><th>Benchmark</th><th class=\"num\">Mean</th>"
        "<th class=\"num\">Median</th><th class=\"num\">95% CI</th></tr></thead><tbody>")
    for name in sorted(benchmarks):
        entry = benchmarks[name]
        interval = f"{humanise(entry.get('lower_ns'))} – {humanise(entry.get('upper_ns'))}"
        add(
            f"<tr><td><code>{html.escape(name)}</code></td>"
            f"<td class=\"num\">{humanise(entry.get('mean_ns'))}</td>"
            f"<td class=\"num\">{humanise(entry.get('median_ns'))}</td>"
            f"<td class=\"num\">{html.escape(interval)}</td></tr>"
        )
    add("</tbody></table></details>")
    add(
        "<p class=\"note\">Raw data: <a href=\"latest.json\">latest.json</a>. "
        "Method, caveats and what each comparison does and does not establish: "
        f"<a href=\"https://github.com/{repository}/blob/main/docs/benchmarks.md\">"
        "docs/benchmarks.md</a>.</p>"
    )
    add("</body></html>")
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    # Derived, not hardcoded. The published page used to name the repository
    # in a string literal, which silently pointed at the old owner the moment
    # the project moved -- a dead link on the one page that is supposed to be
    # the authoritative one.
    parser.add_argument(
        "--repository",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="owner/name, for links back to the source (default: $GITHUB_REPOSITORY)",
    )
    args = parser.parse_args()
    if not args.repository:
        parser.error("--repository is required when GITHUB_REPOSITORY is unset")

    document = json.loads(args.results.read_text())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(document, args.repository))
    print(f"rendered {len(document.get('benchmarks', {}))} benchmarks into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
