"""The human-readable report, and the JSON one."""

from __future__ import annotations

import collections
import json


def _short(value, width=90) -> str:
    text = (
        json.dumps(value, sort_keys=True, default=str)
        if not isinstance(value, str)
        else value
    )
    return text if len(text) <= width else text[: width - 3] + "..."


def build(
    meta: dict,
    step_diffs,
    view_diffs,
    anomalies: dict,
    anomaly_cmp: dict,
    timings: dict,
) -> dict:
    return {
        "meta": meta,
        "summary": {
            "view_differences": sum(1 for d in view_diffs if not d.explained),
            "visible_step_differences": sum(1 for d in step_diffs if d.visible),
            "wire_differences": sum(
                1 for d in step_diffs if not d.visible and not d.explained
            ),
            "explained_differences": sum(
                1 for d in view_diffs + step_diffs if d.explained
            ),
            "anomalies": {
                side: dict(collections.Counter(a["kind"] for a in found))
                for side, found in anomalies.items()
            },
            "anomalies_only_spindle": len(anomaly_cmp["only_spindle"]),
            "anomalies_only_synapse": len(anomaly_cmp["only_synapse"]),
        },
        "view_differences": [d.as_dict() for d in view_diffs],
        "step_differences": [d.as_dict() for d in step_diffs],
        "anomalies": anomalies,
        "anomaly_comparison": anomaly_cmp,
        "timings": timings,
    }


def text(report: dict) -> str:
    out = []
    meta, summ = report["meta"], report["summary"]
    out.append("# Sliding sync differential: Spindle against Synapse")
    out.append("")
    for k, v in meta.items():
        out.append(f"- {k}: {v}")
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append("| | count |")
    out.append("|---|---|")
    out.append(f"| Anomalies only Spindle shows | {summ['anomalies_only_spindle']} |")
    out.append(f"| Anomalies only Synapse shows | {summ['anomalies_only_synapse']} |")
    out.append(f"| Room list differences (client model) | {summ['view_differences']} |")
    out.append(
        f"| Client-visible step differences | {summ['visible_step_differences']} |"
    )
    out.append(f"| Wire-only step differences | {summ['wire_differences']} |")
    out.append(
        f"| Explained (known, not Spindle bugs) | {summ['explained_differences']} |"
    )
    for side, kinds in summ["anomalies"].items():
        out.append(
            f"| {side} anomalies by kind | {', '.join(f'{k}={v}' for k, v in sorted(kinds.items())) or 'none'} |"
        )
    out.append("")

    cmp_ = report["anomaly_comparison"]
    for title, found in (
        ("Anomalies only Spindle shows", cmp_["only_spindle"]),
        ("Anomalies only Synapse shows", cmp_["only_synapse"]),
        ("Anomalies both servers show", cmp_["both"]),
    ):
        out.append(f"## {title}")
        out.append("")
        _anomaly_groups(out, found)

    out.append("## Room list differences (what Element X would show)")
    out.append("")
    _grouped(out, [d for d in report["view_differences"] if not d["explained"]])
    visible = [d for d in report["step_differences"] if d["visible"]]
    wire = [
        d for d in report["step_differences"] if not d["visible"] and not d["explained"]
    ]
    out.append("## Client-visible differences in the responses")
    out.append("")
    _grouped(out, visible)
    out.append("## Wire-only differences in the responses")
    out.append("")
    _grouped(out, wire)

    out.append("## Explained differences")
    out.append("")
    explained = [
        d
        for d in report["view_differences"] + report["step_differences"]
        if d["explained"]
    ]
    reasons = collections.Counter(d["explained"] for d in explained)
    if not reasons:
        out.append("None.")
    for reason, n in reasons.most_common():
        out.append(f"- {n} x {reason}")
    out.append("")

    out.append("## Long-poll timings")
    out.append("")
    out.append(
        "A long poll that returns content should return at once: the change was made before the request."
    )
    out.append("")
    out.append("| step | synapse ms | spindle ms |")
    out.append("|---|---|---|")
    tim = report["timings"]
    steps = list(dict.fromkeys(t["step"] for side in tim.values() for t in side))
    for step in steps:
        cells = []
        for side in ("synapse", "spindle"):
            t = next((t for t in tim.get(side, []) if t["step"] == step), None)
            cells.append(
                "-"
                if t is None
                else f"{t['ms']:.0f}{'' if t['content'] else ' (empty)'}"
            )
        out.append(f"| {step} | {cells[0]} | {cells[1]} |")
    out.append("")
    return "\n".join(out)


def _anomaly_groups(out, found, examples=6):
    """One entry per kind: how many, in which steps and rooms, and examples."""
    if not found:
        out.append("None.")
        out.append("")
        return
    by_kind = collections.OrderedDict()
    for a in found:
        by_kind.setdefault(a["kind"], []).append(a)
    for kind, items in by_kind.items():
        steps = list(dict.fromkeys(a["step"] for a in items))
        rooms = sorted({a["room"] for a in items if a["room"]})
        out.append(
            f"- **{kind}** x{len(items)} in steps {', '.join(steps)}"
            + (f"; {len(rooms)} rooms" if rooms else "")
        )
        for a in items[:examples]:
            out.append(
                f"  - `{a['step']}` conn `{a['conn']}` #{a['seq']}: {a['detail']}"
            )
        if len(items) > examples:
            out.append(f"  - ... {len(items) - examples} more in report.json")
    out.append("")


def _grouped(out, diffs):
    if not diffs:
        out.append("None.")
        out.append("")
        return
    by_kind = collections.OrderedDict()
    for d in diffs:
        by_kind.setdefault(d["kind"], []).append(d)
    for kind, items in by_kind.items():
        out.append(f"### {kind} ({len(items)})")
        out.append("")
        for d in items:
            where = f"step `{d['step']}` conn `{d['conn']}`"
            if d["room"]:
                where += f" room `{d['room']}`"
            out.append(f"- {where} `{d['field']}`")
            out.append(f"  - synapse: `{_short(d['synapse'])}`")
            out.append(f"  - spindle: `{_short(d['spindle'])}`")
            if d.get("note"):
                out.append(f"  - {d['note']}")
        out.append("")
