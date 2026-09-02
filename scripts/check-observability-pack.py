#!/usr/bin/env python3
"""Check that the observability pack names metrics the server exports.

    scripts/check-observability-pack.py

The alert rules (deploy/prometheus/spindle-alerts.yaml) and the Grafana
dashboard (deploy/grafana/spindle.json) are the pieces of this repository
most likely to rot silently: a renamed metric leaves a rule that never
fires and a panel that draws nothing, and neither the compiler nor a test
notices. This check reads every `spindle_*` metric name out of both,
strips the histogram suffixes Prometheus adds (`_bucket`, `_sum`,
`_count`), and requires each to appear in
crates/spindle-server/src/metrics.rs and in the table docs/metrics.md
keeps. It also parses the ServiceMonitor manifest and requires the port
name and path the alert rules' `job` label depends on.

Exit status 0 when everything lines up, 1 with the offending names.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
ALERTS = REPO / "deploy" / "prometheus" / "spindle-alerts.yaml"
DASHBOARD = REPO / "deploy" / "grafana" / "spindle.json"
MONITORS = REPO / "deploy" / "kubernetes" / "servicemonitor.yaml"
METRICS_RS = REPO / "crates" / "spindle-server" / "src" / "metrics.rs"
METRICS_MD = REPO / "docs" / "metrics.md"

NAME = re.compile(r"\bspindle_[a-z0-9_]+")
SUFFIXES = ("_bucket", "_sum", "_count")


def bare(name: str) -> str:
    for suffix in SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def exported() -> set[str]:
    return set(NAME.findall(METRICS_RS.read_text()))


def documented() -> set[str]:
    return {
        match
        for line in METRICS_MD.read_text().splitlines()
        if line.startswith("| `spindle_")
        for match in NAME.findall(line)
    }


def named_in(text: str) -> set[str]:
    return {bare(name) for name in NAME.findall(text)}


def main() -> int:
    problems: list[str] = []

    rules = yaml.safe_load(ALERTS.read_text())
    alerts = [rule for group in rules["groups"] for rule in group["rules"] if "alert" in rule]
    for rule in alerts:
        for field in ("expr", "for", "annotations"):
            if field not in rule:
                problems.append(f"alert {rule.get('alert')} has no {field}")
    dashboard = json.loads(DASHBOARD.read_text())
    panels = dashboard.get("panels", [])
    if not panels:
        problems.append("the dashboard has no panels")

    have = exported()
    known = documented()
    wanted = named_in(ALERTS.read_text()) | named_in(DASHBOARD.read_text())
    for name in sorted(wanted):
        if name not in have:
            problems.append(f"{name} is named by the pack but not exported by metrics.rs")
        elif name not in known:
            problems.append(f"{name} is exported but missing from the table in docs/metrics.md")
    for name in sorted(have - wanted):
        # Not a failure: a metric nobody charts is still a metric. Said so
        # the gap is visible in the run's output.
        print(f"check-observability-pack: note: {name} is exported and not on the dashboard")

    monitors = [doc for doc in yaml.safe_load_all(MONITORS.read_text()) if doc]
    kinds = {doc.get("kind") for doc in monitors}
    for kind in ("ServiceMonitor", "PodMonitor"):
        if kind not in kinds:
            problems.append(f"servicemonitor.yaml has no {kind}")
    for doc in monitors:
        endpoints = doc.get("spec", {}).get("endpoints") or doc.get("spec", {}).get("podMetricsEndpoints") or []
        for endpoint in endpoints:
            if endpoint.get("path") != "/metrics" or endpoint.get("port") != "metrics":
                problems.append(f"{doc['kind']} scrapes {endpoint.get('path')} on port {endpoint.get('port')}, not /metrics on `metrics`")
            job = [r for r in endpoint.get("relabelings", []) if r.get("targetLabel") == "job"]
            if not job or job[0].get("replacement") != "spindle":
                problems.append(f"{doc['kind']} does not set job=spindle, which the alert rules select on")

    for line in problems:
        print(f"check-observability-pack: {line}", file=sys.stderr)
    if problems:
        return 1
    print(
        f"check-observability-pack: {len(alerts)} alerts and {len(panels)} panels name "
        f"{len(wanted)} metrics, all exported and documented"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
