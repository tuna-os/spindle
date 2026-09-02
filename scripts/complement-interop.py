#!/usr/bin/env python3
"""Compare and summarize Complement heterogeneous interop results against a baseline.

Reads a homogeneous baseline ledger and a heterogeneous interop ledger, diffs
them to separate genuine interop regressions from shared gaps, annotates known
peer-side divergences / false positives (such as MSC3916 media deprecations on
Synapse), and produces a report-only summary table.

Usage:
    scripts/complement-interop.py --baseline tmp/complement-results.jsonl --interop tmp/complement-interop.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Known peer divergences that are upstream deprecations or peer-side behaviors
# rather than Spindle regressions.
KNOWN_PEER_DIVERGENCES: dict[str, str] = {
    "TestMediaAdmin": "Synapse 404s deprecated unauthenticated media endpoints per MSC3916",
    "TestMediaWithoutAuth": "Synapse requires authenticated media per MSC3916",
    "TestMSC3916": "MSC3916 authenticated media transitions on peer",
}


def read_ledger(path: Path) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Read a go test -json ledger into (outcomes, output)."""
    outcomes: dict[str, str] = {}
    output: dict[str, list[str]] = {}
    if not path.exists():
        return outcomes, output

    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            test = record.get("Test")
            action = record.get("Action")
            if not test:
                continue
            if action in {"pass", "fail", "skip"}:
                outcomes[test] = action
            elif action == "output":
                output.setdefault(test, []).append(record.get("Output", ""))
    return outcomes, output


def categorize_results(
    baseline_outcomes: dict[str, str],
    interop_outcomes: dict[str, str],
) -> dict[str, list[str]]:
    """Compare baseline and interop outcomes into categories."""
    categories: dict[str, list[str]] = {
        "shared_pass": [],
        "shared_fail": [],
        "peer_divergence": [],
        "interop_regression": [],
        "interop_improvement": [],
        "skipped": [],
    }

    all_tests = sorted(set(baseline_outcomes.keys()) | set(interop_outcomes.keys()))

    for test in all_tests:
        base = baseline_outcomes.get(test)
        interop = interop_outcomes.get(test)

        if interop == "skip" or (interop is None and base == "skip"):
            categories["skipped"].append(test)
        elif base == "pass" and interop == "pass":
            categories["shared_pass"].append(test)
        elif base == "pass" and interop in {"fail", "absent", None}:
            # Check if this is a known peer divergence
            is_peer_divergence = any(pattern in test for pattern in KNOWN_PEER_DIVERGENCES)
            if is_peer_divergence:
                categories["peer_divergence"].append(test)
            else:
                categories["interop_regression"].append(test)
        elif base in {"fail", "absent", None} and interop == "pass":
            categories["interop_improvement"].append(test)
        elif base in {"fail", "absent", None} and interop in {"fail", "absent", None}:
            categories["shared_fail"].append(test)

    return categories


def format_summary(
    categories: dict[str, list[str]],
    baseline_name: str = "homogeneous",
    interop_name: str = "synapse-interop",
) -> str:
    """Format a human-readable and markdown-compatible summary."""
    lines = []
    lines.append(f"## Complement Interop Report: {interop_name} vs {baseline_name}")
    lines.append("")
    lines.append("| Category | Count | Description |")
    lines.append("|---|---|---|")
    lines.append(f"| **Shared Passing** | {len(categories['shared_pass'])} | Passing in both homogeneous and interop runs |")
    lines.append(f"| **Shared Gaps** | {len(categories['shared_fail'])} | Baseline gaps (failing in both, not an interop regression) |")
    lines.append(f"| **Peer Divergences** | {len(categories['peer_divergence'])} | Known peer deprecations / false positives (e.g. MSC3916 media) |")
    lines.append(f"| **Interop Regressions** | {len(categories['interop_regression'])} | Passed homogeneous, failed in interop |")
    lines.append(f"| **Interop Improvements** | {len(categories['interop_improvement'])} | Passed only in interop |")
    lines.append(f"| **Skipped** | {len(categories['skipped'])} | Skipped tests |")
    lines.append("")

    if categories["peer_divergence"]:
        lines.append("### Peer-Side False Positives & Divergences")
        for test in categories["peer_divergence"]:
            reason = "Peer deprecation"
            for pattern, explanation in KNOWN_PEER_DIVERGENCES.items():
                if pattern in test:
                    reason = explanation
                    break
            lines.append(f"- `{test}`: {reason}")
        lines.append("")

    if categories["interop_regression"]:
        lines.append("### Interop Regressions")
        for test in categories["interop_regression"]:
            lines.append(f"- `{test}`")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Complement Interop Summarizer")
    parser.add_argument("--baseline", type=Path, required=True, help="Baseline ledger (homogeneous)")
    parser.add_argument("--interop", type=Path, required=True, help="Interop ledger (heterogeneous)")
    parser.add_argument("--report", type=Path, help="Output markdown report file")
    parser.add_argument("--fail-on-regression", action="store_true", help="Exit nonzero on genuine interop regression")
    arguments = parser.parse_args()

    baseline_outcomes, _ = read_ledger(arguments.baseline)
    interop_outcomes, _ = read_ledger(arguments.interop)

    if not interop_outcomes:
        print("complement-interop: interop ledger is empty or missing", file=sys.stderr)
        return 1

    categories = categorize_results(baseline_outcomes, interop_outcomes)
    summary = format_summary(categories)
    print(summary)

    if arguments.report:
        arguments.report.write_text(summary, encoding="utf-8")

    if arguments.fail_on_regression and categories["interop_regression"]:
        print(f"\ncomplement-interop: {len(categories['interop_regression'])} genuine interop regressions found", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
