#!/usr/bin/env python3
"""Collect Criterion results into one machine-readable file.

Criterion scatters its output across ``target/criterion/<group>/<id>/new/``,
which is fine for a human with a browser and useless for anything else. This
walks that tree and emits a single JSON document: every benchmark, its mean and
median in nanoseconds, and the confidence interval, keyed so results from
different runs can be compared.

The point is that published numbers stop being hand-copied. A figure typed into
a document is a claim with nothing holding it to the code, and it drifts the
first time somebody changes the code and not the document.

Usage:
    scripts/collect-benchmarks.py target/criterion out.json --commit <sha>
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


def read_estimates(path: pathlib.Path) -> dict | None:
    """One benchmark's timings, in nanoseconds."""
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"skipping {path}: {error}", file=sys.stderr)
        return None

    mean = data.get("mean", {})
    median = data.get("median", {})
    interval = mean.get("confidence_interval", {})
    if "point_estimate" not in mean:
        return None
    return {
        "mean_ns": mean["point_estimate"],
        "median_ns": median.get("point_estimate"),
        "lower_ns": interval.get("lower_bound"),
        "upper_ns": interval.get("upper_bound"),
        "standard_error_ns": mean.get("standard_error"),
    }


def collect(root: pathlib.Path) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for estimates in sorted(root.rglob("new/estimates.json")):
        # <root>/<group>/<...>/new/estimates.json -> "group/..."
        name = "/".join(estimates.relative_to(root).parts[:-2])
        # Criterion also writes a `report` directory; it holds no estimates.
        if not name or name.startswith("report"):
            continue
        measured = read_estimates(estimates)
        if measured is not None:
            results[name] = measured
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("criterion_dir", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--commit", default="unknown")
    parser.add_argument("--ref", default="unknown")
    parser.add_argument("--timestamp", default="unknown")
    parser.add_argument(
        "--runner",
        default="unknown",
        help="What it ran on. Absolute times are not portable between machines, "
        "so a result without this is not interpretable.",
    )
    args = parser.parse_args()

    if not args.criterion_dir.is_dir():
        print(f"no criterion output at {args.criterion_dir}", file=sys.stderr)
        return 1

    results = collect(args.criterion_dir)
    if not results:
        # Publishing an empty result set would look like "everything got fast".
        print(f"no benchmark estimates under {args.criterion_dir}", file=sys.stderr)
        return 1

    document = {
        "commit": args.commit,
        "ref": args.ref,
        "timestamp": args.timestamp,
        "runner": args.runner,
        "benchmarks": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"collected {len(results)} benchmarks into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
