#!/usr/bin/env python3
"""Print one extension's payload from each server, exchange by exchange.

    show_ext.py EXTENSION [--dir tmp/sliding-sync-diff/out] [--step STEP]

EXTENSION is a key under `extensions` (typing, receipts, account_data,
e2ee, to_device). Room IDs are shown as scenario names.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ssdiff.normalise import Namer


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("extension")
    ap.add_argument("--dir", default="tmp/sliding-sync-diff/out")
    ap.add_argument("--step")
    args = ap.parse_args()
    for side in ("synapse", "spindle"):
        with open(os.path.join(args.dir, f"{side}.names.json"), encoding="utf-8") as fh:
            names = json.load(fh)
        namer = Namer(names["rooms"], names["events"])
        print(f"===== {side}")
        with open(os.path.join(args.dir, f"{side}.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                ex = json.loads(line)
                if args.step and ex["step"] != args.step:
                    continue
                ext = ((ex.get("response") or {}).get("extensions") or {}).get(
                    args.extension
                )
                if not ext:
                    continue
                print(
                    f"-- #{ex['seq']} {ex['conn_id']} step={ex['step']} phase={ex['phase']} {ex['ms']:.0f}ms"
                )
                print("   " + json.dumps(namer.deep(ext), sort_keys=True)[:1500])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
