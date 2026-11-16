#!/usr/bin/env python3
"""Print each exchange of one step, both servers: timing, list count, rooms.

show_step.py STEP [--dir tmp/sliding-sync-diff/out] [--conn room-list]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ssdiff.normalise import Namer, event_label


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("step")
    ap.add_argument("--dir", default="tmp/sliding-sync-diff/out")
    ap.add_argument("--conn", default="room-list")
    args = ap.parse_args()
    for side in ("synapse", "spindle"):
        with open(os.path.join(args.dir, f"{side}.names.json"), encoding="utf-8") as fh:
            names = json.load(fh)
        namer = Namer(names["rooms"], names["events"])
        print(f"===== {side}")
        with open(os.path.join(args.dir, f"{side}.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                ex = json.loads(line)
                if ex["step"] != args.step or ex["conn_id"] != args.conn:
                    continue
                resp = ex.get("response") or {}
                ranges = [
                    v.get("ranges") for v in (ex["request"].get("lists") or {}).values()
                ]
                counts = {
                    k: v.get("count") for k, v in (resp.get("lists") or {}).items()
                }
                print(
                    f"-- #{ex['seq']} {ex['phase']} status={ex['status']} {ex['ms']:.0f}ms "
                    f"pos_in={'yes' if ex['query'].get('pos') else 'no'} timeout={ex['query'].get('timeout')} "
                    f"ranges={ranges} counts={counts} errcode={resp.get('errcode')}"
                )
                for rid, room in (resp.get("rooms") or {}).items():
                    tl = [
                        event_label(namer.deep(e)) for e in room.get("timeline") or []
                    ]
                    flags = [k for k in ("initial", "limited") if room.get(k)]
                    print(
                        f"     {namer.room(rid):<12} {' '.join(flags):<16} bump={'Y' if 'bump_stamp' in room else '-'} "
                        f"tl={tl[-3:]}"
                    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
