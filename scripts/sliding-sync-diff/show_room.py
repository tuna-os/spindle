#!/usr/bin/env python3
"""Print what each server sent for one scenario room, exchange by exchange.

    show_room.py ROOM [--dir tmp/sliding-sync-diff/out] [--step STEP] [--full]

For checking a reported difference against the raw exchanges.
"""

from __future__ import annotations

import argparse
import json
import os


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("room")
    ap.add_argument("--dir", default="tmp/sliding-sync-diff/out")
    ap.add_argument("--step")
    ap.add_argument("--conn", default="room-list")
    ap.add_argument(
        "--full", action="store_true", help="print whole events, not a summary"
    )
    args = ap.parse_args()
    for side in ("synapse", "spindle"):
        with open(os.path.join(args.dir, f"{side}.names.json"), encoding="utf-8") as fh:
            rooms = json.load(fh)["rooms"]
        rid = next((r for r, n in rooms.items() if n == args.room), None)
        print(f"===== {side} {args.room} = {rid}")
        with open(os.path.join(args.dir, f"{side}.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                ex = json.loads(line)
                if ex["conn_id"] != args.conn or (
                    args.step and ex["step"] != args.step
                ):
                    continue
                room = ((ex.get("response") or {}).get("rooms") or {}).get(rid)
                if room is None:
                    continue
                if not args.full:
                    room = dict(room)
                    room["required_state"] = [
                        f"{e['type']}[{e.get('state_key')}]"
                        + (
                            f"={e['content'].get('membership')}"
                            if e["type"] == "m.room.member"
                            else ""
                        )
                        for e in room.get("required_state") or []
                    ]
                    room["timeline"] = [
                        (e.get("content") or {}).get("body")
                        or (e.get("content") or {}).get("ciphertext")
                        or f"{e['type']}[{e.get('state_key', '')}]"
                        for e in room.get("timeline") or []
                    ]
                print(
                    f"-- #{ex['seq']} step={ex['step']} phase={ex['phase']} pos_in={ex['query'].get('pos')}"
                )
                print("   " + json.dumps(room, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
