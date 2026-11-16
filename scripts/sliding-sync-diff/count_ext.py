#!/usr/bin/env python3
"""Count, per server, the answers that carry each extension's payload.

    count_ext.py [--dir tmp/sliding-sync-diff/out]

An extension that is in nearly every answer re-sends data the client
already has; that is the cue to look at it with show_ext.py.
"""

from __future__ import annotations

import argparse
import collections
import json
import os


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dir", default="tmp/sliding-sync-diff/out")
    args = ap.parse_args()
    for side in ("synapse", "spindle"):
        total = collections.Counter()
        carried = collections.Counter()
        with open(os.path.join(args.dir, f"{side}.jsonl"), encoding="utf-8") as fh:
            for line in fh:
                ex = json.loads(line)
                if ex["status"] != 200:
                    continue
                total[ex["conn_id"]] += 1
                ext = ex["response"].get("extensions") or {}
                ad = ext.get("account_data") or {}
                for t in {e.get("type") for e in ad.get("global") or []}:
                    carried[(ex["conn_id"], f"account_data.global {t}")] += 1
                if any(ad.get("rooms", {}).values()):
                    carried[(ex["conn_id"], "account_data.rooms (non-empty)")] += 1
                for name in ("receipts", "typing"):
                    if (ext.get(name) or {}).get("rooms"):
                        carried[(ex["conn_id"], f"{name}.rooms (non-empty)")] += 1
                if (ext.get("to_device") or {}).get("events"):
                    carried[(ex["conn_id"], "to_device.events (non-empty)")] += 1
                if ex["response"].get("rooms"):
                    carried[(ex["conn_id"], "rooms (non-empty)")] += 1
        print(f"== {side}: answers per connection {dict(total)}")
        for (conn, what), n in sorted(carried.items()):
            print(f"   {conn:<11} {what:<45} {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
