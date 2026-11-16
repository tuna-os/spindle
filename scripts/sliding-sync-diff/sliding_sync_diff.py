#!/usr/bin/env python3
"""Run Element X-shaped sliding sync traffic against Synapse and Spindle and compare.

    sliding_sync_diff.py run    [--synapse URL] [--spindle URL] [--out DIR] [--json]
    sliding_sync_diff.py replay TAP.jsonl [...]  [--mutate-every N]
    sliding_sync_diff.py report DIR [--json]     # compare saved exchanges again

`up.sh` starts both servers; `run.sh` does the whole thing in one command.
See README.md in this directory for what each check means.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ssdiff import compare, driver, report
from ssdiff.http import Server
from ssdiff.normalise import Namer

SIDES = ("synapse", "spindle")


def _servers(args):
    return [
        Server("synapse", args.synapse, args.secret),
        Server("spindle", args.spindle, args.secret),
    ]


def _version(server: Server) -> str:
    status, body, _ = server.raw("GET", "/_matrix/federation/v1/version")
    if status == 200:
        s = body.get("server") or {}
        return f"{s.get('name')} {s.get('version')}"
    return "unknown"


def _save(out_dir: str, side: str, exchanges, world, extra=None):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, f"{side}.jsonl"), "w", encoding="utf-8") as fh:
        fh.writelines(json.dumps(ex, sort_keys=True) + "\n" for ex in exchanges)
    names = {
        "rooms": world.room_names(),
        "events": world.events,
        "observer": world.alice.user_id,
        "notes": world.notes,
    }
    if extra:
        names.update(extra)
    with open(os.path.join(out_dir, f"{side}.names.json"), "w", encoding="utf-8") as fh:
        json.dump(names, fh, indent=1, sort_keys=True)


def analyse(out_dir: str, meta: dict) -> dict:
    exchanges, namers, observer, extras = {}, {}, None, {}
    for side in SIDES:
        with open(os.path.join(out_dir, f"{side}.jsonl"), encoding="utf-8") as fh:
            exchanges[side] = [json.loads(line) for line in fh if line.strip()]
        with open(os.path.join(out_dir, f"{side}.names.json"), encoding="utf-8") as fh:
            names = json.load(fh)
        namers[side] = Namer(names["rooms"], names["events"])
        observer = names["observer"]
        extras[side] = names
    step_diffs = compare.compare_steps(
        compare.step_views(exchanges["synapse"], namers["synapse"]),
        compare.step_views(exchanges["spindle"], namers["spindle"]),
    )
    view_diffs = compare.compare_models(
        compare.model_views(exchanges["synapse"], namers["synapse"], observer),
        compare.model_views(exchanges["spindle"], namers["spindle"], observer),
    )
    anomalies = {
        side: compare.anomalies(exchanges[side], namers[side]) for side in SIDES
    }
    anomaly_cmp = compare.compare_anomalies(anomalies["synapse"], anomalies["spindle"])
    timings = {side: extras[side].get("timings", []) for side in SIDES}
    for side in SIDES:
        if extras[side].get("notes"):
            meta[f"{side} notes"] = "; ".join(extras[side]["notes"])
        if extras[side].get("error"):
            meta[f"{side} error"] = extras[side]["error"]
    return report.build(meta, step_diffs, view_diffs, anomalies, anomaly_cmp, timings)


def emit(rep: dict, out_dir: str, as_json: bool):
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=1, default=str)
    txt = report.text(rep)
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(txt)
    print(json.dumps(rep, indent=1, default=str) if as_json else txt)


def cmd_run(args) -> int:
    servers = _servers(args)
    runs = [
        driver.ScenarioRun(
            s,
            args.long_poll_ms,
            args.drain_ms,
            args.enc_poll_ms,
            args.batch,
            args.profiles,
            args.restart_cmd,
        )
        for s in servers
    ]
    log = lambda m: print(m, file=sys.stderr)
    log(f"== scenario against {servers[0].base} and {servers[1].base}")
    started = time.time()
    driver.run_scenario(runs, log=log, only_steps=args.steps)
    meta = {
        "mode": "scenario",
        "synapse": _version(servers[0]),
        "spindle": args.spindle_label or _version(servers[1]),
        "long_poll_ms": args.long_poll_ms,
        "drain_ms": args.drain_ms,
        "growing_batch": args.batch,
        "rooms_seeded": len(runs[0].world.rooms),
        "wall_s": round(time.time() - started, 1),
        "out": args.out,
    }
    for side, run in zip(SIDES, runs):
        _save(
            args.out,
            side,
            run.rec.exchanges if run.rec else [],
            run.world,
            {"timings": run.timings, "error": run.error},
        )
    rep = analyse(args.out, meta)
    emit(rep, args.out, args.json)
    return 1 if any(r.error for r in runs) else 0


def cmd_replay(args) -> int:
    sys.path.insert(
        0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sync-tap")
    )
    import sync_tap_report

    entries = [
        e
        for e in sync_tap_report.load(args.files)
        if isinstance(e.get("request"), dict)
        and (not args.user or e.get("user") == args.user)
    ]
    entries.sort(key=lambda e: e.get("seq", 0))
    if args.limit:
        entries = entries[: args.limit]
    servers = _servers(args)
    runs = [driver.ReplayRun(s, args.max_timeout_ms) for s in servers]
    log = lambda m: print(m, file=sys.stderr)
    log(f"== replaying {len(entries)} recorded requests")
    driver.run_replay(runs, entries, args.mutate_every, log=log)
    meta = {
        "mode": "replay",
        "recording": ", ".join(args.files),
        "requests": len(entries),
        "synapse": _version(servers[0]),
        "spindle": args.spindle_label or _version(servers[1]),
        "max_timeout_ms": args.max_timeout_ms,
        "mutate_every": args.mutate_every,
        "out": args.out,
    }
    for side, run in zip(SIDES, runs):
        _save(args.out, side, run.exchanges, run.world)
    rep = analyse(args.out, meta)
    emit(rep, args.out, args.json)
    return 0


def cmd_report(args) -> int:
    rep = analyse(args.dir, {"mode": "report", "out": args.dir})
    emit(rep, args.dir, args.json)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--synapse", default="http://127.0.0.1:18008")
        p.add_argument("--spindle", default="http://127.0.0.1:18009")
        p.add_argument(
            "--secret",
            default=os.environ.get("SSDIFF_SHARED_SECRET", "ssdiff-shared-secret"),
        )
        p.add_argument("--out", default="tmp/sliding-sync-diff/out")
        p.add_argument("--json", action="store_true", help="print the report as JSON")
        p.add_argument(
            "--spindle-label", help="what to call the Spindle build in the report"
        )

    p = sub.add_parser("run", help="seed the scenario and run Element X's sequence")
    common(p)
    p.add_argument("--long-poll-ms", type=int, default=3000)
    p.add_argument("--drain-ms", type=int, default=500)
    p.add_argument("--enc-poll-ms", type=int, default=1000)
    p.add_argument(
        "--batch", type=int, default=100, help="growing batch size (Element X: 100)"
    )
    p.add_argument(
        "--profiles", action="store_true", help="also enable the profiles extension"
    )
    p.add_argument("--steps", nargs="*", help="run only these steps (after `initial`)")
    p.add_argument(
        "--restart-cmd",
        help="command that restarts one server; {side} is synapse or "
        "spindle. Enables the server-restart step.",
    )
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("replay", help="replay sync-tap request bodies")
    common(p)
    p.add_argument("files", nargs="+")
    p.add_argument("--user", help="only this recorded user's exchanges")
    p.add_argument("--limit", type=int)
    p.add_argument("--max-timeout-ms", type=int, default=500)
    p.add_argument(
        "--mutate-every",
        type=int,
        default=0,
        help="apply the next scenario mutation every N replayed requests",
    )
    p.set_defaults(fn=cmd_replay)

    p = sub.add_parser("report", help="compare saved exchanges again")
    p.add_argument("dir")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_report)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
