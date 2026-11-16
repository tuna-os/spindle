#!/usr/bin/env python3
"""Read a sync-tap recording back as per-connection timelines and anomalies.

    sync_tap_report.py FILE.jsonl [...]            # summary + anomalies
    sync_tap_report.py FILE.jsonl --timeline       # one line per exchange
    sync_tap_report.py FILE.jsonl --show SEQ       # one exchange in full

What it calls an anomaly is something an MSC4186 client renders as a
glitch, each checked per connection (user, device, conn_id):

  error            a non-200 answer (M_UNKNOWN_POS is counted apart: the
                   client starts over, which Element X shows as a reload)
  count-drop       a list's `count` fell by more than a third, or to 0
  room-lost        a room the client held at `initial` is sent `initial`
                   again without the connection having restarted: the
                   client throws its timeline away and rebuilds it
  bump-backwards   a room's `bump_stamp` went down
  nameless         an `initial` room with no name, no heroes and no
                   m.room.name / m.room.canonical_alias in required_state:
                   the room list shows it as "Empty room"
  empty-limited    `limited: true` with an empty timeline
  pos-chain        a request's `pos` is not the previous answer's `pos`
                   (a client retry, or a response it never got)
  slow             an answer took longer than the request's timeout + 5 s
  window-short     fewer rooms in a list's ranges than `count` allows on
                   an initial answer: the visible window is short of rows
  hero-shape       a hero with a key MSC4186 does not define (it defines
                   user_id, displayname and avatar_url): matrix-rust-sdk
                   ignores it, so the room is named by raw user IDs
  bump-non-proper  a room's `bump_stamp` went up in an answer whose
                   complete (not `limited`) timeline holds no event of a
                   type MSC4186 says bumps a room: the room jumps to the top
                   of Element X's list for a rename, a join or a topic
  count-silent     a list's `count` fell, and no room in that answer says
                   the user left it: the client keeps the room it can no
                   longer find in the server's list
"""

from __future__ import annotations

import argparse
import collections
import json
import sys


def load(paths):
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    print(f"{path}:{n}: unparsable line skipped", file=sys.stderr)


def conn_key(e):
    return (e.get("user"), e.get("device"), e.get("conn_id") or "")


def req_pos(e):
    return (e.get("query") or {}).get("pos") or ((e.get("request") or {}).get("pos"))


def req_timeout(e):
    q = (e.get("query") or {}).get("timeout")
    r = (e.get("request") or {}).get("timeout")
    for v in (r, q):
        try:
            return int(v)
        except (TypeError, ValueError):
            continue
    return 0


def errcode(e):
    resp = e.get("response")
    return resp.get("errcode") if isinstance(resp, dict) else None


# MSC4186's `bump_stamp`: "proper" activity is an event of one of these types.
BUMP_TYPES = {
    "m.room.create",
    "m.room.message",
    "m.room.encrypted",
    "m.sticker",
    "m.call.invite",
    "m.poll.start",
    "m.beacon_info",
    "org.matrix.msc3672.beacon_info",
    "org.matrix.msc3381.poll.start",
}
HERO_KEYS = {"user_id", "displayname", "avatar_url"}


def room_named(room: dict, me: str | None = None) -> bool:
    if room.get("name") or room.get("heroes"):
        return True
    for ev in room.get("required_state") or []:
        if ev.get("type") in ("m.room.name", "m.room.canonical_alias") and (
            ev.get("content") or {}
        ):
            return True
    # An invite is named from its stripped state: the room's name, or the
    # member events of the people in it (the inviter, at least).
    for ev in room.get("invite_state") or []:
        if ev.get("type") in ("m.room.name", "m.room.canonical_alias") and (
            ev.get("content") or {}
        ):
            return True
        if ev.get("type") == "m.room.member" and ev.get("state_key") != me:
            return True
    return False


def own_leave(room: dict, me: str | None) -> bool:
    for ev in (room.get("required_state") or []) + (room.get("timeline") or []):
        if (
            ev.get("type") == "m.room.member"
            and ev.get("state_key") == me
            and (ev.get("content") or {}).get("membership") in ("leave", "ban")
        ):
            return True
    return False


def window_capacity(ranges, count):
    total = 0
    for lo, hi in ranges or []:
        if lo >= count:
            continue
        total += min(hi, count - 1) - lo + 1
    return total


def summarize(entry, prev_lists):
    resp = entry.get("response") if isinstance(entry.get("response"), dict) else {}
    lists = resp.get("lists") or {}
    rooms = resp.get("rooms") or {}
    initial = sum(1 for r in rooms.values() if r.get("initial"))
    counts = ",".join(f"{k}={v.get('count')}" for k, v in sorted(lists.items()))
    ext = ",".join(sorted(k for k, v in (resp.get("extensions") or {}).items() if v))
    return f"lists[{counts}] rooms={len(rooms)} initial={initial} ext[{ext}]"


def analyse(entries):
    by_conn = collections.defaultdict(list)
    for e in entries:
        by_conn[conn_key(e)].append(e)

    anomalies = []
    stats = {}
    for key, seq in by_conn.items():
        seq.sort(key=lambda e: e["seq"])
        held: dict[str, int] = {}  # room -> last bump_stamp
        last_counts: dict[str, int] = {}
        leaves_told = 0
        invites: set[str] = set()
        last_pos = None
        st = collections.Counter()
        params_lists = {}
        for e in seq:
            st["exchanges"] += 1
            pos = req_pos(e)
            code = errcode(e)
            req = e.get("request") if isinstance(e.get("request"), dict) else {}
            if isinstance(req.get("lists"), dict):
                for name, cfg in req["lists"].items():
                    params_lists.setdefault(name, {}).update(cfg or {})

            if pos is None:
                # A connection (re)start: the client holds nothing.
                st["restarts"] += 1
                held.clear()
                last_counts.clear()
                leaves_told = 0
            elif last_pos is not None and pos != last_pos:
                anomalies.append(
                    (e, "pos-chain", f"request pos {pos} != last answer pos {last_pos}")
                )

            if e.get("status") != 200:
                if code == "M_UNKNOWN_POS":
                    st["unknown_pos"] += 1
                else:
                    anomalies.append(
                        (
                            e,
                            "error",
                            f"{e.get('status')} {code}: {(e.get('response') or {}).get('error')}",
                        )
                    )
                last_pos = None
                continue

            timeout = req_timeout(e)
            if e.get("ms", 0) > timeout + 5000:
                anomalies.append(
                    (e, "slow", f"{e['ms']:.0f} ms against timeout {timeout} ms")
                )

            resp = e["response"]
            last_pos = resp.get("pos")
            me = e.get("user")
            # A server may tell the client it left a room in one answer and
            # drop the room from the count in the next: a leave told earlier
            # on the connection pays for one later fall of the count.
            leaves_told += sum(
                1 for r in (resp.get("rooms") or {}).values() if own_leave(r, me)
            )
            for name, lst in (resp.get("lists") or {}).items():
                count = lst.get("count")
                if count is None:
                    continue
                before = last_counts.get(name)
                if (
                    before is not None
                    and before > 0
                    and (count == 0 or count < before * 2 / 3)
                ):
                    anomalies.append(
                        (e, "count-drop", f"list {name}: count {before} -> {count}")
                    )
                if before is not None and pos is not None and count < before:
                    fall = before - count
                    paid = min(fall, leaves_told)
                    leaves_told -= paid
                    if fall > paid:
                        anomalies.append(
                            (
                                e,
                                "count-silent",
                                (
                                    f"list {name}: count {before} -> {count}, "
                                    f"{fall - paid} more than the rooms the client was told it left"
                                ),
                            )
                        )
                last_counts[name] = count
                ranges = (params_lists.get(name) or {}).get("ranges")
                if pos is None and ranges:
                    cap = window_capacity(ranges, count)
                    in_resp = sum(
                        1
                        for r in (resp.get("rooms") or {}).values()
                        if r.get("initial")
                    )
                    if in_resp < cap:
                        anomalies.append(
                            (
                                e,
                                "window-short",
                                f"list {name}: count {count}, ranges {ranges} allow {cap}, initial rooms sent {in_resp}",
                            )
                        )

            for rid, room in (resp.get("rooms") or {}).items():
                bump = room.get("bump_stamp")
                was_invite = rid in invites
                if room.get("invite_state") is not None:
                    invites.add(rid)
                else:
                    invites.discard(rid)
                if room.get("initial"):
                    # An accepted invite is sent in full: the client held
                    # only stripped state, so nothing is thrown away.
                    if rid in held and pos is not None and not was_invite:
                        anomalies.append(
                            (e, "room-lost", f"{rid} sent initial again mid-connection")
                        )
                    if not room_named(room, me):
                        anomalies.append(
                            (e, "nameless", f"{rid}: no name, heroes or name state")
                        )
                bad_hero_keys = sorted(
                    {k for h in room.get("heroes") or [] for k in h} - HERO_KEYS
                )
                if bad_hero_keys:
                    anomalies.append(
                        (e, "hero-shape", f"{rid}: hero keys {bad_hero_keys}")
                    )
                if room.get("limited") and not room.get("timeline"):
                    anomalies.append((e, "empty-limited", f"{rid}"))
                if bump is not None:
                    if rid in held and held[rid] is not None and bump < held[rid]:
                        anomalies.append(
                            (e, "bump-backwards", f"{rid}: {held[rid]} -> {bump}")
                        )
                    timeline = room.get("timeline") or []
                    if (
                        rid in held
                        and held[rid] is not None
                        and bump > held[rid]
                        and timeline
                        and not room.get("limited")
                        and not room.get("initial")
                        and not any(ev.get("type") in BUMP_TYPES for ev in timeline)
                        # For a room the user is no longer joined to, the
                        # stamp is when its membership changed.
                        and not any(
                            ev.get("type") == "m.room.member"
                            and ev.get("state_key") == me
                            for ev in timeline
                        )
                    ):
                        kinds_seen = sorted({ev.get("type") for ev in timeline})
                        anomalies.append(
                            (
                                e,
                                "bump-non-proper",
                                f"{rid}: bump_stamp rose for {kinds_seen}",
                            )
                        )
                    held[rid] = bump
                else:
                    held.setdefault(rid, None)
        stats[key] = st
    return by_conn, stats, anomalies


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="+")
    ap.add_argument("--timeline", action="store_true")
    ap.add_argument("--show", type=int, metavar="SEQ")
    ap.add_argument("--user")
    args = ap.parse_args()

    entries = [
        e for e in load(args.files) if not args.user or e.get("user") == args.user
    ]
    if args.show is not None:
        for e in entries:
            if e.get("seq") == args.show:
                print(json.dumps(e, indent=2))
                return 0
        print(f"no exchange {args.show}", file=sys.stderr)
        return 1

    by_conn, stats, anomalies = analyse(entries)
    for key, seq in by_conn.items():
        st = stats[key]
        ua = seq[-1].get("user_agent", "")[:60]
        print(f"== {key[0]} device={key[1]} conn_id={key[2]!r}  {ua}")
        print(
            f"   {st['exchanges']} exchanges, {st['restarts']} starts, {st['unknown_pos']} M_UNKNOWN_POS, "
            f"{seq[0]['t']} .. {seq[-1]['t']}"
        )
        if args.timeline:
            prev = {}
            for e in seq:
                tag = "START" if req_pos(e) is None else "     "
                if e.get("status") != 200:
                    line = f"{e.get('status')} {errcode(e)}"
                else:
                    line = summarize(e, prev)
                print(
                    f"   #{e['seq']:<6} {e['t'][11:23]} {e.get('ms', 0):>8.0f}ms {tag} {line}"
                )

    kinds = collections.Counter(kind for _, kind, _ in anomalies)
    print(
        f"\n{len(anomalies)} anomalies: "
        + ", ".join(f"{k}={v}" for k, v in kinds.most_common())
    )
    for e, kind, detail in anomalies[:200]:
        print(f"  #{e['seq']:<6} {e['t'][11:23]} {kind:<15} {detail}")
    if len(anomalies) > 200:
        print(f"  ... {len(anomalies) - 200} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
