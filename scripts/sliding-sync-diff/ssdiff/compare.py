"""Compare two servers' exchanges, step by step.

The unit of comparison is a step: everything one connection received while
the client caught up with one change. One server can send a change in one
response and the other in two; Element X does not see a difference there,
so neither does the comparison. Within a step the rooms are merged: the
last value of each field wins, timelines are joined, and required_state is
the union.

Three layers, from what the user sees to what the wire carried:

1. view    the room list the client model builds (model.py)
2. step    the merged per-room fields and the list counts
3. anomaly sync_tap_report.py's checks on each server's own stream
"""

from __future__ import annotations

import collections
import os
import sys

from .model import RoomListModel
from .normalise import Namer, event_label, state_entries

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "sync-tap"))
import sync_tap_report

# A difference of one of these kinds changes what Element X shows.
VISIBLE = {
    "view-missing",
    "view-order",
    "view-name",
    "view-unread",
    "view-membership",
    "view-preview",
    "view-bump-stamp",
    "list-count",
    "error",
    "window",
}


# Users who share u2 with Alice from the start; see scenario.py.
ALREADY_SHARING = {
    f"@{u}:" for u in ("alice", "bob", "carol", "dave", "erin", "frank", "grace")
}


def explain(d: Diff) -> str | None:
    """Why a difference is not a Spindle bug, when the reason is known.

    Each rule is narrow on purpose: it names a field and the direction of
    the difference, so a new difference in the same field still shows.
    """
    if d.field in ("notification_count", "highlight_count") and d.synapse in (
        0,
        "<absent>",
    ):
        return (
            "Synapse sends notification_count and highlight_count as constant 0 "
            '("dummy values" in its handler); the MSC drops both fields. Spindle\'s are real counts.'
        )
    if (
        d.field == "e2ee.device_lists"
        and isinstance(d.synapse, dict)
        and isinstance(d.spindle, dict)
    ):
        missing = set(d.synapse["changed"]) - set(d.spindle["changed"])
        extra = set(d.spindle["changed"]) - set(d.synapse["changed"])
        if not extra and all(
            any(u.startswith(p) for p in ALREADY_SHARING) for u in missing
        ):
            return (
                "Synapse also lists users Alice already shared an encrypted-capable room with; "
                "only users who newly share a room must be listed."
            )
    if (
        d.field.startswith("required_state m.room.topic")
        and isinstance(d.synapse, dict)
        and "m.topic" in d.synapse
        and isinstance(d.spindle, dict)
        and d.spindle.get("topic") == d.synapse.get("topic")
    ):
        return "Synapse's createRoom adds the MSC3765 rich-text topic beside the plain one."
    return None


class Diff:
    def __init__(self, step, conn, kind, room, field, synapse, spindle, note=""):
        self.step, self.conn, self.kind, self.room = step, conn, kind, room
        self.field, self.synapse, self.spindle, self.note = (
            field,
            synapse,
            spindle,
            note,
        )
        self.explained = explain(self)

    @property
    def visible(self) -> bool:
        return self.kind in VISIBLE and not self.explained

    def as_dict(self):
        return {
            "step": self.step,
            "conn": self.conn,
            "kind": self.kind,
            "room": self.room,
            "field": self.field,
            "synapse": self.synapse,
            "spindle": self.spindle,
            "visible": self.visible,
            "note": self.note,
            "explained": self.explained,
        }


def _room_summary(data: dict, namer: Namer) -> dict:
    out = {}
    for key in (
        "initial",
        "name",
        "is_dm",
        "joined_count",
        "invited_count",
        "notification_count",
        "highlight_count",
        "num_live",
        "limited",
    ):
        if key in data:
            out[key] = data[key]
    if "avatar" in data:
        out["avatar"] = data["avatar"]
    out["bump_stamp?"] = "bump_stamp" in data
    if data.get("heroes") is not None:
        out["heroes"] = sorted(h.get("user_id") for h in data["heroes"])
    if data.get("invite_state") is not None:
        out["invite_state"] = sorted(
            f"{e.get('type')}[{e.get('state_key', '')}]" for e in data["invite_state"]
        )
    out["timeline"] = [event_label(namer.deep(e)) for e in data.get("timeline") or []]
    out["required_state"] = state_entries(data.get("required_state"), namer)
    return out


def _merge_room(into: dict, new: dict) -> None:
    for key, value in new.items():
        if key == "timeline":
            into.setdefault("timeline", []).extend(value)
        elif key == "required_state":
            into.setdefault("required_state", {}).update(value)
        elif key in ("initial", "limited") or key == "bump_stamp?":
            into[key] = into.get(key, False) or value
        else:
            into[key] = value


def _extensions(resp: dict, namer: Namer) -> dict:
    ext = resp.get("extensions") or {}
    out = {}
    ad = ext.get("account_data") or {}
    if ad:
        out["account_data.global"] = sorted(
            e.get("type") for e in ad.get("global") or []
        )
        out["account_data.rooms"] = {
            namer.room(r): sorted(e.get("type") for e in evs)
            for r, evs in (ad.get("rooms") or {}).items()
        }
    rc = ext.get("receipts") or {}
    if rc:
        rooms = {}
        for rid, ev in (rc.get("rooms") or {}).items():
            content = ev.get("content") or {}
            rooms[namer.room(rid)] = sorted(
                f"{namer.event(eid)}:{rtype}:{user}"
                for eid, types in content.items()
                for rtype, users in types.items()
                for user in users
            )
        out["receipts.rooms"] = rooms
    ty = ext.get("typing") or {}
    if ty:
        out["typing.rooms"] = {
            namer.room(rid): sorted((ev.get("content") or {}).get("user_ids") or [])
            for rid, ev in (ty.get("rooms") or {}).items()
        }
    e2 = ext.get("e2ee") or {}
    if e2:
        dl = e2.get("device_lists") or {}
        out["e2ee.device_lists"] = {
            "changed": sorted(dl.get("changed") or []),
            "left": sorted(dl.get("left") or []),
        }
        out["e2ee.otk_count"] = e2.get("device_one_time_keys_count")
        out["e2ee.fallback_types"] = (
            sorted(e2.get("device_unused_fallback_key_types") or [])
            if e2.get("device_unused_fallback_key_types") is not None
            else None
        )
    td = ext.get("to_device") or {}
    if td:
        out["to_device.events"] = [
            f"{e.get('type')} from {e.get('sender')}" for e in td.get("events") or []
        ]
        out["to_device.next_batch?"] = "next_batch" in td
    return out


def _merge_ext(into: dict, new: dict) -> None:
    for key, value in new.items():
        if key == "to_device.events":
            into.setdefault(key, []).extend(value)
        elif isinstance(value, dict) and key not in (
            "e2ee.device_lists",
            "e2ee.otk_count",
        ):
            slot = into.setdefault(key, {})
            for k, v in value.items():
                if isinstance(v, list) and key != "typing.rooms":
                    slot[k] = sorted(set(slot.get(k, [])) | set(v))
                else:
                    slot[k] = v
        elif key == "e2ee.device_lists":
            slot = into.setdefault(key, {"changed": [], "left": []})
            slot["changed"] = sorted(set(slot["changed"]) | set(value["changed"]))
            slot["left"] = sorted(set(slot["left"]) | set(value["left"]))
        elif key == "account_data.global":
            into[key] = sorted(set(into.get(key, [])) | set(value))
        else:
            into[key] = value


class StepView:
    """One server's merged view of one step on one connection."""

    def __init__(self):
        self.rooms: dict[str, dict] = {}
        self.counts: dict[str, int] = {}
        self.ext: dict = {}
        self.errors: list[str] = []
        self.exchanges = 0
        self.first_window: list[str] | None = None


def step_views(exchanges: list[dict], namer: Namer) -> dict:
    """{(step, conn): StepView} for one server."""
    views: dict = collections.OrderedDict()
    for ex in exchanges:
        if ex.get("phase") == "lost":
            continue
        key = (ex["step"], ex["conn_id"])
        view = views.setdefault(key, StepView())
        view.exchanges += 1
        if ex["status"] != 200:
            code = (ex.get("response") or {}).get("errcode")
            view.errors.append(f"{ex['status']} {code}")
            continue
        resp = ex["response"]
        for lname, lst in (resp.get("lists") or {}).items():
            if lst.get("count") is not None:
                view.counts[lname] = lst["count"]
        rooms = resp.get("rooms") or {}
        if (
            (ex.get("query") or {}).get("pos") is None
            and ex["conn_id"] == "room-list"
            and view.first_window is None
        ):
            view.first_window = sorted(namer.room(r) for r in rooms)
        for rid, data in rooms.items():
            _merge_room(
                view.rooms.setdefault(namer.room(rid), {}), _room_summary(data, namer)
            )
        _merge_ext(view.ext, _extensions(resp, namer))
    return views


def compare_steps(syn: dict, spi: dict) -> list[Diff]:
    diffs = []
    for key in list(dict.fromkeys(list(syn) + list(spi))):
        step, conn = key
        a, b = syn.get(key), spi.get(key)
        if a is None or b is None:
            diffs.append(
                Diff(
                    step,
                    conn,
                    "error",
                    None,
                    "step",
                    a is not None,
                    b is not None,
                    "one server has no exchanges for this step",
                )
            )
            continue
        if (a.errors or b.errors) and a.errors != b.errors:
            diffs.append(Diff(step, conn, "error", None, "status", a.errors, b.errors))
        for lname in sorted(set(a.counts) | set(b.counts)):
            if a.counts.get(lname) != b.counts.get(lname):
                diffs.append(
                    Diff(
                        step,
                        conn,
                        "list-count",
                        None,
                        f"lists.{lname}.count",
                        a.counts.get(lname),
                        b.counts.get(lname),
                    )
                )
        if a.first_window != b.first_window:
            only_a = sorted(set(a.first_window or []) - set(b.first_window or []))
            only_b = sorted(set(b.first_window or []) - set(a.first_window or []))
            diffs.append(
                Diff(
                    step,
                    conn,
                    "window",
                    None,
                    "rooms in the pos-less answer",
                    only_a,
                    only_b,
                    "rooms only that server put in the window",
                )
            )
        for room in sorted(set(a.rooms) | set(b.rooms)):
            ra, rb = a.rooms.get(room), b.rooms.get(room)
            if ra is None or rb is None:
                diffs.append(
                    Diff(
                        step,
                        conn,
                        "room-presence",
                        room,
                        "sent",
                        ra is not None,
                        rb is not None,
                        _presence_note(ra or rb),
                    )
                )
                continue
            for field in sorted(set(ra) | set(rb)):
                if field == "required_state":
                    _compare_state(
                        diffs, step, conn, room, ra.get(field, {}), rb.get(field, {})
                    )
                    continue
                va, vb = ra.get(field, "<absent>"), rb.get(field, "<absent>")
                if va != vb:
                    diffs.append(
                        Diff(step, conn, f"field:{field}", room, field, va, vb)
                    )
        for field in sorted(set(a.ext) | set(b.ext)):
            va, vb = a.ext.get(field, "<absent>"), b.ext.get(field, "<absent>")
            if va != vb:
                diffs.append(
                    Diff(
                        step,
                        conn,
                        f"extension:{field.split('.')[0]}",
                        None,
                        field,
                        va,
                        vb,
                    )
                )
    return diffs


def _presence_note(room: dict) -> str:
    bits = []
    if room.get("initial"):
        bits.append("initial")
    if room.get("timeline"):
        bits.append(f"timeline {room['timeline'][-3:]}")
    return ", ".join(bits)


def _compare_state(diffs, step, conn, room, sa: dict, sb: dict):
    keys_a, keys_b = set(sa), set(sb)
    if keys_a != keys_b:
        diffs.append(
            Diff(
                step,
                conn,
                "field:required_state",
                room,
                "required_state keys",
                sorted(f"{t}[{k}]" for t, k in keys_a - keys_b),
                sorted(f"{t}[{k}]" for t, k in keys_b - keys_a),
                "entries only that server sent",
            )
        )
    for key in sorted(keys_a & keys_b):
        if sa[key] != sb[key]:
            diffs.append(
                Diff(
                    step,
                    conn,
                    "field:required_state",
                    room,
                    f"required_state {key[0]}[{key[1]}]",
                    sa[key],
                    sb[key],
                )
            )


def model_views(exchanges: list[dict], namer: Namer, observer: str) -> dict:
    """{step: rows} of the room list after each step, on `room-list`."""
    model = RoomListModel(observer)
    out = collections.OrderedDict()
    for ex in exchanges:
        if ex["conn_id"] != "room-list" or ex.get("phase") == "lost":
            continue
        if ex["status"] == 200:
            model.apply(ex["response"], namer)
        out[ex["step"]] = [dict(r) for r in model.view()]
    return out


def compare_models(syn: dict, spi: dict) -> list[Diff]:
    diffs = []
    for step in list(dict.fromkeys(list(syn) + list(spi))):
        a, b = syn.get(step, []), spi.get(step, [])
        ia = {r["room"]: r for r in a}
        ib = {r["room"]: r for r in b}
        for room in sorted(set(ia) ^ set(ib)):
            diffs.append(
                Diff(
                    step,
                    "room-list",
                    "view-missing",
                    room,
                    "in room list",
                    room in ia,
                    room in ib,
                )
            )
        common = [r["room"] for r in a if r["room"] in ib]
        order_b = [r["room"] for r in b if r["room"] in ia]
        if common != order_b:
            moved = _moved(common, order_b)
            diffs.append(
                Diff(
                    step,
                    "room-list",
                    "view-order",
                    None,
                    "order (newest first)",
                    common,
                    order_b,
                    f"rooms out of place: {moved}",
                )
            )
        for room in sorted(set(ia) & set(ib)):
            ra, rb = ia[room], ib[room]
            for field, kind in (
                ("display", "view-name"),
                ("membership", "view-membership"),
                ("notification_count", "view-unread"),
                ("highlight_count", "view-unread"),
                ("preview", "view-preview"),
                ("has_bump_stamp", "view-bump-stamp"),
            ):
                if ra[field] != rb[field]:
                    diffs.append(
                        Diff(step, "room-list", kind, room, field, ra[field], rb[field])
                    )
    return _collapse(diffs)


def _moved(a: list, b: list) -> list:
    """The rooms whose relative order differs: those not in a longest common subsequence."""
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            dp[i][j] = (
                dp[i + 1][j + 1] + 1
                if a[i] == b[j]
                else max(dp[i + 1][j], dp[i][j + 1])
            )
    i = j = 0
    keep = set()
    while i < n and j < m:
        if a[i] == b[j]:
            keep.add(a[i])
            i += 1
            j += 1
        elif dp[i + 1][j] >= dp[i][j + 1]:
            i += 1
        else:
            j += 1
    return [x for x in a if x not in keep]


def _collapse(diffs: list[Diff]) -> list[Diff]:
    """A view difference that persists step after step is one finding.

    The first step it appears in is reported, with the steps it lasted.
    """
    out, open_ = [], {}
    order = []
    for d in diffs:
        key = (d.kind, d.room, d.field, repr(d.synapse), repr(d.spindle))
        if key in open_:
            open_[key].note_steps.append(d.step)
            continue
        d.note_steps = [d.step]
        open_[key] = d
        order.append(d)
    for d in order:
        if len(d.note_steps) > 1:
            span = f"persists through {len(d.note_steps)} steps ({d.note_steps[0]} .. {d.note_steps[-1]})"
            d.note = f"{d.note}; {span}" if d.note else span
        out.append(d)
    return out


def anomalies(exchanges: list[dict], namer: Namer) -> list[dict]:
    """sync_tap_report's checks, with room IDs named."""
    # The client never saw a lost answer, so neither do the checks.
    seen = [dict(e) for e in exchanges if e.get("phase") != "lost"]
    _, _, found = sync_tap_report.analyse(seen)
    out = []
    for ex, kind, detail in found:
        room = None
        for rid, name in namer.rooms.items():
            if rid in detail:
                detail = detail.replace(rid, "!" + name)
                room = name
        out.append(
            {
                "step": ex["step"],
                "conn": ex["conn_id"],
                "seq": ex["seq"],
                "kind": kind,
                "room": room,
                "detail": detail,
            }
        )
    return out


def compare_anomalies(syn: list[dict], spi: list[dict]) -> dict:
    def key(a):
        return (a["step"], a["conn"], a["kind"], a["room"])

    ka = collections.Counter(key(a) for a in syn)
    kb = collections.Counter(key(a) for a in spi)
    only_spindle = [a for a in spi if kb[key(a)] > ka.get(key(a), 0)]
    only_synapse = [a for a in syn if ka[key(a)] > kb.get(key(a), 0)]
    both = [a for a in spi if key(a) in ka]
    return {"only_spindle": only_spindle, "only_synapse": only_synapse, "both": both}
