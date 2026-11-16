"""Make one server's sliding sync answer comparable with the other's.

Room IDs become scenario names (`!g03`), event IDs become the label the
scenario gave the event (its body, or its ciphertext), and the values that
are only ever local to one server are dropped: `pos`, `origin_server_ts`,
`age`, `unsigned`, `event_id`, `prev_batch`, `next_batch` and the raw
`bump_stamp` (its relative order is compared elsewhere).
"""

from __future__ import annotations

import re

MASKED = {
    "pos",
    "origin_server_ts",
    "age",
    "unsigned",
    "event_id",
    "prev_batch",
    "next_batch",
    "txn_id",
    "replaces_state",
}

# The required_state types whose content a client renders; for the rest only
# (type, state_key) is compared.
CONTENT_COMPARED = {
    "m.room.name",
    "m.room.topic",
    "m.room.avatar",
    "m.room.canonical_alias",
    "m.room.encryption",
    "m.room.join_rules",
    "m.room.tombstone",
    "m.room.history_visibility",
}
MEMBER_KEYS = ("membership", "displayname", "is_direct")

ROOM_ID = re.compile(r"![A-Za-z0-9._=\-/+]+(?::[A-Za-z0-9.\-]+(?::\d+)?)?")
EVENT_ID = re.compile(r"\$[A-Za-z0-9._=\-/+]+(?::[A-Za-z0-9.\-]+)?")


class Namer:
    """Maps one server's IDs to scenario names."""

    def __init__(
        self, rooms: dict[str, str] | None = None, events: dict[str, str] | None = None
    ):
        self.rooms = dict(rooms or {})  # room ID -> name
        self.events = dict(events or {})  # event ID -> label

    def room(self, rid: str) -> str:
        name = self.rooms.get(rid)
        if name is None:
            # Unknown: number it in order of first sight, which lines up
            # across servers when both see the rooms in the same order.
            name = f"?{len([n for n in self.rooms.values() if n.startswith('?')]) + 1}"
            self.rooms[rid] = name
        return name

    def event(self, eid: str) -> str:
        return self.events.get(eid, "$?")

    def text(self, value: str) -> str:
        value = ROOM_ID.sub(
            lambda m: (
                "!" + self.room(m.group(0)) if m.group(0) in self.rooms else m.group(0)
            ),
            value,
        )
        return EVENT_ID.sub(
            lambda m: (
                "$" + self.events[m.group(0)]
                if m.group(0) in self.events
                else m.group(0)
            ),
            value,
        )

    def deep(self, value):
        if isinstance(value, dict):
            return {
                self.text(k) if isinstance(k, str) else k: self.deep(v)
                for k, v in value.items()
                if k not in MASKED
            }
        if isinstance(value, list):
            return [self.deep(v) for v in value]
        if isinstance(value, str):
            return self.text(value)
        return value


def event_label(ev: dict) -> str:
    """What an event is, independent of its ID."""
    content = ev.get("content") or {}
    etype = ev.get("type", "?")
    if etype == "m.room.message" and "body" in content:
        return content["body"]
    if etype == "m.room.encrypted" and "ciphertext" in content:
        return f"enc:{content['ciphertext']}"
    if "state_key" in ev:
        if etype == "m.room.member":
            return f"m.room.member[{ev['state_key']}]={content.get('membership')}"
        return f"{etype}[{ev['state_key']}]" if ev["state_key"] else etype
    return etype


def state_entries(events, namer: Namer) -> dict:
    """required_state as {(type, state_key): rendered content or None}."""
    out = {}
    for ev in events or []:
        key = (ev.get("type"), namer.text(ev.get("state_key", "")))
        content = ev.get("content") or {}
        if ev.get("type") in CONTENT_COMPARED:
            out[key] = namer.deep(content)
        elif ev.get("type") == "m.room.member":
            out[key] = {k: content.get(k) for k in MEMBER_KEYS if k in content}
        else:
            out[key] = None
    return out
