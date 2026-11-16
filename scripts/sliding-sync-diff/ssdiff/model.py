"""What Element X's room list shows, rebuilt from one server's answers.

A field-by-field diff of two responses says what the wire carried. This
says what the person sees: which rooms the list holds, in which order, under
which name, with which unread badge. It follows matrix-rust-sdk's handling
in outline, not line by line:

- `name` in a response, or m.room.name in required_state, names the room;
  then m.room.canonical_alias; then the heroes; then, when there are no
  heroes (an invite: neither server sends heroes for one), the member
  events the client holds; else "Empty Room". A hero's name is its
  `displayname` (the key ruma reads; any other key is not seen), else the
  hero's member event if the client holds one, else the hero is skipped.
- `heroes`, `joined_count`, `invited_count`, `notification_count`,
  `highlight_count` and `bump_stamp` are kept until a response replaces them.
- A room with `invite_state` is an invite. Otherwise Alice's own
  m.room.member event, in required_state or the timeline, sets her
  membership. A left room leaves the list.
- The order is `bump_stamp` (the SDK's recency stamp), newest first, then
  the display name. A room with no stamp sorts last. Current matrix-rust-sdk
  sorts by the timestamp of the latest event it computes on the client
  first, and uses the recency stamp only when neither room has one; older
  Element X builds use the stamp alone. So a `view-order` difference is
  what an older build shows, and what a current build shows for rooms with
  no latest event (new invites, empty rooms).
- A room whose tombstone points at a room Alice has joined is hidden
  (the SDK's deduplicate-versions filter).

The model is the same code for both servers, so where it is approximate it
is approximate on both sides equally.
"""

from __future__ import annotations

from .normalise import Namer, event_label

STICKY = (
    "joined_count",
    "invited_count",
    "notification_count",
    "highlight_count",
    "bump_stamp",
    "is_dm",
)


class RoomListModel:
    def __init__(self, observer: str):
        self.observer = observer
        self.rooms: dict[str, dict] = {}
        self.counts: dict[str, int] = {}
        self.namer: Namer | None = None

    def apply(self, resp: dict, namer: Namer) -> None:
        self.namer = namer
        for lname, lst in (resp.get("lists") or {}).items():
            if lst.get("count") is not None:
                self.counts[lname] = lst["count"]
        for rid, data in (resp.get("rooms") or {}).items():
            name = namer.room(rid)
            room = self.rooms.setdefault(
                name, {"membership": None, "state": {}, "timeline": []}
            )
            for key in STICKY:
                if data.get(key) is not None:
                    room[key] = data[key]
            if data.get("name") is not None:
                room["response_name"] = data["name"]
            if data.get("heroes") is not None:
                room["heroes"] = [
                    (h.get("user_id"), h.get("displayname"))
                    for h in data["heroes"]
                    if h.get("user_id") != self.observer
                ]
            if data.get("invite_state") is not None:
                room["membership"] = "invite"
                for ev in data["invite_state"]:
                    room["state"][(ev.get("type"), ev.get("state_key", ""))] = (
                        ev.get("content") or {}
                    )
            for ev in data.get("required_state") or []:
                room["state"][(ev.get("type"), ev.get("state_key", ""))] = (
                    ev.get("content") or {}
                )
            timeline = data.get("timeline") or []
            if data.get("limited") or data.get("initial"):
                room["timeline"] = []
            for ev in timeline:
                room["timeline"].append(event_label(namer.deep(ev)))
                if "state_key" in ev:
                    room["state"][(ev.get("type"), ev.get("state_key"))] = (
                        ev.get("content") or {}
                    )
            room["timeline"] = room["timeline"][-5:]
            own = room["state"].get(("m.room.member", self.observer))
            if own and own.get("membership") and data.get("invite_state") is None:
                room["membership"] = own["membership"]
            elif room["membership"] is None:
                room["membership"] = "join"

    def display_name(self, room: dict) -> str:
        name = room.get("response_name") or (
            room["state"].get(("m.room.name", "")) or {}
        ).get("name")
        if name:
            return name
        alias = (room["state"].get(("m.room.canonical_alias", "")) or {}).get("alias")
        if alias:
            return alias
        # matrix-sdk-base (room/display_name.rs): a hero's `displayname`, or
        # else the name from that member's event in the store; a hero with
        # neither is skipped ("Ignoring hero, no member info"). With $LAZY
        # members the store holds only the members who sent something.
        heroes = []
        for user_id, displayname in room.get("heroes") or []:
            member = room["state"].get(("m.room.member", user_id))
            if displayname:
                heroes.append(displayname)
            elif member is not None:
                heroes.append(member.get("displayname") or user_id)
        if not room.get("heroes"):
            members = sorted(
                (key[1], (content or {}).get("displayname") or key[1])
                for key, content in room["state"].items()
                if key[0] == "m.room.member"
                and key[1] != self.observer
                and (content or {}).get("membership") in ("join", "invite")
            )
            heroes = [name for _, name in members[:5]]
        if heroes:
            total = (
                (room.get("joined_count") or 0) + (room.get("invited_count") or 0) - 1
            )
            if total > len(heroes):
                return f"{', '.join(heroes)} and {total - len(heroes)} others"
            if len(heroes) == 1:
                return heroes[0]
            return f"{', '.join(heroes[:-1])} and {heroes[-1]}"
        return "Empty Room"

    def view(self) -> list[dict]:
        """The rows of the room list, in order."""
        joined = {n for n, r in self.rooms.items() if r["membership"] == "join"}
        rows = []
        for name, room in self.rooms.items():
            if room["membership"] in ("leave", "ban"):
                continue
            tomb = room["state"].get(("m.room.tombstone", "")) or {}
            successor = tomb.get("replacement_room")
            if successor and self.namer and self.namer.rooms.get(successor) in joined:
                continue
            rows.append(
                {
                    "room": name,
                    "display": self.display_name(room),
                    "membership": room["membership"],
                    "notification_count": room.get("notification_count", 0),
                    "highlight_count": room.get("highlight_count", 0),
                    "preview": room["timeline"][-1] if room["timeline"] else None,
                    "_bump": room.get("bump_stamp"),
                }
            )
        rows.sort(key=lambda r: (r["_bump"] is None, -(r["_bump"] or 0), r["display"]))
        for r in rows:
            r["has_bump_stamp"] = r.pop("_bump") is not None
        return rows
