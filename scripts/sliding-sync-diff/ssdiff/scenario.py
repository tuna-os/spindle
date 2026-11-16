"""The scenario: who exists, which rooms, and what changes between syncs.

Everything here runs once per server, in the same order, from the same
seeded random generator, so the two servers hold the same rooms in the same
recency order. Room IDs differ between the servers; the scenario's room
names (`dm-bob`, `g03`, ...) are what the comparison joins on.

Alice is the observed user, on device ELEMENTX. Everyone else exists to make
something happen to her room list.
"""

from __future__ import annotations

import random
import time

from .http import MatrixError, Server, User, quote

PASSWORD = "ssdiff-password-1"
OBSERVER = "alice"
OBSERVER_DEVICE = "ELEMENTX"
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"]
# Shares no room with Alice until a step makes him: the e2ee extension must
# then list him in device_lists.changed, or Alice's client never fetches his
# keys. Everyone in USERS already shares u2 with her.
STRANGER = "henry"
AVATAR = "mxc://diff.test/ssdiffavatar"

# Messages in different rooms must land in different milliseconds, or a sort
# on timestamps ties where a sort on stream order does not. That would be a
# harness artefact, not a server difference.
MESSAGE_GAP_S = 0.012


class World:
    """One server's copy of the scenario: the IDs it minted, by name."""

    def __init__(self, server: Server):
        self.server = server
        self.users: dict[str, User] = {}
        self.rooms: dict[str, str] = {}  # scenario name -> room ID
        self.events: dict[str, str] = {}  # event ID -> label
        self.last_event: dict[str, str] = {}  # scenario name -> last event ID sent
        self.notes: list[str] = []  # things a step skipped, and why
        self.upgrade_version: str | None = None

    def uid(self, localpart: str) -> str:
        return f"@{localpart}:{self.server_name}"

    @property
    def server_name(self) -> str:
        return self.users[OBSERVER].user_id.split(":", 1)[1]

    @property
    def alice(self) -> User:
        return self.users[OBSERVER]

    def room_names(self) -> dict[str, str]:
        return {rid: name for name, rid in self.rooms.items()}

    # --- the operations steps are made of -------------------------------------

    def msg(
        self, room: str, sender: str, body: str, mention: list[str] | None = None
    ) -> str:
        content = {"msgtype": "m.text", "body": body}
        if mention is not None:
            content["m.mentions"] = {"user_ids": [self.uid(u) for u in mention]}
        eid = self.users[sender].send(self.rooms[room], "m.room.message", content)
        self.events[eid] = body
        self.last_event[room] = eid
        time.sleep(MESSAGE_GAP_S)
        return eid

    def enc(self, room: str, sender: str, label: str) -> str:
        # Not real Megolm: the server never decrypts, so a well-formed shell
        # is enough. The ciphertext doubles as the event's label.
        content = {
            "algorithm": "m.megolm.v1.aes-sha2",
            "ciphertext": label,
            "sender_key": "ssdiffsenderkey",
            "session_id": "ssdiffsession",
            "device_id": self.users[sender].device_id,
        }
        eid = self.users[sender].send(self.rooms[room], "m.room.encrypted", content)
        self.events[eid] = label
        self.last_event[room] = eid
        time.sleep(MESSAGE_GAP_S)
        return eid

    def state(self, room: str, sender: str, etype: str, key: str, content: dict) -> str:
        eid = self.users[sender].state(self.rooms[room], etype, key, content)
        self.events[eid] = f"{etype}[{key}]"
        return eid

    def create(
        self,
        name: str,
        creator: str,
        *,
        members=(),
        invite=(),
        title=None,
        topic=None,
        avatar=False,
        alias=None,
        direct=False,
        encrypted=False,
        space=False,
        public=False,
    ) -> str:
        body: dict = {"preset": "public_chat" if public else "private_chat"}
        if direct:
            body["preset"] = "trusted_private_chat"
            body["is_direct"] = True
        if title:
            body["name"] = title
        if topic:
            body["topic"] = topic
        if alias:
            body["room_alias_name"] = alias
        if space:
            body["creation_content"] = {"type": "m.space"}
        initial = []
        if encrypted:
            initial.append(
                {
                    "type": "m.room.encryption",
                    "state_key": "",
                    "content": {"algorithm": "m.megolm.v1.aes-sha2"},
                }
            )
        if avatar:
            initial.append(
                {"type": "m.room.avatar", "state_key": "", "content": {"url": AVATAR}}
            )
        if initial:
            body["initial_state"] = initial
        invitees = list(members) + list(invite)
        if invitees:
            body["invite"] = [self.uid(u) for u in invitees]
        rid = self.users[creator].create_room(body)
        self.rooms[name] = rid
        for member in members:
            self.users[member].join(rid)
        return rid


def seed(world: World) -> None:
    """Users, rooms and history. Alice ends up with about fifty rooms."""
    srv = world.server
    for localpart in USERS + [STRANGER]:
        try:
            srv.register(localpart, PASSWORD)
        except MatrixError as err:
            if (err.body or {}).get("errcode") != "M_USER_IN_USE":
                raise
        device = OBSERVER_DEVICE if localpart == OBSERVER else f"{localpart.upper()}DEV"
        user = srv.login(localpart, PASSWORD, device)
        world.users[localpart] = user
        user.set_displayname(localpart.capitalize())

    w = world
    rng = random.Random(4186)

    # Alice's device keys and one-time keys, so the e2ee extension has counts
    # to report. Signatures are not checked by either server on upload.
    w.alice.keys_upload(
        {
            "device_keys": {
                "user_id": w.alice.user_id,
                "device_id": w.alice.device_id,
                "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                "keys": {
                    f"curve25519:{w.alice.device_id}": "ssdiffcurve",
                    f"ed25519:{w.alice.device_id}": "ssdiffed",
                },
                "signatures": {
                    w.alice.user_id: {f"ed25519:{w.alice.device_id}": "ssdiffsig"}
                },
            },
            "one_time_keys": {
                f"signed_curve25519:AAAA{i}": {
                    "key": f"ssdiffotk{i}",
                    "signatures": {
                        w.alice.user_id: {f"ed25519:{w.alice.device_id}": "sig"}
                    },
                }
                for i in range(5)
            },
            "fallback_keys": {
                "signed_curve25519:FB1": {
                    "key": "ssdifffallback",
                    "fallback": True,
                    "signatures": {
                        w.alice.user_id: {f"ed25519:{w.alice.device_id}": "sig"}
                    },
                }
            },
        }
    )

    _upload_device_keys(w.users[STRANGER])

    # Direct messages. dm-erin stays an invite until a mutation accepts it.
    w.create("dm-bob", "alice", members=["bob"], direct=True)
    w.create("dm-carol", "carol", members=["alice"], direct=True)
    w.create("dm-dave", "alice", members=["dave"], direct=True, encrypted=True)
    w.create("dm-erin", "erin", invite=["alice"], direct=True)
    w.alice.account_data(
        "m.direct",
        {
            w.uid("bob"): [w.rooms["dm-bob"]],
            w.uid("carol"): [w.rooms["dm-carol"]],
            w.uid("dave"): [w.rooms["dm-dave"]],
        },
    )

    titles = [
        "Alpha",
        "Bravo",
        "Charlie",
        "Delta",
        "Echo",
        "Foxtrot",
        "Golf",
        "Hotel",
        "India",
        "Juliet",
        "Kilo",
        "Lima",
    ]
    others = USERS[1:]
    for i, title in enumerate(titles, 1):
        creator = others[i % len(others)]
        members = [u for u in others[: 1 + i % 4] if u != creator] + ["alice"]
        w.create(
            f"g{i:02}",
            creator,
            members=members,
            title=f"{title} Team",
            topic=f"Topic of {title}" if i % 3 == 0 else None,
            avatar=i % 4 == 0,
        )

    # Rooms with no name: the room list shows them by their heroes.
    w.create("u1", "bob", members=["alice", "carol"])
    w.create("u2", "alice", members=["bob", "carol", "dave", "erin", "frank", "grace"])
    w.create("u3", "bob", members=["alice"])
    w.create("u4", "alice")
    w.create("al1", "carol", members=["alice"], alias="ssdiff-alias-room")

    w.create("sp", "alice", members=["bob"], title="Main Space", space=True)
    for i in (1, 2, 3):
        child = f"sc{i}"
        w.create(child, "alice", members=["bob"], title=f"Space Child {i}")
        w.state(
            "sp", "alice", "m.space.child", w.rooms[child], {"via": [w.server_name]}
        )
        w.state(
            child,
            "alice",
            "m.space.parent",
            w.rooms["sp"],
            {"via": [w.server_name], "canonical": True},
        )

    for i in range(1, 6):
        title = f"Secret {i}" if i <= 3 else None
        w.create(
            f"e{i}",
            others[i % len(others)],
            members=["alice", "bob"],
            title=title,
            encrypted=True,
        )

    w.create("inv-accept", "bob", invite=["alice"], title="Invite To Accept")
    w.create(
        "inv-reject",
        "carol",
        invite=["alice"],
        title="Invite To Reject",
        topic="Say no",
    )
    w.create("inv-stay", "frank", invite=["alice"], title="Pending Invite", avatar=True)

    w.create("left1", "bob", members=["alice"], title="Left Early")
    w.create("left2", "carol", members=["alice"], title="Leave Later")
    w.create("pub", "grace", title="Public Lobby", public=True, alias="ssdiff-lobby")
    w.create("upg", "alice", members=["bob"], title="Upgrade Me")
    for i in range(1, 15):
        w.create(f"b{i:02}", "bob", members=["alice"], title=f"Bulk {i:02}")

    # History: a first message everywhere, then a last message in a shuffled
    # order, so that recency is not creation order.
    joined = [
        n for n in w.rooms if not n.startswith(("inv-", "dm-erin", "pub", "left1"))
    ]
    for name in joined:
        if name in ("u4",):
            continue
        sender = (
            "alice"
            if name in ("u2", "dm-dave", "sp", "upg") or name.startswith("sc")
            else _member(w, name)
        )
        if name.startswith("e") or name == "dm-dave":
            w.enc(name, sender, f"first {name}")
        else:
            w.msg(name, sender, f"first {name}")
    w.msg("left1", "bob", "first left1")
    w.alice.leave(w.rooms["left1"])

    order = [n for n in joined if n != "u4"]
    rng.shuffle(order)
    for name in order:
        sender = _member(w, name)
        if name.startswith("e") or name == "dm-dave":
            w.enc(name, sender if name != "dm-dave" else "dave", f"last {name}")
        elif name == "g02":
            w.msg(name, sender, f"last {name} Alice look", mention=["alice"])
        else:
            w.msg(name, sender, f"last {name}")
    world.seed_order = order

    # Alice has read g01 and sc1; the rest are unread.
    w.alice.receipt(w.rooms["g01"], w.last_event["g01"])
    w.alice.receipt(w.rooms["sc1"], w.last_event["sc1"])
    w.alice.room_account_data(
        w.rooms["g01"], "m.tag", {"tags": {"m.favourite": {"order": 0.5}}}
    )
    w.alice.room_account_data(w.rooms["b14"], "m.tag", {"tags": {"m.lowpriority": {}}})

    # A room version for the upgrade step that both servers can move to.
    caps = w.alice.capabilities().get("capabilities", {}).get("m.room_versions", {})
    world.room_versions = caps


def _member(w: World, name: str) -> str:
    """A member other than Alice when there is one, for unread counts."""
    preferred = {
        "dm-bob": "bob",
        "dm-carol": "carol",
        "dm-dave": "dave",
        "u1": "carol",
        "u2": "erin",
        "u3": "bob",
        "al1": "carol",
        "sp": "bob",
        "upg": "bob",
        "left2": "carol",
    }
    if name in preferred:
        return preferred[name]
    if name.startswith(("sc", "b")):
        return "bob"
    if name.startswith("e"):
        return "bob"
    if name.startswith("g"):
        # The creator is always a member; see seed().
        return _creator_of(w, name)
    return "alice"


# --- the steps ---------------------------------------------------------------
#
# A step is: what changes on the server (applied to both, the same way), then
# what the client does (an Element X sync action). `ops` is a function of the
# World so that each server's IDs are used.


class Step:
    def __init__(
        self, name: str, about: str, ops=None, action: str = "sync", rooms=None
    ):
        self.name = name
        self.about = about
        self.ops = ops or (lambda w: None)
        self.action = action  # sync | subscribe | recover | restart | retry | concurrent | server-restart
        self.rooms = rooms or []  # for subscribe: scenario room names


def _upgrade(w: World):
    versions = getattr(w, "room_versions", {}) or {}
    available = versions.get("available") or {}
    w.upgrade_version = None
    for candidate in ("11", "10", "9"):
        if available.get(candidate) == "stable":
            w.upgrade_version = candidate
            break
    if w.upgrade_version is None:
        w.notes.append("upgrade: no stable room version 9-11 offered; step skipped")
        return
    new = w.alice.upgrade(w.rooms["upg"], w.upgrade_version)
    w.rooms["upg@new"] = new
    w.msg("upg@new", "alice", "first message after upgrade")


def _churn(w: World):
    # Carol created g02 and invites Frank, who joins; Bob leaves g04.
    w.users[_creator_of(w, "g02")].invite(w.rooms["g02"], w.uid("frank"))
    w.users["frank"].join(w.rooms["g02"])
    w.users["bob"].leave(w.rooms["g04"])


def _upload_device_keys(user: User):
    user.keys_upload(
        {
            "device_keys": {
                "user_id": user.user_id,
                "device_id": user.device_id,
                "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                "keys": {
                    f"curve25519:{user.device_id}": "ssdiffcurve",
                    f"ed25519:{user.device_id}": "ssdiffed",
                },
                "signatures": {
                    user.user_id: {f"ed25519:{user.device_id}": "ssdiffsig"}
                },
            }
        }
    )


def _retry_ops(w: World):
    # A room new to the connection and a change to a known one, so that the
    # answer the client never sees carries both.
    w.create("inv-new", STRANGER, invite=["alice"], title="Invite While Lost")
    w.msg("b08", "bob", "sent while the answer was lost")


def _keys_and_to_device(w: World):
    w.enc("e1", "bob", "bob encrypted in e1")
    w.users["bob"].send_to_device(
        "m.room_key_request",
        {
            w.alice.user_id: {
                w.alice.device_id: {
                    "action": "request_cancellation",
                    "request_id": "ssdiff1",
                    "requesting_device_id": "BOBDEV",
                }
            }
        },
    )
    bob = w.users["bob"]
    bob.keys_upload(
        {
            "device_keys": {
                "user_id": bob.user_id,
                "device_id": bob.device_id,
                "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                "keys": {
                    f"curve25519:{bob.device_id}": "bobcurve",
                    f"ed25519:{bob.device_id}": "bobed",
                },
                "signatures": {bob.user_id: {f"ed25519:{bob.device_id}": "bobsig"}},
            }
        }
    )


def _burst(w: World):
    for i in range(25):
        w.msg("g01", "bob", f"burst g01 {i:02}")


def _new_dm(w: World):
    w.create("dm-grace", "grace", invite=["alice"], direct=True)
    w.msg("dm-grace", "grace", "hi alice from grace")


def _accept_dm(w: World):
    w.alice.join(w.rooms["dm-grace"])
    w.alice.account_data(
        "m.direct",
        {
            w.uid("bob"): [w.rooms["dm-bob"]],
            w.uid("carol"): [w.rooms["dm-carol"]],
            w.uid("dave"): [w.rooms["dm-dave"]],
            w.uid("grace"): [w.rooms["dm-grace"]],
        },
    )


def steps(seed_order: list[str]) -> list[Step]:
    oldest = seed_order[0]
    return [
        Step(
            "initial",
            "cold start: no pos, selective 0..19, then growing to the full list",
        ),
        Step(
            "bump-oldest",
            f"bob writes in {oldest}, the least recent room, which moves it to the top",
            lambda w: w.msg(
                oldest,
                _member(w, oldest) if _member(w, oldest) != "alice" else "bob",
                f"bump {oldest}",
            ),
        ),
        Step(
            "rename",
            "g03's creator renames it (a state event, not a message)",
            lambda w: w.state(
                "g03",
                _creator_of(w, "g03"),
                "m.room.name",
                "",
                {"name": "Gamma Renamed"},
            ),
        ),
        Step(
            "mention",
            "carol mentions alice in u1, a room with no name",
            lambda w: w.msg("u1", "carol", "u1 hey Alice", mention=["alice"]),
        ),
        Step(
            "accept-invite",
            "alice joins inv-accept and bob says hello",
            lambda w: (
                w.alice.join(w.rooms["inv-accept"]),
                w.msg("inv-accept", "bob", "welcome alice"),
            ),
        ),
        Step(
            "reject-invite",
            "alice rejects inv-reject",
            lambda w: w.alice.leave(w.rooms["inv-reject"]),
        ),
        Step(
            "typing-receipt",
            "bob types in dm-bob and sends a read receipt there",
            lambda w: (
                w.users["bob"].typing(w.rooms["dm-bob"], True),
                w.users["bob"].receipt(w.rooms["dm-bob"], w.last_event["dm-bob"]),
            ),
        ),
        Step(
            "typing-stop",
            "bob stops typing in dm-bob",
            lambda w: w.users["bob"].typing(w.rooms["dm-bob"], False),
        ),
        Step(
            "account-data",
            "alice changes global and room account data",
            lambda w: (
                w.alice.account_data("org.ssdiff.setting", {"v": 1}),
                w.alice.room_account_data(
                    w.rooms["g04"], "m.tag", {"tags": {"m.favourite": {"order": 0.1}}}
                ),
            ),
        ),
        Step(
            "new-dm-invite",
            "grace starts a DM with alice (an invite with is_direct)",
            _new_dm,
        ),
        Step("accept-dm", "alice joins grace's DM and updates m.direct", _accept_dm),
        Step("leave", "alice leaves left2", lambda w: w.alice.leave(w.rooms["left2"])),
        Step(
            "join-public",
            "alice joins the public room and grace speaks",
            lambda w: (
                w.alice.join(w.rooms["pub"]),
                w.msg("pub", "grace", "lobby hello"),
            ),
        ),
        Step("membership-churn", "frank joins g02 and bob leaves g04", _churn),
        # The spec's device_lists.changed covers users who "now share an
        # encrypted room": e1 is encrypted, pub (which Alice also shares
        # with Henry after this) is not.
        Step(
            "stranger-joins",
            "henry, who shared no room with alice, joins the encrypted room e1",
            lambda w: (
                w.users["bob"].invite(w.rooms["e1"], w.uid(STRANGER)),
                w.users[STRANGER].join(w.rooms["e1"]),
            ),
        ),
        Step(
            "kicked",
            "bob kicks alice from b13",
            lambda w: w.users["bob"].call(
                "POST",
                f"/_matrix/client/v3/rooms/{quote(w.rooms['b13'])}/kick",
                {"user_id": w.alice.user_id, "reason": "ssdiff"},
            ),
        ),
        Step(
            "topic-avatar",
            "topic change in g05, avatar change in g06",
            lambda w: (
                w.state(
                    "g05",
                    _creator_of(w, "g05"),
                    "m.room.topic",
                    "",
                    {"topic": "New topic"},
                ),
                w.state(
                    "g06",
                    _creator_of(w, "g06"),
                    "m.room.avatar",
                    "",
                    {"url": AVATAR + "2"},
                ),
            ),
        ),
        Step(
            "e2ee",
            "an encrypted message, a to-device message and a device key change",
            _keys_and_to_device,
        ),
        Step(
            "open-room",
            "alice opens g01 (a room subscription, timeline_limit 20)",
            action="subscribe",
            rooms=["g01"],
        ),
        Step("burst", "bob sends 25 messages to the open room g01", _burst),
        Step(
            "switch-room",
            "alice opens dm-carol instead of g01",
            action="subscribe",
            rooms=["dm-carol"],
        ),
        Step(
            "concurrent-cancel",
            "a long poll is abandoned while the server holds it: alice opens g02, "
            "the client re-sends with the same pos, then bob writes in b10",
            lambda w: w.msg("b10", "bob", "while a poll was abandoned"),
            action="concurrent",
            rooms=["g02"],
        ),
        Step("upgrade", "alice upgrades upg to a new room version", _upgrade),
        Step(
            "read",
            "alice reads u1, which clears its highlight",
            lambda w: w.alice.receipt(w.rooms["u1"], w.last_event["u1"]),
        ),
        Step(
            "pos-retry",
            "a long poll whose answer never reaches the client (a cancelled request), "
            "then the same request again with the same pos",
            _retry_ops,
            action="retry",
        ),
        Step(
            "recover",
            "the app comes back from the background: selective 0..19 with the old pos, then growing",
            lambda w: w.msg("b05", "bob", "while backgrounded"),
            action="recover",
        ),
        Step(
            "restart",
            "a cold start without pos (as after M_UNKNOWN_POS)",
            lambda w: w.msg("b06", "bob", "before restart"),
            action="restart",
        ),
        Step(
            "after-restart",
            "a message after the restart",
            lambda w: w.msg("g07", _member(w, "g07"), "after restart g07"),
        ),
        Step(
            "server-restart",
            "both servers restart; the client carries on with its pos "
            "(only with --restart-cmd)",
            lambda w: w.msg("g08", _member(w, "g08"), "after server restart"),
            action="server-restart",
        ),
    ]


def _creator_of(w: World, name: str) -> str:
    i = int(name[1:])
    return USERS[1:][i % 6]
