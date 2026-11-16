"""The request bodies Element X sends, as matrix-rust-sdk builds them.

Sources, at matrix-org/matrix-rust-sdk `main` (read November 2026):

- crates/matrix-sdk-ui/src/room_list_service/mod.rs: the `room-list`
  connection, list `all_rooms`, DEFAULT_REQUIRED_STATE, timeline_limit 1,
  filters `{is_invite: None}` (which ruma serializes as `{}`), and the
  account_data, receipts (rooms `*`), typing and profiles extensions.
  Subscriptions add m.room.pinned_events and use timeline_limit 20.
- crates/matrix-sdk-ui/src/room_list_service/state.rs: the state machine.
  Init and SettingUp send a selective range 0..=19 with timeout 0, Running
  switches to a growing range in batches of 100 and long-polls only when
  the list is fully loaded. After the sync stops (app in the background,
  an error), Recovering puts the selective 0..=19 back, keeps `pos`, and
  grows again.
- crates/matrix-sdk/src/sliding_sync/list/request_generator.rs: how the
  growing range follows the list's `count`.
- crates/matrix-sdk-ui/src/encryption_sync_service.rs: the `encryption`
  connection: no lists, to_device (with `since`) and e2ee.

matrix-rust-sdk does not send `include_heroes`: ruma's MSC4186 request type
has no such field, and both servers send heroes without being asked.
The profiles extension is in the SDK but in neither server; it is off here
unless `profiles=True`, so that an unknown extension is not the first
thing the comparison sees.
"""

from __future__ import annotations

import copy

DEFAULT_REQUIRED_STATE = [
    ["m.room.name", ""],
    ["m.room.encryption", ""],
    ["m.room.member", "$LAZY"],
    ["m.room.member", "$ME"],
    ["m.room.topic", ""],
    ["m.room.avatar", ""],
    ["m.room.canonical_alias", ""],
    ["m.room.power_levels", ""],
    ["org.matrix.msc3401.call.member", "*"],
    ["m.room.join_rules", ""],
    ["m.room.tombstone", ""],
    ["m.room.create", ""],
    ["m.room.history_visibility", ""],
    ["io.element.functional_members", ""],
    ["m.space.parent", "*"],
    ["m.space.child", "*"],
    ["org.matrix.msc3672.beacon_info", "*"],
    # ruma serializes RoomRetention by its unstable name (MSC1763).
    ["org.matrix.msc1763.retention", ""],
]
SUBSCRIPTION_EXTRA_REQUIRED_STATE = [["m.room.pinned_events", ""]]
LIST_NAME = "all_rooms"
SELECTIVE_RANGE = (0, 19)
GROWING_BATCH = 100
LIST_TIMELINE_LIMIT = 1
SUBSCRIPTION_TIMELINE_LIMIT = 20


class RoomListConnection:
    """The `room-list` connection and its state machine.

    The harness calls `request()` for the next body and query, and
    `handle()` with each answer, as the SDK does around one sync.
    """

    def __init__(
        self,
        conn_id: str = "room-list",
        batch: int = GROWING_BATCH,
        profiles: bool = False,
    ):
        self.conn_id = conn_id
        self.batch = batch
        self.profiles = profiles
        self.reset()
        self.subscriptions: dict[str, dict] = {}

    def reset(self):
        """A fresh client: no pos, state Init."""
        self.pos = None
        self.state = "Init"
        self.mode = "selective"
        self.fetched = 0
        self.requested_end = None
        self.fully_loaded = False
        self.count = None

    # --- the parts of the state machine the harness drives ------------------

    def recover(self):
        """The sync stopped (backgrounded, network error) and starts again.

        Terminated{from: Running} -> Recovering: selective 0..=19, keep pos.
        """
        self.state = "Terminated"
        self.mode = "selective"

    def restart_without_pos(self):
        """M_UNKNOWN_POS, or a cold start with no cached pos."""
        self.reset()

    def subscribe(self, room_ids: list[str]):
        """Open a room. `set_room_subscriptions` replaces the set."""
        sub = {
            "required_state": copy.deepcopy(
                DEFAULT_REQUIRED_STATE + SUBSCRIPTION_EXTRA_REQUIRED_STATE
            ),
            "timeline_limit": SUBSCRIPTION_TIMELINE_LIMIT,
        }
        self.subscriptions = {rid: copy.deepcopy(sub) for rid in room_ids}

    # --- one sync --------------------------------------------------------------

    def _next_state(self):
        if self.state == "Init":
            return "SettingUp"
        if self.state in ("SettingUp", "Recovering"):
            if self.mode != "growing":
                self.mode = "growing"
                self.fetched = 0
                self.fully_loaded = False
            return "Running"
        if self.state == "Terminated":
            return "Recovering"
        return "Running"

    def _ranges(self):
        if self.mode == "selective":
            self.requested_end = None
            return [list(SELECTIVE_RANGE)]
        end = self.fetched + self.batch
        if self.count is not None:
            end = min(end, self.count)
        end = max(end - 1, 0)
        self.requested_end = end
        return [[0, end]]

    def _timeout(self, long_poll_ms: int):
        # The closure reads the state *before* this sync's transition.
        if self.state in ("Init", "SettingUp", "Recovering", "Terminated"):
            return 0
        if self.mode == "selective" or self.fully_loaded:
            return long_poll_ms
        return 0

    def request(self, long_poll_ms: int):
        self._pending_state = self._next_state()
        timeout = self._timeout(long_poll_ms)
        extensions = {
            "account_data": {"enabled": True},
            "receipts": {"enabled": True, "rooms": ["*"]},
            "typing": {"enabled": True},
        }
        if self.profiles:
            extensions["profiles"] = {"enabled": True}
        body = {
            "conn_id": self.conn_id,
            "lists": {
                LIST_NAME: {
                    "ranges": self._ranges(),
                    "required_state": copy.deepcopy(DEFAULT_REQUIRED_STATE),
                    "timeline_limit": LIST_TIMELINE_LIMIT,
                    "filters": {},
                }
            },
            "extensions": extensions,
        }
        if self.subscriptions:
            body["room_subscriptions"] = copy.deepcopy(self.subscriptions)
        return body, self.pos, timeout

    def handle(self, status: int, resp: dict):
        if status != 200:
            if isinstance(resp, dict) and resp.get("errcode") == "M_UNKNOWN_POS":
                # The SDK drops pos and starts over; the room list keeps the
                # rooms it has, but the state machine goes back to Init.
                self.reset()
            else:
                self.state = "Terminated"
                self.mode = "selective"
            return
        self.pos = resp.get("pos")
        self.state = self._pending_state
        lst = (resp.get("lists") or {}).get(LIST_NAME)
        if lst is not None and lst.get("count") is not None:
            self.count = lst["count"]
        if (
            self.mode == "growing"
            and self.requested_end is not None
            and self.count is not None
        ):
            maximum = max(self.count - 1, 0)
            if self.requested_end < maximum:
                self.fetched = self.requested_end + 1
                self.fully_loaded = False
            else:
                self.fetched = maximum
                self.fully_loaded = True
        elif self.mode == "selective":
            self.fully_loaded = True

    def settled(self) -> bool:
        """True once the SDK would long-poll: Running and fully loaded."""
        return self.state == "Running" and self.mode == "growing" and self.fully_loaded


class EncryptionConnection:
    """The `encryption` connection: to_device and e2ee, no lists."""

    def __init__(self, conn_id: str = "encryption"):
        self.conn_id = conn_id
        self.pos = None
        self.since = None

    def request(self, long_poll_ms: int):
        to_device = {"enabled": True}
        if self.since is not None:
            to_device["since"] = self.since
        body = {
            "conn_id": self.conn_id,
            "extensions": {"to_device": to_device, "e2ee": {"enabled": True}},
        }
        # No lists, so nothing lowers the SDK's poll timeout: even the first
        # request long-polls.
        return body, self.pos, long_poll_ms

    def handle(self, status: int, resp: dict):
        if status != 200:
            if isinstance(resp, dict) and resp.get("errcode") == "M_UNKNOWN_POS":
                self.pos = None
            return
        self.pos = resp.get("pos")
        td = (resp.get("extensions") or {}).get("to_device") or {}
        if td.get("next_batch") is not None:
            self.since = td["next_batch"]

    def settled(self) -> bool:
        return True
