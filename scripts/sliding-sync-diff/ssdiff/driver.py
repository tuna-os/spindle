"""Drive both servers through the scenario, or through a recording.

Each server runs in its own thread, so a long poll on one does not hold up
the other; within a server, everything is in order. Every exchange is kept
in the sync-tap JSONL shape (plus `step` and `phase`), so the raw files can
be read by sync_tap_report.py as they are.
"""

from __future__ import annotations

import datetime as dt
import json
import shlex
import subprocess
import threading
import time
import traceback

from . import elementx, scenario
from .http import Server, User


class Recorder:
    def __init__(self, user: User):
        self.user = user
        self.exchanges: list[dict] = []
        self.seq = 0

    def sync(
        self,
        conn,
        step: str,
        phase: str,
        long_poll_ms: int,
        timeout_override=None,
        lost: bool = False,
    ):
        """One request. `lost`: the client never sees the answer (a request
        it cancelled), so the connection state does not move."""
        body, pos, timeout = conn.request(long_poll_ms)
        if timeout_override is not None and timeout:
            timeout = timeout_override
        query, status, resp, ms = self.user.sliding(body, pos, timeout)
        if lost:
            phase = "lost"
        else:
            conn.handle(status, resp)
        self.seq += 1
        self.exchanges.append(
            {
                "t": dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds"),
                "ms": round(ms, 1),
                "user": self.user.user_id,
                "device": self.user.device_id,
                "conn_id": body.get("conn_id") or "",
                "query": query,
                "request": body,
                "status": status,
                "response": resp,
                "seq": self.seq,
                "step": step,
                "phase": phase,
            }
        )
        return status, resp, ms


def _has_content(resp: dict) -> bool:
    """Whether an answer carried a change, not just the always-present keys.

    Synapse answers `"typing": {"rooms": {}}` and an e2ee block with key
    counts every time; neither is news.
    """
    if not isinstance(resp, dict):
        return False
    if resp.get("rooms"):
        return True
    ext = resp.get("extensions") or {}
    for name in ("account_data",):
        if any((ext.get(name) or {}).get(k) for k in ("global", "rooms")):
            return True
    for name in ("receipts", "typing"):
        if (ext.get(name) or {}).get("rooms"):
            return True
    dl = (ext.get("e2ee") or {}).get("device_lists") or {}
    if dl.get("changed") or dl.get("left"):
        return True
    return bool((ext.get("to_device") or {}).get("events"))


class ScenarioRun:
    """One server's run of the scenario."""

    def __init__(
        self,
        server: Server,
        long_poll_ms: int,
        drain_ms: int,
        enc_poll_ms: int,
        batch: int,
        profiles: bool,
        restart_cmd: str | None = None,
    ):
        self.server = server
        self.world = scenario.World(server)
        self.long_poll_ms = long_poll_ms
        self.drain_ms = drain_ms
        self.enc_poll_ms = enc_poll_ms
        self.room_list = elementx.RoomListConnection(batch=batch, profiles=profiles)
        self.encryption = elementx.EncryptionConnection()
        self.rec: Recorder | None = None
        self.timings: list[dict] = []
        self.error: str | None = None
        self.restart_cmd = restart_cmd

    def seed(self):
        scenario.seed(self.world)
        self.rec = Recorder(self.world.alice)

    def restart_server(self):
        cmd = self.restart_cmd.replace("{side}", self.server.label)
        subprocess.run(shlex.split(cmd), check=True, stdout=subprocess.DEVNULL)
        for _ in range(120):
            try:
                status, _, _ = self.server.raw(
                    "GET", "/_matrix/client/versions", timeout=2
                )
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.5)
        raise RuntimeError(f"{self.server.label} did not come back after a restart")

    def _concurrent(self, step: scenario.Step):
        """A long poll the client abandons while the server still holds it.

        Element X cancels the in-flight request when the room subscriptions
        change and sends a new one with the same pos at once. Here request A
        long-polls; B (new subscriptions, same pos) is sent while A waits;
        then the step's change lands, which wakes A. A's answer is lost; the
        client carries on from B, and its next poll must still bring the
        change.
        """
        rec = self.rec
        holder = {}

        def poll_a():
            body, pos, timeout = self.room_list.request(self.long_poll_ms)
            holder["a"] = (body, pos, self.world.alice.sliding(body, pos, timeout))

        thread = threading.Thread(target=poll_a)
        thread.start()
        time.sleep(0.3)
        self.room_list.subscribe([self.world.rooms[n] for n in step.rooms])
        rec.sync(self.room_list, step.name, "catch-up", self.long_poll_ms)
        time.sleep(0.2)
        step.ops(self.world)
        thread.join()
        body, _pos, (query, status, resp, ms) = holder["a"]
        rec.seq += 1
        rec.exchanges.append(
            {
                "t": dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds"),
                "ms": round(ms, 1),
                "user": rec.user.user_id,
                "device": rec.user.device_id,
                "conn_id": body.get("conn_id") or "",
                "query": query,
                "request": body,
                "status": status,
                "response": resp,
                "seq": rec.seq,
                "step": step.name,
                "phase": "lost",
            }
        )

    def run_step(self, step: scenario.Step):
        if step.action == "concurrent":
            self._concurrent(step)
        else:
            step.ops(self.world)
        if step.action == "subscribe":
            self.room_list.subscribe([self.world.rooms[n] for n in step.rooms])
        elif step.action == "recover":
            self.room_list.recover()
        elif step.action == "restart":
            self.room_list.restart_without_pos()
            self.encryption = elementx.EncryptionConnection()
        elif step.action == "server-restart":
            self.restart_server()
        elif step.action == "retry":
            # Element X cancels an in-flight request when, for example, the
            # room subscriptions change, and sends it again with the same
            # pos. The server may have answered the first one in full.
            self.rec.sync(
                self.room_list, step.name, "lost", self.long_poll_ms, lost=True
            )

        # Catch up the way the SDK does: timeout 0 until the list is fully
        # loaded, then one long poll; then more polls while answers carry
        # anything, which is how a change split over two answers is caught.
        # An error (M_UNKNOWN_POS after a server restart) sends the client
        # back to the start, and it catches up again at once.
        for _attempt in range(3):
            for _ in range(8):
                if self.room_list.settled():
                    break
                self.rec.sync(self.room_list, step.name, "catch-up", self.long_poll_ms)
            status, resp, ms = self.rec.sync(
                self.room_list, step.name, "long-poll", self.long_poll_ms
            )
            self.timings.append(
                {
                    "step": step.name,
                    "conn": "room-list",
                    "ms": ms,
                    "content": _has_content(resp),
                    "timeout": self.long_poll_ms,
                }
            )
            if status == 200:
                break
        for _ in range(3):
            if status != 200 or not _has_content(resp):
                break
            status, resp, ms = self.rec.sync(
                self.room_list,
                step.name,
                "drain",
                self.long_poll_ms,
                timeout_override=self.drain_ms,
            )

        for _attempt in range(3):
            status, resp, ms = self.rec.sync(
                self.encryption, step.name, "long-poll", self.enc_poll_ms
            )
            if status == 200:
                break
        for _ in range(2):
            if status != 200 or not _has_content(resp):
                break
            status, resp, ms = self.rec.sync(
                self.encryption,
                step.name,
                "drain",
                self.enc_poll_ms,
                timeout_override=self.drain_ms,
            )


def parallel(fns):
    """Run one function per server at once; re-raise the first failure."""
    errors = [None] * len(fns)

    def wrap(i, fn):
        try:
            fn()
        except Exception:  # noqa: BLE001 -- reported with its traceback below
            errors[i] = traceback.format_exc()

    threads = [threading.Thread(target=wrap, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


def run_scenario(runs: list[ScenarioRun], log=print, only_steps=None):
    errs = parallel([r.seed for r in runs])
    for run, err in zip(runs, errs):
        if err:
            raise RuntimeError(f"seeding {run.server.label} failed:\n{err}")
    order = runs[0].world.seed_order
    if any(r.world.seed_order != order for r in runs):
        raise RuntimeError("the two servers were seeded in different orders")
    plan = scenario.steps(order)
    if not runs[0].restart_cmd:
        plan = [s for s in plan if s.action != "server-restart"]
    if only_steps:
        plan = [s for s in plan if s.name in only_steps or s.name == "initial"]
    for step in plan:
        log(f"   step {step.name}: {step.about}")
        errs = parallel([lambda r=r, s=step: r.run_step(s) for r in runs])
        for run, err in zip(runs, errs):
            if err:
                run.error = f"step {step.name}: {err.strip().splitlines()[-1]}"
                log(f"   !! {run.server.label} failed at {step.name}:\n{err}")
        if any(errs):
            break
    return plan


# --- replay ------------------------------------------------------------------


class ReplayRun:
    """Replays recorded request bodies against one server.

    Only bodies are taken from the recording. Each recorded (user, device)
    becomes a device of Alice's, and each of its conn_ids a connection;
    `pos` and the to_device `since` are this server's own, and a recorded
    request without `pos` starts that connection over. Room IDs in the bodies (room subscriptions) are mapped
    onto scenario rooms in order of first sight, the same way on both
    servers.
    """

    def __init__(self, server: Server, max_timeout_ms: int):
        self.server = server
        self.world = scenario.World(server)
        self.max_timeout_ms = max_timeout_ms
        self.devices: dict = {}
        self.pos: dict = {}
        self.to_device_since: dict = {}
        self.exchanges: list[dict] = []
        self.room_map: dict[str, str] = {}
        self.seq = 0
        self.error = None

    def seed(self):
        scenario.seed(self.world)

    def _user_for(self, key) -> User:
        if key not in self.devices:
            n = len(self.devices) + 1
            self.devices[key] = self.server.login(
                scenario.OBSERVER, scenario.PASSWORD, f"REPLAY{n}"
            )
        return self.devices[key]

    def _map_rooms(self, body: dict) -> dict:
        targets = [rid for name, rid in sorted(self.world.rooms.items())]
        subs = body.get("room_subscriptions")
        if isinstance(subs, dict):
            mapped = {}
            for rid, cfg in subs.items():
                if rid not in self.room_map:
                    self.room_map[rid] = targets[len(self.room_map) % len(targets)]
                mapped[self.room_map[rid]] = cfg
            body["room_subscriptions"] = mapped
        return body

    def replay_one(self, entry: dict, step: str):
        key = (entry.get("user"), entry.get("device"), entry.get("conn_id") or "")
        # One replay device per recorded device; its connections stay apart
        # by conn_id, as they were.
        user = self._user_for(key[:2])
        body = json.loads(json.dumps(entry.get("request") or {}))
        body.pop("pos", None)
        body = self._map_rooms(body)
        # to_device's `since` is a token of the recorded server, like pos:
        # each server gets back its own.
        td = (body.get("extensions") or {}).get("to_device")
        if isinstance(td, dict) and "since" in td:
            if self.to_device_since.get(key) is not None:
                td["since"] = self.to_device_since[key]
            else:
                td.pop("since")
        recorded_pos = (entry.get("query") or {}).get("pos") or (
            entry.get("request") or {}
        ).get("pos")
        pos = self.pos.get(key) if recorded_pos is not None else None
        timeout = None
        raw_timeout = (entry.get("query") or {}).get("timeout")
        if raw_timeout is not None:
            timeout = min(int(raw_timeout), self.max_timeout_ms)
        query, status, resp, ms = user.sliding(body, pos, timeout)
        if status == 200:
            self.pos[key] = resp.get("pos")
            batch = ((resp.get("extensions") or {}).get("to_device") or {}).get(
                "next_batch"
            )
            if batch is not None:
                self.to_device_since[key] = batch
        elif isinstance(resp, dict) and resp.get("errcode") == "M_UNKNOWN_POS":
            self.pos.pop(key, None)
        self.seq += 1
        self.exchanges.append(
            {
                "t": dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds"),
                "ms": round(ms, 1),
                "user": user.user_id,
                "device": user.device_id,
                # Both servers see the recording's conn_id; the anomaly checks
                # key on (user, device, conn_id), and the device is per original.
                "conn_id": body.get("conn_id") or "",
                "query": query,
                "request": body,
                "status": status,
                "response": resp,
                "seq": self.seq,
                "step": step,
                "phase": "replay",
                "recorded_seq": entry.get("seq"),
            }
        )


def run_replay(
    runs: list[ReplayRun], entries: list[dict], mutate_every: int, log=print
):
    errs = parallel([r.seed for r in runs])
    for run, err in zip(runs, errs):
        if err:
            raise RuntimeError(f"seeding {run.server.label} failed:\n{err}")
    mutations = [
        s
        for s in scenario.steps(runs[0].world.seed_order)
        if s.action == "sync" and s.name != "initial"
    ]
    m = 0
    for i, entry in enumerate(entries):
        step = f"r{i + 1:04}"
        if mutate_every and i and i % mutate_every == 0 and m < len(mutations):
            mstep = mutations[m]
            m += 1
            log(f"   {step}: mutation {mstep.name}")
            errs = parallel([lambda r=r, s=mstep: s.ops(r.world) for r in runs])
            if any(errs):
                raise RuntimeError(f"mutation {mstep.name} failed: {errs}")
        errs = parallel([lambda r=r, e=entry, s=step: r.replay_one(e, s) for r in runs])
        if any(errs):
            raise RuntimeError(f"replay of recorded #{entry.get('seq')} failed: {errs}")
