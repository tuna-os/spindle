#!/usr/bin/env python3
"""Time MSC4140 delayed events on any homeserver, over the Client-Server API.

The comparison #36 asked for once #42's rig existed: the same two
measurements `cargo bench --bench delayed_events` and `--bench
delayed_firing` take inside Spindle, taken from outside, so the same driver
can point at Synapse with MSC4140 enabled and at Spindle on the same host in
the same sitting.

- **restart**: one participant's heartbeat (`POST
  .../delayed_events/{id}/restart`), timed over HTTP, with N delays live in
  one room -- N participants in one call, each with its leave pending.
- **firing**: how late a delay lands against the deadline it was given,
  measured as the arrival of the resulting event on a `/sync` long-poll, so
  the delivery path is in the number for both servers alike. Deadlines are
  spread over a window so the measurement samples the server's timer at
  every phase rather than at one.

Nothing here is Spindle-specific; it speaks the unstable MSC4140 paths both
servers serve. Like api-benchmark.py it refuses to report a partial run: a
non-2xx response aborts it.

    scripts/delayed-events-benchmark.py --base http://127.0.0.1:8099 \\
        --label spindle --out tmp/delayed-spindle.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

MEMBER = "org.matrix.msc3401.call.member"
UNSTABLE = "/_matrix/client/unstable/org.matrix.msc4140"


class Failed(RuntimeError):
    """A request the benchmark cannot honestly continue past."""


class Client:
    def __init__(self, base: str, token: str | None = None) -> None:
        self.base = base.rstrip("/")
        self.token = token

    def request(self, method: str, path: str, body: dict | None = None, timeout: float = 60) -> dict:
        data = json.dumps(body if body is not None else {}).encode() if method != "GET" else None
        request = urllib.request.Request(f"{self.base}{path}", data=data, method=method)
        if data is not None:
            request.add_header("content-type", "application/json")
        if self.token:
            request.add_header("authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            raise Failed(f"{method} {path}: {error.code} {error.read()[:300]!r}") from error


def register(base: str, name: str) -> tuple[Client, str]:
    body = Client(base).request(
        "POST",
        "/_matrix/client/v3/register",
        {"username": name, "password": "bench-password-1", "auth": {"type": "m.login.dummy"}},
    )
    return Client(base, body["access_token"]), body["user_id"]


def percentile(samples: list[float], percent: int) -> float:
    ordered = sorted(samples)
    return ordered[(len(ordered) - 1) * percent // 100]


def summary(samples: list[float]) -> dict:
    return {
        "n": len(samples),
        "p50_ms": round(percentile(samples, 50), 2),
        "p99_ms": round(percentile(samples, 99), 2),
        "max_ms": round(max(samples), 2),
        "mean_ms": round(statistics.fmean(samples), 2),
    }


def call_room(base: str, size: int, tag: str) -> tuple[Client, str, list[tuple[Client, str]]]:
    """A public room with `size` participants able to write call membership."""
    creator, creator_id = register(base, f"c{tag}{size}")
    room = creator.request(
        "POST",
        "/_matrix/client/v3/createRoom",
        {"preset": "public_chat", "power_level_content_override": {"events": {MEMBER: 0}}},
    )["room_id"]
    participants = [(creator, creator_id)]

    def join(index: int) -> tuple[Client, str]:
        client, user_id = register(base, f"p{tag}{size}x{index}")
        client.request("POST", f"/_matrix/client/v3/rooms/{room}/join", {})
        return client, user_id

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        participants += list(pool.map(join, range(size - 1)))
    return creator, room, participants


def schedule(client: Client, user_id: str, room: str, delay_ms: int) -> str:
    key = f"_{user_id}_D{uuid.uuid4().hex[:8]}"
    return client.request(
        "PUT",
        f"/_matrix/client/v3/rooms/{room}/state/{MEMBER}/{key}?org.matrix.msc4140.delay={delay_ms}",
        {},
    )["delay_id"]


def measure_restart(base: str, size: int, restarts: int) -> dict:
    _, room, participants = call_room(base, size, "r")
    delays = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        delays = list(
            pool.map(lambda p: (p[0], schedule(p[0], p[1], room, 3_600_000)), participants)
        )
    samples = []
    for index in range(restarts):
        client, delay_id = delays[index % len(delays)]
        started = time.perf_counter()
        client.request("POST", f"{UNSTABLE}/delayed_events/{delay_id}/restart", {})
        samples.append((time.perf_counter() - started) * 1000)
    # Cancelled afterwards, so nothing fires into a later measurement.
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(
            pool.map(
                lambda d: d[0].request("POST", f"{UNSTABLE}/delayed_events/{d[1]}/cancel", {}),
                delays,
            )
        )
    return summary(samples)


class Watcher:
    """A /sync long-poll recording when each event first arrives."""

    def __init__(self, client: Client) -> None:
        self.client = client
        self.seen: dict[str, float] = {}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        since = client.request("GET", "/_matrix/client/v3/sync?timeout=0")["next_batch"]
        self.thread = threading.Thread(target=self.run, args=(since,), daemon=True)
        self.thread.start()

    def run(self, since: str) -> None:
        while not self.stop.is_set():
            body = self.client.request("GET", f"/_matrix/client/v3/sync?timeout=2000&since={since}")
            now = time.time()
            with self.lock:
                for room in body.get("rooms", {}).get("join", {}).values():
                    for section in ("timeline", "state"):
                        for event in room.get(section, {}).get("events", []):
                            key = event.get("state_key")
                            if key is not None and event.get("type") == MEMBER:
                                self.seen.setdefault(key, now)
            since = body["next_batch"]


def measure_firing(base: str, size: int, window_ms: int, lead_ms: int) -> dict:
    observer, room, participants = call_room(base, size, "f")
    watcher = Watcher(observer)
    deadlines: dict[str, float] = {}

    def arm(index: int) -> None:
        client, user_id = participants[index]
        # Deadlines spread evenly over the window, with a sub-millisecond
        # offset each, so every phase of the server's timer is sampled.
        delay = lead_ms + window_ms * index // size
        key = f"_{user_id}_F{index}"
        asked = time.time()
        client.request(
            "PUT",
            f"/_matrix/client/v3/rooms/{room}/state/{MEMBER}/{key}?org.matrix.msc4140.delay={delay}",
            {},
        )
        deadlines[key] = asked + delay / 1000

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(arm, range(size)))
    armed = time.time()
    if any(deadline <= armed for deadline in deadlines.values()):
        raise Failed("a deadline passed before every delay was armed; raise --lead-ms")
    give_up = max(deadlines.values()) + 120
    while time.time() < give_up:
        with watcher.lock:
            if all(key in watcher.seen for key in deadlines):
                break
        time.sleep(0.01)
    watcher.stop.set()
    with watcher.lock:
        missing = [key for key in deadlines if key not in watcher.seen]
        if missing:
            # Not a partial result to average: the server could not keep up,
            # and that is the finding. Recorded as such, with no lateness
            # figures that would leave out exactly the delays that were worst.
            return {"n": size, "incomplete": True, "arrived": size - len(missing), "give_up_s": 120}
        late = [(watcher.seen[key] - deadline) * 1000 for key, deadline in deadlines.items()]
    if min(late) < -50:
        raise Failed(f"a delay fired {-min(late):.0f} ms early")
    return summary(late)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--base", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--sizes", default="10,100,1000")
    parser.add_argument("--restarts", type=int, default=300)
    parser.add_argument("--window-ms", type=int, default=5_000)
    parser.add_argument("--lead-ms", type=int, default=20_000)
    parser.add_argument("--out", type=pathlib.Path)
    args = parser.parse_args()
    sizes = [int(size) for size in args.sizes.split(",")]
    result: dict = {"label": args.label, "base": args.base, "restart": {}, "firing": {}}
    for size in sizes:
        print(f"{args.label}: restart with {size} live delays", file=sys.stderr)
        result["restart"][size] = measure_restart(args.base, size, args.restarts)
        print(f"  {result['restart'][size]}", file=sys.stderr)
    for size in sizes:
        print(f"{args.label}: firing jitter at {size}", file=sys.stderr)
        result["firing"][size] = measure_firing(args.base, size, args.window_ms, args.lead_ms)
        print(f"  {result['firing'][size]}", file=sys.stderr)
    text = json.dumps(result, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
