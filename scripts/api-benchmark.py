#!/usr/bin/env python3
"""Drive a Matrix homeserver over the Client-Server API and time it.

Nothing here is Spindle-specific. It speaks the published API and takes a
base URL, so the same script points at Synapse and Tuwunel unchanged -- which
is the whole point of #42: a comparison is only evidence if both sides ran the
same workload from the same driver.

Two things it does deliberately.

**It measures a curve, not a point.** Every operation is timed at several room
sizes, because the claims in SPEC 18.1 are all about how cost changes with
room size rather than what it costs once. A single number at trivial scale
would tell us almost nothing and would flatter whichever server has the lower
fixed overhead.

**It refuses to report a partial run.** A failed request that is quietly
dropped makes a server look faster, which is the most dangerous direction for
a benchmark to be wrong in. Any non-2xx response aborts the whole run.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import statistics
import sys
import time
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 30


class Failed(RuntimeError):
    """A request the benchmark cannot honestly continue past."""


class Client:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.token: str | None = None

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        url = f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            request.add_header("content-type", "application/json")
        if self.token:
            request.add_header("authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:300]
            raise Failed(f"{method} {path} -> {error.code}: {detail}") from error
        except urllib.error.URLError as error:
            raise Failed(f"{method} {path} -> {error.reason}") from error

    def register(self, username: str, password: str = "benchmark-password") -> str:
        """Register, hold the token, and return the full user ID."""
        body = self.request(
            "POST",
            "/_matrix/client/v3/register",
            {
                "username": username,
                "password": password,
                "auth": {"type": "m.login.dummy"},
            },
        )
        self.token = body["access_token"]
        return body["user_id"]


def timed(operation) -> float:
    """One sample, in nanoseconds."""
    start = time.perf_counter_ns()
    operation()
    return float(time.perf_counter_ns() - start)


def summarise(samples: list[float]) -> dict:
    """Median and spread, not mean.

    A homeserver's latency distribution has a tail -- a compaction, a lock, a
    GC pause -- and a mean lets one such sample move the headline number. The
    median is what a client usually waits; p99 is what makes people complain.
    Both are reported so neither can be quoted alone.
    """
    ordered = sorted(samples)
    return {
        "mean_ns": statistics.median(ordered),
        "lower_ns": ordered[0],
        "upper_ns": ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))],
        "samples": len(ordered),
    }


def fill_room(client: Client, room_id: str, count: int, offset: int) -> str | None:
    """Send `count` messages, returning the id of the first one sent.

    The first event's id is what makes `context_deep` possible: it is a handle
    on a point near the *start* of the room, which is where asking for state
    costs a DAG server something and costs us a snapshot read.
    """
    first = None
    for index in range(count):
        body = client.request(
            "PUT",
            f"/_matrix/client/v3/rooms/{room_id}/send/m.room.message/fill{offset + index}",
            {"msgtype": "m.text", "body": f"filler {offset + index}"},
        )
        if first is None:
            first = body.get("event_id")
    return first


def measure(base: str, sizes: list[int], samples: int, warmup: int) -> dict:
    """Time each operation at each room size, in one process, back to back.

    Same host, same run: #42's first methodology guardrail. A comparison across
    runs on different machines is noise, so every number a ratio is computed
    from is produced here, beside the others.
    """
    results: dict[str, dict] = {}
    stamp = time.time_ns()
    alice = Client(base)
    alice.register(f"alice{stamp}")

    room_id = alice.request("POST", "/_matrix/client/v3/createRoom", {})["room_id"]
    filled = 0
    oldest = None

    for size in sorted(sizes):
        first = fill_room(alice, room_id, size - filled, filled)
        if oldest is None:
            oldest = first
        filled = size

        counter = {"n": 0}

        def send() -> None:
            counter["n"] += 1
            alice.request(
                "PUT",
                f"/_matrix/client/v3/rooms/{room_id}/send/m.room.message"
                f"/probe{size}_{counter['n']}",
                {"msgtype": "m.text", "body": "probe"},
            )

        # Back-pagination. SPEC 10.4 calls this the endpoint that most visibly
        # misbehaves on DAG servers, so it is the one most worth a curve.
        def paginate() -> None:
            alice.request(
                "GET", f"/_matrix/client/v3/rooms/{room_id}/messages?limit=20"
            )

        def read_state() -> None:
            alice.request("GET", f"/_matrix/client/v3/rooms/{room_id}/state")

        # State at a point *deep* in history, which is the operation SPEC 18.1
        # is actually about.
        #
        # The rest of this sweep measures the head of the room, where every
        # server is fast because the answer is the one it just computed.
        # `/context` on the oldest event asks a different question: what was
        # the state back there? A server that stores state as a DAG has to
        # resolve or walk to answer it; a server that keeps a content-addressed
        # snapshot per event reads one. If the design's central claim is true,
        # this is the column where it shows.
        #
        # It is also the closest this driver can get to the claim. Fork depth
        # is unreachable over the client-server API -- a single server
        # linearizes everything it accepts, and forks arrive over federation --
        # so history depth is the dimension that can actually be varied here.
        def context_deep() -> None:
            alice.request(
                "GET",
                f"/_matrix/client/v3/rooms/{room_id}/context/{oldest}?limit=10",
            )

        operations = [
            ("send", send),
            ("messages_page", paginate),
            ("state", read_state),
        ]
        if oldest:
            operations.append(("context_deep", context_deep))

        for name, operation in operations:
            for _ in range(warmup):
                operation()
            results[f"{name}/{size}"] = summarise(
                [timed(operation) for _ in range(samples)]
            )

        # Joins go in their own room, filled to the same size.
        #
        # Not fussiness: every join leaves an `m.room.member` event in the
        # room's *state*, so measuring joins in the shared room made each size
        # inherit the previous size's joiners. `state` and `sync_initial` then
        # grew with the number of members the benchmark had itself added,
        # while the x-axis claimed to be varying the event count. The first run
        # of this script reported 1.74x and 4.36x growth that were partly the
        # driver's own doing.
        join_room = alice.request("POST", "/_matrix/client/v3/createRoom", {})[
            "room_id"
        ]
        fill_room(alice, join_room, size, 0)
        joiners = []
        for index in range(samples):
            joiner = Client(base)
            user_id = joiner.register(f"j{size}x{index}x{stamp}")
            # Registered and invited up front, outside the timed section, or
            # the number would be mostly registration.
            alice.request(
                "POST",
                f"/_matrix/client/v3/rooms/{join_room}/invite",
                {"user_id": user_id},
            )
            joiners.append(joiner)
        # An initial sync, by a user in exactly one room of this size.
        #
        # Alice will not do: she accumulates a room per size, and an initial
        # sync covers every joined room, so her number grows with how far
        # through the sweep we are rather than with the room. That confound
        # produced a 4.79x "result" on the first two runs of this script, which
        # was the driver measuring itself.
        observer = Client(base)
        observer_id = observer.register(f"obs{size}x{stamp}")
        alice.request(
            "POST",
            f"/_matrix/client/v3/rooms/{join_room}/invite",
            {"user_id": observer_id},
        )
        observer.request(
            "POST", f"/_matrix/client/v3/rooms/{join_room}/join", {}
        )

        def sync_initial() -> None:
            observer.request("GET", "/_matrix/client/v3/sync")

        for _ in range(warmup):
            sync_initial()
        results[f"sync_initial/{size}"] = summarise(
            [timed(sync_initial) for _ in range(samples)]
        )

        results[f"join/{size}"] = summarise(
            [
                timed(
                    lambda joiner=joiner: joiner.request(
                        "POST", f"/_matrix/client/v3/rooms/{join_room}/join", {}
                    )
                )
                for joiner in joiners
            ]
        )

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base_url", help="e.g. http://127.0.0.1:8448")
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument(
        "--server",
        required=True,
        help="which homeserver this is (spindle, synapse, tuwunel) -- recorded "
        "in the results so a ratio can name both sides",
    )
    parser.add_argument(
        "--sizes",
        default="10,100,1000",
        help="room sizes, in events, to measure at (default: 10,100,1000)",
    )
    parser.add_argument("--samples", type=int, default=25)
    parser.add_argument("--warmup", type=int, default=5)
    arguments = parser.parse_args()

    sizes = [int(size) for size in arguments.sizes.split(",") if size]
    if not sizes:
        parser.error("--sizes needs at least one room size")

    try:
        benchmarks = measure(
            arguments.base_url, sizes, arguments.samples, arguments.warmup
        )
    except Failed as error:
        # Loudly, and with nothing written. A run that drops failures and
        # reports the rest makes a broken server look like a fast one.
        print(f"api-benchmark: {error}", file=sys.stderr)
        print("no results written: the run did not complete", file=sys.stderr)
        return 1

    document = {
        "server": arguments.server,
        "base_url": arguments.base_url,
        "sizes": sizes,
        "samples": arguments.samples,
        "benchmarks": benchmarks,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(document, indent=2, sort_keys=True))
    print(
        f"api-benchmark: {len(benchmarks)} measurements against "
        f"{arguments.server} at {arguments.base_url} -> {arguments.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
