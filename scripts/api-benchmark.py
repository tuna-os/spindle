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

# How `register` satisfies user-interactive auth. Overridden by
# --registration-token, because the servers this driver must treat equally do
# not agree: Synapse and Spindle take m.login.dummy on an open server, while
# continuwuity refuses open registration outright and gates on a token. The
# driver adapting is what keeps the workload identical past the front door.
REGISTRATION_AUTH: dict = {"type": "m.login.dummy"}
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
            refusal = Failed(f"{method} {path} -> {error.code}: {detail}")
            try:
                refusal.body = json.loads(detail)
            except json.JSONDecodeError:
                refusal.body = None
            raise refusal from error
        except urllib.error.URLError as error:
            raise Failed(f"{method} {path} -> {error.reason}") from error

    def register(self, username: str, password: str = "benchmark-password") -> str:
        """Register through the UIA dance, hold the token, return the user ID.

        The first request carries no auth: a conformant server answers 401
        with the flows and a session, and the retry cites that session. A
        server that skips the challenge and registers outright (some do on
        an open server) is accepted as-is — the driver measures homeservers,
        it does not referee their UIA strictness.
        """
        request = {"username": username, "password": password}
        try:
            body = self.request("POST", "/_matrix/client/v3/register", request)
        except Failed as refusal:
            challenge = getattr(refusal, "body", None)
            session = (challenge or {}).get("session") if isinstance(challenge, dict) else None
            auth = dict(REGISTRATION_AUTH)
            if session:
                auth["session"] = session
            request["auth"] = auth
            body = self.request("POST", "/_matrix/client/v3/register", request)
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
                "GET", f"/_matrix/client/v3/rooms/{room_id}/messages?limit=20&dir=b"
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

        # The same question through the sliding window (MSC4186): the visible
        # slice of the room list, not the whole account. This is the endpoint
        # Element X actually calls where classic clients call /sync, so the
        # pair (sync_initial, sliding_window) is the before/after of the
        # room-list story. Skipped without complaint on a server that has not
        # implemented it -- Synapse without the feature flag 404s, and a
        # missing column is honest where a fabricated one is not.
        def sliding_window() -> None:
            observer.request(
                "POST",
                "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
                {
                    "lists": {
                        "main": {
                            "ranges": [[0, 10]],
                            "required_state": [["m.room.name", ""]],
                            "timeline_limit": 3,
                        }
                    }
                },
            )

        # Incremental sync: the request a running client actually spends its
        # life making. Every sitting before this one measured only the
        # *initial* sync -- the request a client makes once -- which left the
        # whole steady-state path unmeasured. That gap hid a real fix and let
        # a claim about it go out overstated (see #175): the server
        # short-circuits an incremental sync for a room with nothing new, so
        # work that looked like it ran "on every sync" only ran on syncs that
        # carried an event. The two cases are therefore measured separately,
        # because they take different paths.
        cursor = {
            "since": observer.request("GET", "/_matrix/client/v3/sync")["next_batch"]
        }
        chatter = {"count": 0}

        def sync_poll() -> None:
            """Nothing new. The most common request a homeserver serves."""
            observer.request(
                "GET",
                f"/_matrix/client/v3/sync?since={cursor['since']}&timeout=0",
            )

        def say_something() -> None:
            """Outside the timed section: give the next sync one event."""
            chatter["count"] += 1
            alice.request(
                "PUT",
                f"/_matrix/client/v3/rooms/{join_room}/send/m.room.message"
                f"/tick{size}_{chatter['count']}",
                {"msgtype": "m.text", "body": "tick"},
            )

        def sync_delta() -> None:
            """One event waiting. Advances the cursor, so every sample is a
            fresh one-event delta rather than the same backlog re-delivered."""
            body = observer.request(
                "GET",
                f"/_matrix/client/v3/sync?since={cursor['since']}&timeout=0",
            )
            cursor["since"] = body["next_batch"]

        sliding_supported = True
        try:
            sliding_window()
        except Failed:
            sliding_supported = False

        for _ in range(warmup):
            sync_initial()
        results[f"sync_initial/{size}"] = summarise(
            [timed(sync_initial) for _ in range(samples)]
        )

        for _ in range(warmup):
            sync_poll()
        results[f"sync_poll/{size}"] = summarise(
            [timed(sync_poll) for _ in range(samples)]
        )

        for _ in range(warmup):
            say_something()
            sync_delta()
        delta_samples = []
        for _ in range(samples):
            say_something()
            delta_samples.append(timed(sync_delta))
        results[f"sync_delta/{size}"] = summarise(delta_samples)
        if sliding_supported:
            for _ in range(warmup):
                sliding_window()
            results[f"sliding_window/{size}"] = summarise(
                [timed(sliding_window) for _ in range(samples)]
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


def measure_members(base: str, sizes: list[int], samples: int, warmup: int) -> dict:
    """Time the room-list reads in rooms of N *joined members*.

    `measure` varies how many events a room holds and holds membership at two,
    which is a real dimension but only one of them. Every endpoint here is
    answered out of room *state*, and the member list is the part of state that
    grows without bound in the rooms people complain about. A sweep that never
    varies it cannot see a cost that scales with it -- and did not: the
    sliding-window read grew linearly with membership while this driver
    reported it flat, because every room it measured had two members in it.

    Same operations, same request shapes, different axis. Written to its own
    document because the x-axis means something else here, and a chart that
    silently mixes 800 members with 800 events is worse than no chart.
    """
    results: dict[str, dict] = {}
    stamp = time.time_ns()
    alice = Client(base)
    alice.register(f"alice{stamp}")

    for size in sorted(sizes):
        room_id = alice.request("POST", "/_matrix/client/v3/createRoom", {})["room_id"]
        # A fresh room per size, for the reason `measure` learned the hard way:
        # a shared room makes each size inherit the previous size's members, so
        # the x-axis stops describing the thing being varied.
        for index in range(size):
            member = Client(base)
            user_id = member.register(f"m{size}x{index}x{stamp}")
            alice.request(
                "POST",
                f"/_matrix/client/v3/rooms/{room_id}/invite",
                {"user_id": user_id},
            )
            member.request("POST", f"/_matrix/client/v3/rooms/{room_id}/join", {})

        # The reader is a member like any other, and not Alice: Alice is in
        # every room this sweep has built so far, and an initial sync covers
        # all of them.
        observer = Client(base)
        observer_id = observer.register(f"obs{size}x{stamp}")
        alice.request(
            "POST",
            f"/_matrix/client/v3/rooms/{room_id}/invite",
            {"user_id": observer_id},
        )
        observer.request("POST", f"/_matrix/client/v3/rooms/{room_id}/join", {})

        def sliding_window() -> None:
            observer.request(
                "POST",
                "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
                {
                    "lists": {
                        "main": {
                            "ranges": [[0, 10]],
                            "required_state": [["m.room.name", ""]],
                            "timeline_limit": 3,
                        }
                    }
                },
            )

        def sync_initial() -> None:
            observer.request("GET", "/_matrix/client/v3/sync")

        def read_state(room_id: str = room_id) -> None:
            observer.request("GET", f"/_matrix/client/v3/rooms/{room_id}/state")

        operations = [("sync_initial", sync_initial), ("state", read_state)]
        try:
            sliding_window()
        except Failed:
            pass  # A server without MSC4186 gets a missing column, not a fake one.
        else:
            operations.insert(0, ("sliding_window", sliding_window))

        for name, operation in operations:
            for _ in range(warmup):
                operation()
            results[f"{name}/{size}"] = summarise(
                [timed(operation) for _ in range(samples)]
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
    parser.add_argument(
        "--registration-token",
        help="satisfy m.login.registration_token instead of m.login.dummy",
    )
    parser.add_argument(
        "--dimension",
        choices=("events", "members"),
        default="events",
        help="what --sizes counts: events in the room (default), or joined "
        "members in it. Two different axes, so two different runs and two "
        "different output files -- never one chart with both on it.",
    )
    parser.add_argument(
        "--round",
        type=int,
        default=1,
        help="which round of a repeated sitting this is, recorded in the "
        "results. One round cannot separate a real difference from this "
        "host's run-to-run variance (#171), so a sitting repeats and the "
        "renderer calls a cell only when the rounds separate.",
    )
    parser.add_argument("--samples", type=int, default=25)
    parser.add_argument("--warmup", type=int, default=5)
    arguments = parser.parse_args()
    if arguments.registration_token:
        global REGISTRATION_AUTH
        REGISTRATION_AUTH = {
            "type": "m.login.registration_token",
            "token": arguments.registration_token,
        }

    sizes = [int(size) for size in arguments.sizes.split(",") if size]
    if not sizes:
        parser.error("--sizes needs at least one room size")

    driver = measure if arguments.dimension == "events" else measure_members
    try:
        benchmarks = driver(
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
        "dimension": arguments.dimension,
        "round": arguments.round,
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
