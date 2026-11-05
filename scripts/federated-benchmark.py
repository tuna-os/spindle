#!/usr/bin/env python3
"""Parity line 3's three targeted cells, measured with a rival in the room.

#42's third line names five workloads the architecture targets. Two of them
(back-pagination, deep history) are client-server operations every sitting
measures. The other three need a second homeserver on the far side of a
federation link, or a rival beside Spindle on the same axis, and until #647
nothing measured them with anyone but Spindle in the seat:

- **Join a 10,000-member federated room** (`federated_join/<members>`). The
  cost is the handshake, not the joiner's client: `send_join` hands over
  state with ten thousand member events, and the joining server verifies,
  stores and serves it. The cell runs from the client's `POST /join` to
  the joining server serving the full membership through `/joined_members`.
  A server that answers the join early (MSC3706 partial state) is not
  credited for a membership it cannot yet serve; the moment `/join`
  returned is recorded beside the cell as `join_returned_ns`.
- **Federation catch-up after a partition** (`partition_catchup/<missed>`).
  A proxy refuses traffic both ways while the resident sends `missed`
  events; the proxy heals and the resident sends one marker. The cell runs
  from the resident's first connection to the subject after the heal to
  the subject serving every missed event and the marker through
  `/messages`. The wait between the heal and that connection is the
  resident's retry backoff -- the same resident for every subject, and in
  the Rust bench most of its 0.9--3.2 s spread -- so it is recorded beside
  the cell (`resident_retry_ns`, `heal_to_served_ns`) rather than in it.
- **Concurrent send** (`send_throughput/<clients>`). `api-benchmark.py
  --dimension concurrency`'s workload, unchanged: each client writes to its
  own room. The cell is wall time per send across the burst
  (1e9 / sends-per-second), so lower is better and a ratio is the
  throughput ratio; the per-request latency spread is kept beside it.

**The far side is held constant.** One Spindle, the *resident*, hosts every
federated room and is the sender in every partition, for every subject.
Only the subject -- Spindle, Synapse or Tuwunel -- changes, so a ratio
between subjects is a ratio between joiners and between catching-up
servers, not between pairs. Spindle is measured as a subject by the same
driver in the same round as its rivals; the in-process bench
(`cargo bench -p spindle-server --bench federated_timing`) is a different
instrument and is not compared against.

**Every federation link is TLS, terminated the same way for everyone.** Each
server listens on plain HTTP on loopback and is named `127.0.0.1:<front>`,
where `<front>` is this driver's TLS front: it terminates TLS with a
certificate from a CA made for the run, and forwards to the server. Synapse
and Tuwunel both document a reverse proxy in front of them as the
production shape (Tuwunel's release builds carry no TLS listener at all),
so every subject is reached the way its operators reach it, through the
same front. The front is also the partition: closed, it resets new
connections and aborts established ones, so pooled keep-alive flows cannot
sail through (the leak the Rust bench's proxy was written to prevent).

Every subject runs its production defaults, with the sitting's rate limits
lifted and its federation pointed at loopback. The resident alone carries a
rig setting: `retry_base_ms = 50`, as in the Rust bench, so a partition is
followed by a retry within a few seconds rather than a minute -- the same
for every subject, because the resident is the same.

One round starts every server cold, measures every subject in turn
(reversed on even rounds, so drift becomes spread rather than bias), and
writes `<group>.<server>.r<N>.json` beside the sittings that
`scripts/parity-gate.py` reads, with `<group>.sitting.json` as provenance.
A request that fails aborts the run with nothing written for it, the
driver's rule: a dropped failure makes a broken server look fast.

    scripts/federated-benchmark.py --group targeted-20261105 --rounds 3 \\
        --subject spindle --subject synapse --subject tuwunel

Needs `target/release/spindle`, Synapse in SYNAPSE_VENV, Tuwunel in
BENCH_BIN (`just bench-field`), `openssl`, and for Synapse on Postgres,
BENCH_PG_URL with `psql`.
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import importlib.util
import json
import os
import pathlib
import platform
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent

# The client-server driver every sitting uses: its client, its failure rule
# and its concurrency workload, so the throughput cell is the same workload
# the earlier Spindle-vs-Synapse figure came from.
_spec = importlib.util.spec_from_file_location("api_benchmark", HERE / "api-benchmark.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
Failed = api.Failed

# A 10,000-member join on a slow joiner is minutes, not the driver's 30 s.
api.TIMEOUT_SECONDS = 900

TOKEN = os.environ.get("BENCH_TOKEN", "benchtoken")
# How long a subject may take to serve the membership, or to catch up,
# before the run fails. Generous: the cell is the time, and a cap only
# exists so a wedged server ends the run instead of the job's deadline.
CONVERGE_SECONDS = 900
# Seeding joins in flight at once on the resident. Its room lock orders
# them anyway; this only overlaps the HTTP round trips.
SEED_WORKERS = 8
AS_TOKEN = "rig-seed-as-token"


# --- the TLS front, which is also the partition ----------------------------


class Front:
    """TLS in front of one server's plain-HTTP port, with a gate.

    Open, it terminates TLS and pumps bytes both ways. Closed, it resets new
    connections at accept and aborts every established flow, so a pooled
    keep-alive connection cannot carry traffic across the partition.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop, target: int, context) -> None:
        self.loop = loop
        self.target = target
        self.context = context
        self.open = True
        self.flows: set[asyncio.Task] = set()
        # When the first connection after the last heal was admitted: the
        # moment the far side's retry reached this server again.
        self.first_flow: int | None = None
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        self.port = listener.getsockname()[1]
        self.server = self._call(asyncio.start_server(self._accept, sock=listener))

    def _call(self, coroutine):
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result()

    async def _accept(self, reader, writer) -> None:
        if not self.open:
            reset(writer)
            return
        if self.first_flow is None:
            self.first_flow = time.perf_counter_ns()
        task = asyncio.current_task()
        self.flows.add(task)
        upstream = None
        try:
            if self.context is not None:
                await writer.start_tls(self.context)
            up_reader, upstream = await asyncio.open_connection("127.0.0.1", self.target)
            pumps = [
                asyncio.ensure_future(pump(reader, upstream)),
                asyncio.ensure_future(pump(up_reader, writer)),
            ]
            try:
                await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for each in pumps:
                    each.cancel()
        except (OSError, ssl.SSLError, asyncio.CancelledError):
            pass
        finally:
            self.flows.discard(task)
            reset(writer)
            if upstream is not None:
                reset(upstream)

    async def _set(self, open_: bool) -> None:
        self.open = open_
        if open_:
            self.first_flow = None
        else:
            for task in list(self.flows):
                task.cancel()

    def set(self, open_: bool) -> None:
        self._call(self._set(open_))

    def close(self) -> None:
        self.loop.call_soon_threadsafe(self.server.close)


async def pump(reader, writer) -> None:
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()


def reset(writer) -> None:
    """Close with a reset, not a FIN: the peer learns at once that the link
    is gone, so the partition measures recovery rather than timeouts."""
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError:
            pass
    writer.transport.abort()


def front_loop() -> asyncio.AbstractEventLoop:
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True, name="fronts").start()
    return loop


def make_ca(directory: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    """A CA made for this run, and one leaf for 127.0.0.1 it signs.

    Every subject verifies the front's certificate against this CA, so TLS
    is not switched off anywhere -- only rooted somewhere private.
    """
    ca_key, ca = directory / "ca.key", directory / "ca.pem"
    key, csr, cert = directory / "front.key", directory / "front.csr", directory / "front.pem"
    ext = directory / "front.ext"
    quiet = {"check": True, "capture_output": True}
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-days", "2", "-subj", "/CN=spindle federated benchmark CA",
         "-keyout", ca_key, "-out", ca,
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign"], **quiet)
    subprocess.run(
        ["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-subj", "/CN=127.0.0.1", "-keyout", key, "-out", csr], **quiet)
    ext.write_text(
        "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
        "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
        # Strict verifiers (Python 3.13's default, among others) refuse a
        # leaf without these.
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
    )
    subprocess.run(
        ["openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
         "-CAcreateserial", "-days", "2", "-extfile", ext, "-out", cert], **quiet)
    return ca, cert, key


# --- the servers -----------------------------------------------------------


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Server:
    """One homeserver: its process, its client port and its federation name."""

    def __init__(self, kind: str, work: pathlib.Path, front: Front, port: int) -> None:
        self.kind = kind
        self.work = work
        self.front = front
        self.port = port
        self.name = f"127.0.0.1:{front.port}"
        self.base = f"http://127.0.0.1:{port}"
        self.process: subprocess.Popen | None = None

    def launch(self, command: list, env: dict | None = None, cwd=None) -> None:
        log = open(self.work / "run.log", "wb")  # noqa: SIM115 -- the child holds it
        self.process = subprocess.Popen(
            [str(part) for part in command], stdout=log, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, env={**os.environ, **(env or {})}, cwd=cwd,
            start_new_session=True,
        )
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise Failed(f"{self.kind} exited at startup; see {self.work / 'run.log'}")
            try:
                api.Client(self.base).request("GET", "/_matrix/client/versions")
                return
            except Failed:
                time.sleep(0.5)
        raise Failed(f"{self.kind} on :{self.port} did not come up")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            os.killpg(self.process.pid, 15)
            try:
                self.process.wait(30)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, 9)
        self.front.close()

    def client(self, token: str | None = None) -> api.Client:
        client = api.Client(self.base)
        client.token = token
        return client

    def register(self, username: str) -> api.Client:
        """A fresh account on this server, by the door the sitting uses."""
        api.REGISTRATION_AUTH = (
            {"type": "m.login.registration_token", "token": TOKEN}
            if self.kind == "tuwunel"
            else {"type": "m.login.dummy"}
        )
        client = api.Client(self.base)
        client.register(username)
        return client


def spindle_config(server: Server, resident: bool) -> pathlib.Path:
    lines = [
        "[server]",
        f'name = "{server.name}"',
        f'bind = "127.0.0.1:{server.port}"',
        "[storage]",
        f'path = "{server.work / "data"}"',
        "[ratelimit]",
        "enabled = false",
        "[federation]",
        'allow_internal = ["127.0.0.0/8"]',
        "trusted_key_servers = []",
    ]
    if resident:
        # The rig's one tuned knob, on the side that is the same for every
        # subject: see the module docstring.
        lines.append("retry_base_ms = 50")
        registration = server.work / "seed.yaml"
        registration.write_text(json.dumps({
            "id": "seed", "url": None, "as_token": AS_TOKEN, "hs_token": "rig-seed-hs-token",
            "sender_localpart": "resident", "rate_limited": False,
            "namespaces": {"users": [{"exclusive": True, "regex": "@seed[0-9]+:.*"}]},
        }))
        lines += ["[appservices]", f'registrations = ["{registration}"]']
    config = server.work / "spindle.toml"
    config.write_text("\n".join(lines) + "\n")
    return config


def start_spindle(work, front, port, binary, ca, resident=False) -> Server:
    server = Server("spindle", work, front, port)
    config = spindle_config(server, resident)
    # SSL_CERT_FILE is the root store rustls-native-certs reads: the run's CA
    # is the only root, which is all a loopback federation needs.
    server.launch([binary, config], env={"SSL_CERT_FILE": str(ca)})
    return server


# Every rate limit Synapse exposes, lifted the way bench-servers.sh lifts
# them for the sitting, plus the federation limiter the sitting never
# reached because it never federated.
SYNAPSE_LIMIT = {"per_second": 100000, "burst_count": 100000}
SYNAPSE_LIMITS = {
    "rc_message": SYNAPSE_LIMIT,
    "rc_registration": SYNAPSE_LIMIT,
    "rc_login": {"address": SYNAPSE_LIMIT, "account": SYNAPSE_LIMIT, "failed_attempts": SYNAPSE_LIMIT},
    "rc_joins": {"local": SYNAPSE_LIMIT, "remote": SYNAPSE_LIMIT},
    "rc_joins_per_room": SYNAPSE_LIMIT,
    "rc_invites": {"per_room": SYNAPSE_LIMIT, "per_user": SYNAPSE_LIMIT, "per_issuer": SYNAPSE_LIMIT},
    "rc_presence": {"per_user": SYNAPSE_LIMIT},
    "rc_room_creation": SYNAPSE_LIMIT,
    "rc_key_requests": SYNAPSE_LIMIT,
    "rc_federation": {
        "window_size": 1000, "sleep_limit": 100000, "sleep_delay": 1,
        "reject_limit": 100000, "concurrent": 100000,
    },
}


def start_synapse(work, front, port, venv, ca, pg_url, round_number) -> Server:
    server = Server("synapse", work, front, port)
    python = pathlib.Path(venv) / "bin" / "python"
    base = work / "homeserver.yaml"
    subprocess.run(
        [python, "-m", "synapse.app.homeserver", "--server-name", server.name,
         "--config-path", base, "--generate-config", "--report-stats=no"],
        check=True, capture_output=True, cwd=work,
    )
    overrides = {
        "listeners": [{
            "port": port, "bind_addresses": ["127.0.0.1"], "type": "http", "tls": False,
            "x_forwarded": False, "resources": [{"names": ["client", "federation"], "compress": False}],
        }],
        "enable_registration": True,
        "enable_registration_without_verification": True,
        "trusted_key_servers": [],
        "suppress_key_server_warning": True,
        "federation_verify_certificates": True,
        "federation_custom_ca_list": [str(ca)],
        # Synapse refuses to federate to loopback unless told otherwise --
        # the same judgement as Spindle's allow_internal and Tuwunel's
        # ip_range_denylist, lifted the same way for all three. The
        # blocklist, not ip_range_whitelist: Synapse's federation client
        # checks an IP-literal server name against the blocklist alone.
        "ip_range_blacklist": [],
        **SYNAPSE_LIMITS,
    }
    if pg_url:
        at = urllib.parse.urlparse(pg_url)
        database = f"synapse_fed_r{round_number}"
        subprocess.run(
            ["psql", pg_url, "-v", "ON_ERROR_STOP=1", "-q",
             "-c", f"DROP DATABASE IF EXISTS {database}",
             "-c", f"CREATE DATABASE {database} ENCODING 'UTF8' LC_COLLATE 'C' "
                   "LC_CTYPE 'C' TEMPLATE template0"],
            check=True,
        )
        overrides["database"] = {
            "name": "psycopg2",
            "args": {
                "user": at.username, "password": at.password, "database": database,
                "host": at.hostname, "port": at.port or 5432, "cp_min": 5, "cp_max": 10,
            },
        }
    # JSON is YAML, and a second --config-path overrides the generated
    # file's top-level keys, so the generated file is never edited.
    rig = work / "rig.yaml"
    rig.write_text(json.dumps(overrides, indent=2))
    server.launch(
        [python, "-m", "synapse.app.homeserver", "--config-path", base, "--config-path", rig],
        cwd=work,
    )
    return server


def start_tuwunel(work, front, port, binary, ca) -> Server:
    server = Server("tuwunel", work, front, port)
    config = work / "tuwunel.toml"
    config.write_text(
        "[global]\n"
        f'server_name = "{server.name}"\n'
        f'database_path = "{work / "data"}"\n'
        'address = "127.0.0.1"\n'
        f"port = {port}\n"
        "allow_registration = true\n"
        f'registration_token = "{TOKEN}"\n'
        "allow_federation = true\n"
        "trusted_servers = []\n"
        "ip_range_denylist = []\n"
        'log = "warn"\n'
    )
    server.launch([binary, "-c", config], env={"SSL_CERT_FILE": str(ca)})
    return server


# --- the workloads ---------------------------------------------------------


def seed_room(resident: Server, members: int) -> str:
    """A public room on the resident with `members` joined beside its
    creator, seeded through the appservice door: no password is hashed
    per member, and every join is an ordinary signed membership event."""
    service = resident.client(AS_TOKEN)
    room = service.request("POST", "/_matrix/client/v3/createRoom", {"preset": "public_chat"})["room_id"]
    quoted = urllib.parse.quote(room)

    def join(number: int) -> None:
        user = urllib.parse.quote(f"@seed{number}:{resident.name}")
        resident.client(AS_TOKEN).request(
            "POST", f"/_matrix/client/v3/join/{quoted}?user_id={user}", {}
        )

    with concurrent.futures.ThreadPoolExecutor(SEED_WORKERS) as pool:
        for _ in pool.map(join, range(members)):
            pass
    return room


def joined(client: api.Client, room: str) -> int:
    path = f"/_matrix/client/v3/rooms/{urllib.parse.quote(room)}/joined_members"
    return len(client.request("GET", path).get("joined") or {})


def federated_join(resident: Server, subject: Server, members: int, tag: str) -> dict:
    room = seed_room(resident, members)
    expected = members + 2  # the creator, every seeded member, the joiner
    # The resident finishes its own writes before the clock starts.
    if joined(resident.client(AS_TOKEN), room) != members + 1:
        raise Failed("the resident's room holds the wrong membership before the join")
    joiner = subject.register(f"joiner{tag}")
    via = urllib.parse.quote(resident.name)
    started = time.perf_counter_ns()
    joiner.request("POST", f"/_matrix/client/v3/join/{urllib.parse.quote(room)}?server_name={via}", {})
    returned = time.perf_counter_ns() - started
    seen = 0
    while True:
        try:
            seen = joined(joiner, room)
        except Failed:
            # A server still finishing a partial-state join may refuse the
            # read; the clock keeps running, which is the point.
            seen = 0
        if seen >= expected:
            break
        if time.perf_counter_ns() - started > CONVERGE_SECONDS * 1e9:
            raise Failed(f"{subject.kind} served {seen} of {expected} members after {CONVERGE_SECONDS} s")
        time.sleep(0.05)
    elapsed = time.perf_counter_ns() - started
    if seen != expected:
        raise Failed(f"{subject.kind} served {seen} members, expected {expected}")
    return cell(elapsed, join_returned_ns=float(returned), joined_members=seen)


def message_bodies(client: api.Client, room: str) -> list[str]:
    bodies, token = [], None
    quoted = urllib.parse.quote(room)
    while True:
        path = f"/_matrix/client/v3/rooms/{quoted}/messages?dir=b&limit=100"
        if token:
            path += f"&from={urllib.parse.quote(token)}"
        page = client.request("GET", path)
        chunk = page.get("chunk") or []
        bodies += [
            event["content"]["body"] for event in chunk
            if event.get("type") == "m.room.message" and isinstance(event.get("content", {}).get("body"), str)
        ]
        token = page.get("end")
        if not chunk or not token:
            return bodies


def partition_catchup(resident: Server, subject: Server, missed: int, tag: str) -> dict:
    sender = resident.client(AS_TOKEN)
    room = sender.request("POST", "/_matrix/client/v3/createRoom", {"preset": "public_chat"})["room_id"]
    quoted = urllib.parse.quote(room)
    bob = subject.register(f"bob{tag}")
    bob.request("POST", f"/_matrix/client/v3/join/{quoted}?server_name={urllib.parse.quote(resident.name)}", {})
    deadline = time.monotonic() + 120
    while joined(sender, room) != 2 or joined(bob, room) != 2:
        if time.monotonic() > deadline:
            raise Failed(f"{subject.kind} and the resident never agreed on the room's two members")
        time.sleep(0.1)

    resident.front.set(False)
    subject.front.set(False)
    for number in range(missed):
        sender.request(
            "PUT", f"/_matrix/client/v3/rooms/{quoted}/send/m.room.message/missed{tag}x{number}",
            {"msgtype": "m.text", "body": f"missed-{number}"},
        )
    time.sleep(2)
    leaked = [body for body in message_bodies(bob, room) if body.startswith("missed-")]
    if leaked:
        raise Failed(f"{subject.kind} saw {len(leaked)} partitioned events: the partition leaks")

    resident.front.set(True)
    subject.front.set(True)
    healed = time.perf_counter_ns()
    sender.request(
        "PUT", f"/_matrix/client/v3/rooms/{quoted}/send/m.room.message/marker{tag}",
        {"msgtype": "m.text", "body": "marker"},
    )
    newest = f"/_matrix/client/v3/rooms/{quoted}/messages?dir=b&limit=1"
    while True:
        # The newest event is a cheap probe; the whole history is read only
        # once a message has arrived, so polling does not load the server
        # whose recovery it is timing. Any message, not the marker: a
        # server may file the backlog after the marker it fetched it for.
        chunk = bob.request("GET", newest).get("chunk") or []
        if any(event.get("type") == "m.room.message" for event in chunk):
            bodies = message_bodies(bob, room)
            if "marker" in bodies and len(bodies) > missed:
                break
        if time.perf_counter_ns() - healed > CONVERGE_SECONDS * 1e9:
            served = len(message_bodies(bob, room))
            raise Failed(f"{subject.kind} served {served} of {missed + 1} events after {CONVERGE_SECONDS} s")
        time.sleep(0.02)
    served = time.perf_counter_ns()
    contact = subject.front.first_flow
    if contact is None:
        raise Failed(f"{subject.kind} caught up without a connection after the heal")
    # The cell starts when the resident's retry first reaches the subject,
    # not at the heal: the wait between the two is the resident's backoff,
    # the same for every subject, and in the Rust bench it was most of the
    # 0.9--3.2 s spread. Both are kept.
    elapsed = served - contact
    return cell(
        elapsed,
        heal_to_served_ns=float(served - healed),
        resident_retry_ns=float(contact - healed),
        events_per_second=(missed + 1) / (elapsed / 1e9),
    )


def send_throughput(subject: Server, size: int, clients: list[int], samples: int, warmup: int) -> dict:
    api.REGISTRATION_AUTH = (
        {"type": "m.login.registration_token", "token": TOKEN}
        if subject.kind == "tuwunel"
        else {"type": "m.login.dummy"}
    )
    measured = api.measure_concurrency(subject.base, [size], clients, samples, warmup)
    cells = {}
    for count in clients:
        entry = measured[f"send_throughput/{size}/{count}"]
        per_send = 1e9 / entry["sends_per_second"]
        cells[f"send_throughput/{count}"] = cell(
            per_send,
            sends_per_second=entry["sends_per_second"],
            clients=count,
            room_events=size,
            latency_median_ns=entry["mean_ns"],
            latency_lower_ns=entry["lower_ns"],
            latency_p99_ns=entry["upper_ns"],
            latency_samples=entry["samples"],
        )
    return cells


def cell(value_ns: float, **detail) -> dict:
    """One measurement in the sitting's shape: `mean_ns` is what the gate
    and the page read; one sample per round, so the rounds are the spread."""
    return {"mean_ns": float(value_ns), "lower_ns": float(value_ns),
            "upper_ns": float(value_ns), "samples": 1, **detail}


# --- a round ----------------------------------------------------------------


def run_round(args, round_number: int, order: list[str], ca, context, loop) -> dict[str, dict]:
    work = pathlib.Path(tempfile.mkdtemp(prefix=f"fedbench-r{round_number}-", dir=args.work))
    servers: list[Server] = []

    def place(kind: str) -> tuple[pathlib.Path, Front, int]:
        directory = work / kind
        directory.mkdir()
        port = free_port()
        return directory, Front(loop, port, context), port

    try:
        directory, front, port = place("resident")
        resident = start_spindle(directory, front, port, args.spindle, ca, resident=True)
        servers.append(resident)
        subjects = {}
        for kind in order:
            directory, front, port = place(kind)
            if kind == "spindle":
                subjects[kind] = start_spindle(directory, front, port, args.spindle, ca)
            elif kind == "synapse":
                subjects[kind] = start_synapse(directory, front, port, args.synapse_venv, ca, args.pg_url, round_number)
            else:
                subjects[kind] = start_tuwunel(directory, front, port, pathlib.Path(args.bench_bin) / "tuwunel", ca)
            servers.append(subjects[kind])

        results = {}
        for kind in order:
            subject = subjects[kind]
            tag = f"r{round_number}{kind}"
            benchmarks = {}
            print(f"round {round_number}: {kind}", flush=True)
            benchmarks.update(send_throughput(subject, args.throughput_events, args.clients, args.samples, args.warmup))
            for members in args.members:
                benchmarks[f"federated_join/{members}"] = federated_join(resident, subject, members, f"{tag}m{members}")
                print(f"  join {members}: {benchmarks[f'federated_join/{members}']['mean_ns'] / 1e9:.2f} s", flush=True)
            benchmarks[f"partition_catchup/{args.missed}"] = partition_catchup(resident, subject, args.missed, tag)
            print(f"  catch-up: {benchmarks[f'partition_catchup/{args.missed}']['mean_ns'] / 1e9:.2f} s", flush=True)
            results[kind] = benchmarks
        return results
    finally:
        for server in servers:
            server.stop()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


def version_of(kind: str, args) -> str:
    if kind == "spindle":
        commit = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], capture_output=True,
                                text=True, cwd=ROOT).stdout.strip()
        return f"spindle {commit}"
    if kind == "synapse":
        python = pathlib.Path(args.synapse_venv) / "bin" / "python"
        found = subprocess.run([python, "-c", "import synapse; print(synapse.__version__)"],
                               capture_output=True, text=True).stdout.strip()
        return f"synapse {found} on {'postgres' if args.pg_url else 'sqlite'}"
    found = subprocess.run([pathlib.Path(args.bench_bin) / "tuwunel", "--version"],
                           capture_output=True, text=True).stdout.strip().splitlines()
    return found[0] if found else "tuwunel unknown"


def write_sidecar(args, started: str, finished: str) -> None:
    cpu = next(
        (line.split(":", 1)[1].strip() for line in open("/proc/cpuinfo") if line.startswith("model name")),
        platform.processor() or "unknown",
    )
    commit = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], capture_output=True,
                            text=True, cwd=ROOT).stdout.strip()
    sidecar = {
        "group": args.group,
        "rounds": args.rounds,
        "started": started,
        "finished": finished,
        "host": {
            "cpu": cpu,
            "cores": os.cpu_count(),
            "kernel": platform.release(),
            "runner": os.environ.get("BENCH_RUNNER", "developer machine"),
        },
        "spindle_commit": commit,
        "versions": [version_of(kind, args) for kind in args.subject],
        "absent": [],
        "resident": f"spindle {commit}, retry_base_ms = 50",
        "driver": "scripts/federated-benchmark.py",
        "workloads": {
            "federated_join": f"{args.members} members, POST /join to the full membership served",
            "partition_catchup": f"{args.missed} events missed, heal to every one served",
            "send_throughput": f"{args.clients} clients, own room each, {args.throughput_events}-event rooms",
        },
    }
    path = pathlib.Path(args.out) / f"{args.group}.sitting.json"
    path.write_text(json.dumps(sidecar, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--group", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--subject", action="append", choices=("spindle", "synapse", "tuwunel"),
                        help="a server to measure; repeat. Default: all three")
    parser.add_argument("--members", default="1000,10000",
                        help="room sizes to join, comma separated (default 1000,10000)")
    parser.add_argument("--missed", type=int, default=200)
    parser.add_argument("--clients", default="2,4,8",
                        help="concurrent writers; one is the send cell lines 1 and 2 already judge")
    parser.add_argument("--throughput-events", type=int, default=200)
    parser.add_argument("--samples", type=int, default=96)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--spindle", default=str(ROOT / "target" / "release" / "spindle"))
    parser.add_argument("--bench-bin", default=os.environ.get("BENCH_BIN", "tmp/bench-bin"))
    parser.add_argument("--synapse-venv", default=os.environ.get("SYNAPSE_VENV", "tmp/synvenv"))
    parser.add_argument("--pg-url", default=os.environ.get("BENCH_PG_URL"))
    parser.add_argument("--out", default=str(ROOT / "docs" / "benchmarks" / "data"))
    parser.add_argument("--work", default=None, help="where servers keep their data (default: a temp dir)")
    parser.add_argument("--keep", action="store_true", help="keep server data and logs after the run")
    args = parser.parse_args()
    if "." in args.group:
        parser.error("--group must not contain a dot: the renderer takes the group from the filename")
    args.subject = args.subject or ["spindle", "synapse", "tuwunel"]
    args.members = [int(n) for n in args.members.split(",") if n]
    args.clients = [int(n) for n in args.clients.split(",") if n]
    # Absolute, whatever the caller passed: Synapse is started from its own
    # directory, where a relative venv path names nothing.
    for name in ("spindle", "bench_bin", "synapse_venv", "out", "work"):
        if getattr(args, name):
            setattr(args, name, os.path.abspath(getattr(args, name)))
    if args.work:
        os.makedirs(args.work, exist_ok=True)
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "*"
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ.pop(variable, None)

    tls = pathlib.Path(tempfile.mkdtemp(prefix="fedbench-tls-"))
    ca, cert, key = make_ca(tls)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert, key)
    loop = front_loop()

    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    collected: dict[tuple[str, int], dict] = {}
    try:
        for round_number in range(1, args.rounds + 1):
            order = list(args.subject) if round_number % 2 else list(reversed(args.subject))
            for kind, benchmarks in run_round(args, round_number, order, ca, context, loop).items():
                collected[(kind, round_number)] = benchmarks
    except Failed as error:
        print(f"federated-benchmark: {error}", file=sys.stderr)
        print("no results written: the run did not complete", file=sys.stderr)
        return 1
    finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for (kind, round_number), benchmarks in sorted(collected.items()):
        document = {
            "server": kind,
            "dimension": "targeted",
            "round": round_number,
            "members": args.members,
            "missed": args.missed,
            "clients": args.clients,
            "benchmarks": benchmarks,
        }
        path = out / f"{args.group}.{kind}.r{round_number}.json"
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    write_sidecar(args, started, finished)
    print(f"federated-benchmark: {len(collected)} result files -> {out}/{args.group}.*.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
