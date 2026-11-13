#!/usr/bin/env python3
"""Tests for the TLS front in `federated-benchmark.py`, run in CI as a script.

No pytest, for the reason parity-gate-test.py gives. The front is the part
of the targeted sitting a number silently depends on: a partition that
lets a pooled keep-alive connection through measures no partition at all,
and the subject would "catch up" in the time it takes to read a page. So
what is tested is the gate -- open forwards over verified TLS, closed
resets new connections *and* established ones, healed forwards again --
against a loopback echo server, with no homeserver needed.

Usage: python3 scripts/federated-benchmark-test.py
"""

from __future__ import annotations

import importlib.util
import pathlib
import socket
import socketserver
import ssl
import sys
import tempfile
import threading

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("federated_benchmark", HERE / "federated-benchmark.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except ConnectionResetError:
            # The front resetting the flow is what the partition tests do.
            pass


def rig():
    """An echo server, a front before it, and a client context that trusts
    only the run's CA -- the shape every subject's federation link has."""
    echo = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    echo.daemon_threads = True
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    tls = pathlib.Path(tempfile.mkdtemp(prefix="front-test-"))
    ca, cert, key = bench.make_ca(tls)
    server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_context.load_cert_chain(cert, key)
    front = bench.Front(LOOP, echo.server_address[1], server_context)
    client_context = ssl.create_default_context(cafile=str(ca))
    return front, client_context


def connect(front, context) -> ssl.SSLSocket:
    raw = socket.create_connection(("127.0.0.1", front.port), timeout=5)
    # Verified against the IP the server name carries, as the subjects do.
    return context.wrap_socket(raw, server_hostname="127.0.0.1")


def round_trip(sock: ssl.SSLSocket, payload: bytes) -> bytes:
    sock.sendall(payload)
    received = b""
    while len(received) < len(payload):
        chunk = sock.recv(65536)
        if not chunk:
            break
        received += chunk
    return received


def refused(front, context) -> bool:
    try:
        with connect(front, context) as sock:
            return round_trip(sock, b"ping") != b"ping"
    except (OSError, ssl.SSLError):
        return True


def test_an_open_front_forwards_over_tls_the_ca_verifies():
    front, context = rig()
    with connect(front, context) as sock:
        assert round_trip(sock, b"hello" * 1000) == b"hello" * 1000


def test_a_partition_refuses_new_connections_and_a_heal_admits_them():
    front, context = rig()
    front.set(False)
    assert refused(front, context)
    front.set(True)
    with connect(front, context) as sock:
        assert round_trip(sock, b"after") == b"after"


def test_a_partition_breaks_an_established_keep_alive_flow():
    # The leak the Rust bench's proxy was written against: a pooled
    # connection opened before the partition must not carry traffic across
    # it.
    front, context = rig()
    with connect(front, context) as sock:
        assert round_trip(sock, b"before") == b"before"
        front.set(False)
        try:
            leaked = round_trip(sock, b"during")
        except (OSError, ssl.SSLError):
            leaked = b""
        assert leaked != b"during", "an established flow crossed the partition"


LOOP = bench.front_loop()


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as error:
            failed += 1
            print(f"FAIL {test.__name__}: {error}")
        else:
            print(f"ok   {test.__name__}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
