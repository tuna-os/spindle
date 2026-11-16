#!/usr/bin/env python3
"""Record sliding-sync exchanges between real clients and a homeserver.

A reverse proxy for the one route a room list lives on:

    POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync
    POST /_matrix/client/v5/sync   (the same thing at its eventual stable path)

Everything is passed through untouched; for the users named in
SYNC_TAP_USERS the request (query, body), the response (status, body) and
the time it took are appended as one JSON line to SYNC_TAP_DIR/<date>.jsonl.
Element X's room-list misbehaviour -- a list that blanks, a count that
jumps, a room that vanishes -- is then a question about specific responses,
which `sync_tap_report.py` reads back.

The access token is never written: a connection is named by the user, the
device (from /whoami, asked once per token and cached) and the request's
`conn_id`. Bodies are written as the server sent them, so the file holds the
recorded users' messages: keep SYNC_TAP_USERS to people who asked for it.

Standard library only, so it runs from `python:3-slim` with no install.

    SYNC_TAP_UPSTREAM=http://spindle:8008 SYNC_TAP_USERS=@me:example.org \
        SYNC_TAP_DIR=/data python3 sync_tap.py --listen 0.0.0.0:8009
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import http.server
import json
import os
import socketserver
import sys
import threading
import time
import urllib.parse

UPSTREAM = urllib.parse.urlsplit(
    os.environ.get("SYNC_TAP_UPSTREAM", "http://spindle:8008")
)
USERS = {u for u in os.environ.get("SYNC_TAP_USERS", "").split(",") if u}
OUT_DIR = os.environ.get("SYNC_TAP_DIR", "/data")
MAX_FILE_BYTES = int(os.environ.get("SYNC_TAP_MAX_FILE_BYTES", str(512 * 1024 * 1024)))

TAPPED = (
    "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync",
    "/_matrix/client/v5/sync",
)
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}

_whoami: dict[str, tuple[str, str] | None] = {}
_whoami_lock = threading.Lock()
_write_lock = threading.Lock()
_seq = 0


def _upstream() -> http.client.HTTPConnection:
    port = UPSTREAM.port or (443 if UPSTREAM.scheme == "https" else 80)
    cls = (
        http.client.HTTPSConnection
        if UPSTREAM.scheme == "https"
        else http.client.HTTPConnection
    )
    # Long polls wait up to a minute server-side; leave room for that.
    return cls(UPSTREAM.hostname, port, timeout=120)


def identity(token: str) -> tuple[str, str] | None:
    """(user_id, device_id) for an access token, from /whoami, cached by digest."""
    key = hashlib.sha256(token.encode()).hexdigest()
    with _whoami_lock:
        if key in _whoami:
            return _whoami[key]
    found = None
    try:
        conn = _upstream()
        conn.request(
            "GET",
            "/_matrix/client/v3/account/whoami",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp = conn.getresponse()
        body = resp.read()
        if resp.status == 200:
            data = json.loads(body)
            found = (data.get("user_id", ""), data.get("device_id", ""))
    except (OSError, ValueError, http.client.HTTPException):
        found = None
    with _whoami_lock:
        # A failure is not cached: the next request asks again.
        if found is not None:
            _whoami[key] = found
    return found


def _token(headers, query: str) -> str | None:
    auth = headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    params = urllib.parse.parse_qs(query)
    return (params.get("access_token") or [None])[0]


def _path_for_today() -> str:
    day = dt.datetime.now(dt.UTC).strftime("%Y%m%d")
    base = os.path.join(OUT_DIR, f"{day}.jsonl")
    n = 0
    path = base
    while os.path.exists(path) and os.path.getsize(path) >= MAX_FILE_BYTES:
        n += 1
        path = os.path.join(OUT_DIR, f"{day}.{n}.jsonl")
    return path


def record(entry: dict) -> None:
    global _seq
    with _write_lock:
        _seq += 1
        entry["seq"] = _seq
        with open(_path_for_today(), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")


def _json_or_text(raw: bytes):
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return {"_unparsed": raw[:4096].decode("utf-8", "replace")}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet: the JSONL is the log
        pass

    def _proxy(self):
        split = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        headers["Host"] = self.headers.get("Host", UPSTREAM.netloc)

        tapped_route = split.path in TAPPED and self.command == "POST"
        who = None
        if tapped_route and USERS:
            token = _token(self.headers, split.query)
            who = identity(token) if token else None
            if who is not None and who[0] not in USERS:
                who = None

        started = time.monotonic()
        wall = dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")
        try:
            conn = _upstream()
            conn.request(self.command, self.path, body=body or None, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
            status, reason, resp_headers = resp.status, resp.reason, resp.getheaders()
        except (OSError, http.client.HTTPException) as error:
            payload = json.dumps(
                {"errcode": "M_UNKNOWN", "error": f"sync-tap: upstream: {error}"}
            ).encode()
            status, reason, resp_headers = (
                502,
                "Bad Gateway",
                [("Content-Type", "application/json")],
            )
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)

        if who is not None:
            req_json = _json_or_text(body)
            record(
                {
                    "t": wall,
                    "ms": elapsed_ms,
                    "user": who[0],
                    "device": who[1],
                    "conn_id": (req_json or {}).get("conn_id")
                    if isinstance(req_json, dict)
                    else None,
                    "path": split.path,
                    "query": {
                        k: v[0]
                        for k, v in urllib.parse.parse_qs(split.query).items()
                        if k != "access_token"
                    },
                    "user_agent": self.headers.get("User-Agent", ""),
                    "request": req_json,
                    "status": status,
                    "response": _json_or_text(payload),
                }
            )

        # A client that gave up on a long poll has closed its socket; the
        # exchange is still worth recording, so it is written first.
        try:
            self.send_response(status, reason)
            for k, v in resp_headers:
                if k.lower() not in HOP_BY_HOP:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_OPTIONS = do_HEAD = _proxy


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", default="0.0.0.0:8009")
    args = parser.parse_args()
    if not USERS:
        print(
            "sync-tap: SYNC_TAP_USERS is empty; proxying without recording",
            file=sys.stderr,
        )
    os.makedirs(OUT_DIR, exist_ok=True)
    host, port = args.listen.rsplit(":", 1)
    print(
        f"sync-tap: {args.listen} -> {UPSTREAM.geturl()}, recording {sorted(USERS)} into {OUT_DIR}",
        file=sys.stderr,
        flush=True,
    )
    Server((host, int(port)), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
