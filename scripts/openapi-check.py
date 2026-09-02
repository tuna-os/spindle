#!/usr/bin/env python3
"""Validate a live Spindle's responses against the matrix-spec OpenAPI.

    scripts/openapi-check.py --binary target/debug/spindle --spec tmp/matrix-spec

Starts the binary on a free port with a throwaway store, drives one scripted
client through the Client-Server API (two users, one room, a message, and
every read the spec has a response schema for), and validates each response
body against the schema the spec gives for that route and status. A body the
schema refuses is a bug in the server or the spec; the report says which
route, which status, where in the body, and what the schema wanted.

The spec is pinned (SPEC_PIN) so a spec change cannot fail this check on its
own; bumping the pin is a deliberate commit. Routes with a known, explained
divergence live in scripts/openapi-allowlist.txt, one per line as
`METHOD template | reason`; a failure there is reported but does not fail
the check, so the list is the ratchet.

Exit status: 0 when every response validated (allowlisted failures aside),
1 otherwise. --report-only prints the report and exits 0 regardless.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import jsonschema
import yaml

SPEC_PIN = "0dfc6917367ee54dc1366a95196c074ee75d9c34"
SPEC_URL = "https://github.com/matrix-org/matrix-spec"
REPO = pathlib.Path(__file__).resolve().parent.parent
ALLOWLIST = REPO / "scripts" / "openapi-allowlist.txt"
SERVER_NAME = "spec.local"


# --------------------------------------------------------------------------
# The spec: every (method, path template) with its per-status response schema.


class Spec:
    """The client-server OpenAPI, loaded from a matrix-spec checkout."""

    METHODS = ("get", "post", "put", "delete")

    def __init__(self, root: pathlib.Path):
        self.api = root / "data" / "api" / "client-server"
        if not self.api.is_dir():
            sys.exit(f"openapi-check: {root} is not a matrix-spec checkout (no {self.api})")
        self.docs: dict[pathlib.Path, dict] = {}
        # (method, compiled regex, template, responses, file)
        self.routes: list[tuple[str, re.Pattern[str], str, dict, pathlib.Path]] = []
        self.schemas: dict[tuple[str, str, str], dict | None] = {}

    def load(self) -> None:
        for file in sorted(self.api.glob("*.yaml")):
            doc = self.doc(file)
            base = "/_matrix/client/v3"
            for server in doc.get("servers", []):
                variables = server.get("variables", {})
                if "basePath" in variables:
                    base = variables["basePath"].get("default", base)
            for path, methods in doc.get("paths", {}).items():
                for method, operation in methods.items():
                    if method not in self.METHODS:
                        continue
                    template = base + path
                    self.routes.append(
                        (method.upper(), self.matcher(template), template, operation.get("responses", {}), file)
                    )
        # Longest template first, so a literal segment beats a placeholder
        # where both would match.
        self.routes.sort(key=lambda route: (-route[2].count("/"), -len(route[2])))

    @staticmethod
    def matcher(template: str) -> re.Pattern[str]:
        parts = re.split(r"\{[^}]+\}", template)
        # A placeholder may be empty: the spec's state-key routes take an
        # empty key as a trailing slash (`/state/m.room.name/`).
        return re.compile("^" + "[^/]*".join(re.escape(part) for part in parts) + "$")

    def doc(self, file: pathlib.Path) -> dict:
        file = file.resolve()
        if file not in self.docs:
            with file.open() as handle:
                self.docs[file] = yaml.safe_load(handle)
        return self.docs[file]

    def route(self, method: str, path: str):
        for route in self.routes:
            if route[0] == method and route[1].match(path):
                return route
        return None

    def schema(self, route, status: int) -> dict | None:
        """The JSON schema for `status` on this route, refs inlined; None
        when the spec documents the status without a JSON body."""
        method, _, template, responses, file = route
        key = (method, template, str(status))
        if key in self.schemas:
            return self.schemas[key]
        response = responses.get(str(status)) or responses.get("default")
        schema = None
        if response is not None:
            response = self.resolve(response, file, ())
            content = response.get("content", {}).get("application/json", {})
            schema = content.get("schema")
        self.schemas[key] = schema
        return schema

    def documented(self, route, status: int) -> bool:
        return str(status) in route[3]

    def resolve(self, node, file: pathlib.Path, stack: tuple):
        """Inline every `$ref` under `node`, reading other files relative to
        `file`. A reference already on the stack (a recursive schema) becomes
        the permissive `{}` rather than an infinite expansion."""
        if isinstance(node, list):
            return [self.resolve(item, file, stack) for item in node]
        if not isinstance(node, dict):
            return node
        if "$ref" in node:
            ref = node["$ref"]
            target_file, _, fragment = ref.partition("#")
            if target_file:
                target_path = (file.parent / target_file).resolve()
                target_doc = self.doc(target_path)
            else:
                target_path = file.resolve()
                target_doc = self.doc(target_path)
            target = target_doc
            for part in [part for part in fragment.split("/") if part]:
                part = part.replace("~1", "/").replace("~0", "~")
                target = target[part]
            key = (target_path, fragment)
            if key in stack:
                return {}
            resolved = self.resolve(target, target_path, stack + (key,))
            # OpenAPI 3.1 allows siblings beside a $ref (a description,
            # usually); they annotate rather than constrain, so the target
            # wins where they collide.
            siblings = {k: self.resolve(v, file, stack) for k, v in node.items() if k != "$ref"}
            if isinstance(resolved, dict):
                return {**siblings, **resolved}
            return resolved
        return {key: self.resolve(value, file, stack) for key, value in node.items()}


# --------------------------------------------------------------------------
# The server under test.


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Server:
    def __init__(self, binary: pathlib.Path, workdir: pathlib.Path):
        self.binary = binary
        self.workdir = workdir
        self.port = free_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.process: subprocess.Popen | None = None

    def __enter__(self):
        config = self.workdir / "spindle.toml"
        config.write_text(
            "[server]\n"
            f'name = "{SERVER_NAME}"\n'
            f'bind = "127.0.0.1:{self.port}"\n'
            "[storage]\n"
            f'path = "{self.workdir / "data"}"\n'
            "[ratelimit]\n"
            "enabled = false\n"
        )
        log = (self.workdir / "spindle.log").open("w")
        self.process = subprocess.Popen(
            [str(self.binary), str(config)], stdout=log, stderr=subprocess.STDOUT
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                sys.exit(f"openapi-check: the server exited early; see {self.workdir / 'spindle.log'}")
            try:
                urllib.request.urlopen(f"{self.base}/_matrix/client/versions", timeout=1).read()
                return self
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                time.sleep(0.1)
        sys.exit("openapi-check: the server did not answer /versions within 30 s")

    def __exit__(self, *_):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()


# --------------------------------------------------------------------------
# The scripted client, validating as it goes.


class Report:
    def __init__(self, allowlist: dict[str, str]):
        self.allowlist = allowlist
        self.validated = 0
        self.failures: list[str] = []
        self.known: list[str] = []
        self.unmatched: list[str] = []
        self.undocumented: list[str] = []
        self.bodiless = 0
        self.exercised: set[str] = set()


class Client:
    def __init__(self, base: str, spec: Spec, report: Report):
        self.base = base
        self.spec = spec
        self.report = report
        self.txn = 0

    def call(self, method: str, path: str, body=None, token: str | None = None, expect: int = 200):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method)
        if body is not None:
            request.add_header("content-type", "application/json")
        if token:
            request.add_header("authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status = response.status
                raw = response.read()
        except urllib.error.HTTPError as error:
            status = error.code
            raw = error.read()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = None
        if status != expect:
            # The flow cannot go on without the body it asked for, and a
            # report that stopped at the first refusal is better than a
            # cascade of failures it caused.
            sys.exit(f"openapi-check: {method} {path}: expected {expect}, got {status}: {raw[:300]!r}")
        self.validate(method, path, status, parsed)
        return parsed

    def validate(self, method: str, path: str, status: int, body) -> None:
        bare = path.split("?", 1)[0]
        route = self.spec.route(method, bare)
        if route is None:
            self.report.unmatched.append(f"{method} {bare}")
            return
        template = route[2]
        self.report.exercised.add(f"{method} {template}")
        if not self.spec.documented(route, status):
            self.report.undocumented.append(f"{method} {template} -> {status}")
            return
        schema = self.spec.schema(route, status)
        if schema is None:
            self.report.bodiless += 1
            return
        validator = jsonschema.Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(body), key=lambda error: list(error.absolute_path))
        if not errors:
            self.report.validated += 1
            return
        where = "/".join(str(part) for part in errors[0].absolute_path) or "(root)"
        line = f"{method} {template} ({status}) at {where}: {errors[0].message[:300]}"
        if len(errors) > 1:
            line += f" (+{len(errors) - 1} more)"
        key = f"{method} {template}"
        if key in self.report.allowlist:
            self.report.known.append(f"{line}\n    allowed: {self.report.allowlist[key]}")
        else:
            self.report.failures.append(line)

    def next_txn(self) -> str:
        self.txn += 1
        return f"t{self.txn}"


def quote(segment: str) -> str:
    return urllib.parse.quote(segment, safe="")


def drive(client: Client) -> None:
    """One pass through the API. Every call names the status it expects;
    anything else is a failure, because a 4xx where a 200 was due is a bug
    the schema check would otherwise never see."""
    c = client
    alice_id = f"@alice:{SERVER_NAME}"
    bob_id = f"@bob:{SERVER_NAME}"

    c.call("GET", "/_matrix/client/versions")
    registered = c.call(
        "POST",
        "/_matrix/client/v3/register",
        {"username": "alice", "password": "hunter2", "auth": {"type": "m.login.dummy", "session": "s1"}},
    )
    alice = registered["access_token"]
    bob = c.call(
        "POST",
        "/_matrix/client/v3/register",
        {"username": "bob", "password": "hunter2", "auth": {"type": "m.login.dummy", "session": "s2"}},
    )["access_token"]
    c.call("GET", "/_matrix/client/v3/login")
    c.call(
        "POST",
        "/_matrix/client/v3/login",
        {"type": "m.login.password", "identifier": {"type": "m.id.user", "user": "alice"}, "password": "hunter2"},
    )
    c.call("GET", "/_matrix/client/v3/account/whoami", token=alice)
    c.call("GET", "/_matrix/client/v3/capabilities", token=alice)
    c.call("GET", "/_matrix/client/v3/devices", token=alice)

    c.call("PUT", f"/_matrix/client/v3/profile/{quote(alice_id)}/displayname", {"displayname": "Alice"}, alice)
    c.call("PUT", f"/_matrix/client/v3/profile/{quote(alice_id)}/avatar_url", {"avatar_url": f"mxc://{SERVER_NAME}/alice"}, alice)
    c.call("GET", f"/_matrix/client/v3/profile/{quote(alice_id)}", token=alice)
    c.call("GET", f"/_matrix/client/v3/profile/{quote(alice_id)}/displayname", token=alice)
    c.call("GET", f"/_matrix/client/v3/profile/{quote(alice_id)}/avatar_url", token=alice)

    room = c.call("POST", "/_matrix/client/v3/createRoom", {"name": "Spec", "topic": "checking"}, alice)["room_id"]
    r = quote(room)
    c.call("POST", f"/_matrix/client/v3/rooms/{r}/invite", {"user_id": bob_id}, alice)
    c.call("POST", f"/_matrix/client/v3/rooms/{r}/join", {}, bob)
    first = c.call(
        "PUT",
        f"/_matrix/client/v3/rooms/{r}/send/m.room.message/{c.next_txn()}",
        {"msgtype": "m.text", "body": "hello alice, this is a needle"},
        bob,
    )["event_id"]
    second = c.call(
        "PUT",
        f"/_matrix/client/v3/rooms/{r}/send/m.room.message/{c.next_txn()}",
        {"msgtype": "m.text", "body": "and a second one"},
        alice,
    )["event_id"]
    c.call("PUT", f"/_matrix/client/v3/rooms/{r}/state/m.room.topic/", {"topic": "checked"}, alice)
    c.call("PUT", f"/_matrix/client/v3/rooms/{r}/state/m.room.name/", {"name": "Spec room"}, alice)
    c.call("GET", f"/_matrix/client/v3/rooms/{r}/state/m.room.topic/", token=alice)
    c.call("GET", f"/_matrix/client/v3/rooms/{r}/state/m.room.member/{quote(bob_id)}", token=alice)
    c.call("GET", f"/_matrix/client/v3/rooms/{r}/state", token=alice)
    c.call("GET", f"/_matrix/client/v3/rooms/{r}/members", token=alice)
    c.call("GET", f"/_matrix/client/v3/rooms/{r}/joined_members", token=alice)
    c.call("GET", f"/_matrix/client/v3/rooms/{r}/messages?dir=b&limit=10", token=alice)
    c.call("GET", f"/_matrix/client/v3/rooms/{r}/context/{quote(first)}?limit=4", token=alice)
    c.call("GET", f"/_matrix/client/v3/rooms/{r}/event/{quote(first)}", token=alice)
    c.call("GET", f"/_matrix/client/v3/rooms/{r}/aliases", token=alice)
    c.call("GET", f"/_matrix/client/v1/rooms/{r}/timestamp_to_event?ts=0&dir=f", token=alice)

    c.call("POST", f"/_matrix/client/v3/rooms/{r}/receipt/m.read/{quote(first)}", {}, alice)
    c.call("POST", f"/_matrix/client/v3/rooms/{r}/read_markers", {"m.fully_read": first, "m.read": second}, alice)
    c.call("PUT", f"/_matrix/client/v3/rooms/{r}/typing/{quote(alice_id)}", {"typing": True, "timeout": 5000}, alice)

    sync = c.call("GET", "/_matrix/client/v3/sync?timeout=0", token=alice)
    c.call("GET", f"/_matrix/client/v3/sync?timeout=0&since={quote(sync['next_batch'])}", token=alice)
    c.call(
        "POST",
        "/_matrix/client/v3/search",
        {"search_categories": {"room_events": {"search_term": "needle", "event_context": {"before_limit": 1, "after_limit": 1, "include_profile": True}}}},
        alice,
    )
    c.call("GET", "/_matrix/client/v3/notifications", token=alice)
    c.call("GET", "/_matrix/client/v3/pushrules/", token=alice)
    c.call("GET", "/_matrix/client/v3/pushrules/global/underride/.m.rule.message", token=alice)
    c.call("GET", "/_matrix/client/v3/pushrules/global/underride/.m.rule.message/enabled", token=alice)
    c.call("GET", "/_matrix/client/v3/pushrules/global/underride/.m.rule.message/actions", token=alice)
    c.call("GET", "/_matrix/client/v3/pushers", token=alice)

    c.call("PUT", f"/_matrix/client/v3/user/{quote(alice_id)}/account_data/org.example.pref", {"colour": "blue"}, alice)
    c.call("GET", f"/_matrix/client/v3/user/{quote(alice_id)}/account_data/org.example.pref", token=alice)
    c.call("PUT", f"/_matrix/client/v3/user/{quote(alice_id)}/rooms/{r}/account_data/org.example.pref", {"colour": "red"}, alice)
    c.call("GET", f"/_matrix/client/v3/user/{quote(alice_id)}/rooms/{r}/account_data/org.example.pref", token=alice)
    filter_id = c.call("POST", f"/_matrix/client/v3/user/{quote(alice_id)}/filter", {"room": {"timeline": {"limit": 5}}}, alice)["filter_id"]
    c.call("GET", f"/_matrix/client/v3/user/{quote(alice_id)}/filter/{quote(filter_id)}", token=alice)
    c.call("PUT", f"/_matrix/client/v3/user/{quote(alice_id)}/rooms/{r}/tags/m.favourite", {"order": 0.5}, alice)
    c.call("GET", f"/_matrix/client/v3/user/{quote(alice_id)}/rooms/{r}/tags", token=alice)
    c.call("GET", "/_matrix/client/v3/joined_rooms", token=alice)

    alias = f"#spec:{SERVER_NAME}"
    c.call("PUT", f"/_matrix/client/v3/directory/room/{quote(alias)}", {"room_id": room}, alice)
    c.call("GET", f"/_matrix/client/v3/directory/room/{quote(alias)}", token=alice)
    c.call("PUT", f"/_matrix/client/v3/directory/list/room/{r}", {"visibility": "public"}, alice)
    c.call("GET", f"/_matrix/client/v3/directory/list/room/{r}", token=alice)
    c.call("GET", "/_matrix/client/v3/publicRooms", token=alice)
    c.call("POST", "/_matrix/client/v3/publicRooms", {"limit": 10}, alice)
    c.call("POST", "/_matrix/client/v3/user_directory/search", {"search_term": "bob"}, alice)
    c.call("GET", f"/_matrix/client/v1/rooms/{r}/hierarchy", token=alice)
    c.call("GET", "/_matrix/client/v1/media/config", token=alice)
    c.call("GET", f"/_matrix/client/v3/presence/{quote(alice_id)}/status", token=alice)
    c.call("PUT", f"/_matrix/client/v3/presence/{quote(alice_id)}/status", {"presence": "online"}, alice)

    c.call("POST", f"/_matrix/client/v3/rooms/{r}/leave", {}, bob)
    c.call("POST", f"/_matrix/client/v3/rooms/{r}/forget", {}, bob)
    c.call("POST", "/_matrix/client/v3/logout", {}, bob)


# --------------------------------------------------------------------------


def load_allowlist() -> dict[str, str]:
    allowed: dict[str, str] = {}
    if not ALLOWLIST.exists():
        return allowed
    for line in ALLOWLIST.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        route, _, reason = line.partition("|")
        allowed[" ".join(route.split())] = reason.strip() or "(no reason given)"
    return allowed


def ensure_spec(path: pathlib.Path) -> pathlib.Path:
    """A matrix-spec checkout at SPEC_PIN, fetched if `path` is empty."""
    if (path / "data" / "api").is_dir():
        head = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if head and head != SPEC_PIN:
            print(f"openapi-check: note: {path} is at {head[:12]}, the pin is {SPEC_PIN[:12]}", file=sys.stderr)
        return path
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "fetch", "-q", "--depth", "1", SPEC_URL, SPEC_PIN], check=True)
    subprocess.run(["git", "-C", str(path), "checkout", "-q", "FETCH_HEAD"], check=True)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", type=pathlib.Path, default=REPO / "target" / "debug" / "spindle")
    parser.add_argument("--spec", type=pathlib.Path, default=REPO / "tmp" / "matrix-spec",
                        help="a matrix-spec checkout; fetched at the pin if absent")
    parser.add_argument("--report-only", action="store_true", help="never fail, only report")
    parser.add_argument("--keep", action="store_true", help="keep the server's working directory")
    parser.add_argument("--unexercised", action="store_true",
                        help="list the spec routes the scripted client never called")
    arguments = parser.parse_args()

    if not arguments.binary.exists():
        sys.exit(f"openapi-check: no binary at {arguments.binary}; build one with cargo build -p spindle-server")
    spec = Spec(ensure_spec(arguments.spec))
    spec.load()
    report = Report(load_allowlist())

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="openapi-check-", dir=REPO / "tmp" if (REPO / "tmp").is_dir() else None))
    try:
        with Server(arguments.binary, workdir) as server:
            drive(Client(server.base, spec, report))
    finally:
        if not arguments.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    every = sorted({f"{route[0]} {route[2]}" for route in spec.routes})
    print(f"openapi-check: {len(every)} routes in the spec at {SPEC_PIN[:12]}, "
          f"{len(report.exercised)} exercised")
    print(f"openapi-check: {report.validated} responses validated, {report.bodiless} without a JSON body")
    if arguments.unexercised:
        for line in every:
            if line not in report.exercised:
                print(f"  not exercised: {line}")
    for line in report.unmatched:
        print(f"  no spec route: {line}")
    for line in report.undocumented:
        print(f"  status not documented: {line}")
    for line in report.known:
        print(f"  known: {line}")
    for line in report.failures:
        print(f"  FAIL: {line}")
    if report.failures:
        print(f"openapi-check: {len(report.failures)} failure(s)")
        return 0 if arguments.report_only else 1
    print("openapi-check: every response matched its schema")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
