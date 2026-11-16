"""A small Matrix client-server client: the calls the scenario makes.

Standard library only. Every call returns the decoded JSON body; a call the
scenario depends on raises `MatrixError` when it fails, so a harness bug
stops the run instead of turning into a server difference later.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request

SLIDING_PATH = "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"

# The driver talks to loopback. A proxy in the environment would send it
# somewhere else, and that looks like a hung server.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class MatrixError(RuntimeError):
    def __init__(self, server: str, method: str, path: str, status: int, body):
        self.status = status
        self.body = body
        super().__init__(f"{server}: {method} {path} -> {status} {body}")


def quote(s: str) -> str:
    return urllib.parse.quote(s, safe="")


class Server:
    def __init__(self, label: str, base: str, shared_secret: str):
        self.label = label
        self.base = base.rstrip("/")
        self.shared_secret = shared_secret

    def raw(
        self,
        method: str,
        path: str,
        body=None,
        token: str | None = None,
        query: dict | None = None,
        timeout: float = 120.0,
    ):
        """Send one request. Returns (status, decoded body, elapsed ms)."""
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in query.items() if v is not None}
            )
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        start = time.monotonic()
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                status, payload = resp.status, resp.read()
        except urllib.error.HTTPError as err:
            status, payload = err.code, err.read()
        ms = (time.monotonic() - start) * 1000
        try:
            decoded = json.loads(payload) if payload else {}
        except ValueError:
            decoded = {"_raw": payload.decode(errors="replace")}
        return status, decoded, ms

    def call(
        self, method: str, path: str, body=None, token=None, query=None, ok=(200,)
    ):
        status, decoded, _ = self.raw(method, path, body, token, query)
        if status == 429:
            # Neither server should throttle the harness (both are configured
            # not to), but a retry costs less than a false difference.
            time.sleep(decoded.get("retry_after_ms", 500) / 1000)
            status, decoded, _ = self.raw(method, path, body, token, query)
        if status not in ok:
            raise MatrixError(self.label, method, path, status, decoded)
        return decoded

    def register(self, localpart: str, password: str) -> None:
        """Register through the Synapse-compatible shared-secret endpoint."""
        path = "/_synapse/admin/v1/register"
        nonce = self.call("GET", path)["nonce"]
        mac = hmac.new(self.shared_secret.encode(), digestmod=hashlib.sha1)
        for part in (nonce, localpart, password, "notadmin"):
            mac.update(part.encode())
            if part != "notadmin":
                mac.update(b"\x00")
        self.call(
            "POST",
            path,
            {
                "nonce": nonce,
                "username": localpart,
                "password": password,
                "admin": False,
                "mac": mac.hexdigest(),
            },
        )

    def login(self, localpart: str, password: str, device_id: str) -> User:
        resp = self.call(
            "POST",
            "/_matrix/client/v3/login",
            {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": localpart},
                "password": password,
                "device_id": device_id,
                "initial_device_display_name": f"ssdiff {device_id}",
            },
        )
        return User(self, resp["user_id"], resp["access_token"], resp["device_id"])


class User:
    def __init__(self, server: Server, user_id: str, token: str, device_id: str):
        self.server = server
        self.user_id = user_id
        self.token = token
        self.device_id = device_id
        self._txn = 0

    def txn(self) -> str:
        self._txn += 1
        return f"ssdiff{int(time.time() * 1000)}.{self._txn}"

    def call(self, method, path, body=None, query=None, ok=(200,)):
        return self.server.call(method, path, body, self.token, query, ok)

    # --- rooms -------------------------------------------------------------

    def create_room(self, body: dict) -> str:
        return self.call("POST", "/_matrix/client/v3/createRoom", body)["room_id"]

    def send(self, room_id: str, etype: str, content: dict) -> str:
        path = f"/_matrix/client/v3/rooms/{quote(room_id)}/send/{quote(etype)}/{self.txn()}"
        return self.call("PUT", path, content)["event_id"]

    def state(self, room_id: str, etype: str, key: str, content: dict) -> str:
        path = f"/_matrix/client/v3/rooms/{quote(room_id)}/state/{quote(etype)}/{quote(key)}"
        return self.call("PUT", path, content)["event_id"]

    def invite(self, room_id: str, user_id: str, is_direct: bool = False) -> None:
        body = {"user_id": user_id}
        if is_direct:
            # Not in the spec's /invite body, but harmless: the DM flag that
            # matters is `is_direct` on the member event, which createRoom
            # sets. Spindle and Synapse both ignore unknown fields.
            body["is_direct"] = True
        self.call("POST", f"/_matrix/client/v3/rooms/{quote(room_id)}/invite", body)

    def join(self, room_id: str) -> None:
        self.call("POST", f"/_matrix/client/v3/join/{quote(room_id)}", {})

    def leave(self, room_id: str) -> None:
        self.call("POST", f"/_matrix/client/v3/rooms/{quote(room_id)}/leave", {})

    def typing(self, room_id: str, typing: bool, timeout: int = 30000) -> None:
        body = {"typing": typing}
        if typing:
            body["timeout"] = timeout
        self.call(
            "PUT",
            f"/_matrix/client/v3/rooms/{quote(room_id)}/typing/{quote(self.user_id)}",
            body,
        )

    def receipt(self, room_id: str, event_id: str, rtype: str = "m.read") -> None:
        path = f"/_matrix/client/v3/rooms/{quote(room_id)}/receipt/{quote(rtype)}/{quote(event_id)}"
        self.call("POST", path, {})

    def account_data(self, etype: str, content: dict) -> None:
        path = (
            f"/_matrix/client/v3/user/{quote(self.user_id)}/account_data/{quote(etype)}"
        )
        self.call("PUT", path, content)

    def room_account_data(self, room_id: str, etype: str, content: dict) -> None:
        path = (
            f"/_matrix/client/v3/user/{quote(self.user_id)}/rooms/{quote(room_id)}"
            f"/account_data/{quote(etype)}"
        )
        self.call("PUT", path, content)

    def upgrade(self, room_id: str, new_version: str) -> str:
        path = f"/_matrix/client/v3/rooms/{quote(room_id)}/upgrade"
        return self.call("POST", path, {"new_version": new_version})["replacement_room"]

    def set_displayname(self, name: str) -> None:
        self.call(
            "PUT",
            f"/_matrix/client/v3/profile/{quote(self.user_id)}/displayname",
            {"displayname": name},
        )

    def capabilities(self) -> dict:
        return self.call("GET", "/_matrix/client/v3/capabilities")

    # --- end-to-end --------------------------------------------------------

    def send_to_device(self, etype: str, messages: dict) -> None:
        path = f"/_matrix/client/v3/sendToDevice/{quote(etype)}/{self.txn()}"
        self.call("PUT", path, {"messages": messages})

    def keys_upload(self, body: dict) -> dict:
        return self.call("POST", "/_matrix/client/v3/keys/upload", body)

    # --- sliding sync ------------------------------------------------------

    def sliding(self, body: dict, pos: str | None, timeout_ms: int | None):
        query = {}
        if pos is not None:
            query["pos"] = pos
        if timeout_ms is not None:
            query["timeout"] = str(timeout_ms)
        status, resp, ms = self.server.raw(
            "POST",
            SLIDING_PATH,
            body,
            self.token,
            query,
            timeout=(timeout_ms or 0) / 1000 + 60,
        )
        return query, status, resp, ms
