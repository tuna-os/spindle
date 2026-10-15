#!/usr/bin/env python3
"""Client side of the federation drill (docs/synapse-migration-drill.md).

Runs in the drill-client pod, standard library only. It talks to the two
lab servers through their client APIs:

  A  http://drill-a:8008   witness.lab   (Synapse for the whole drill)
  B  http://drill-b:8008   reilly.asia   (Synapse B, later Spindle B)

State lives in $DRILL_STATE (default /state): passwords.json, tokens.json,
rooms.json and every result file.

  drill.py users                 register the four test accounts
  drill.py rooms                 create and join the shared rooms
  drill.py addroom LABEL ID VER  record a room made elsewhere (drill-e2ee)
  drill.py history N             N more events in the long-history room
  drill.py fork write|check      contested fork (with drill.sh partition on/off)
  drill.py baseline LABEL        state map, extremities, newest event per room
  drill.py pingpong LABEL [ROOMS] a message each way in each room (or the
                                 comma-separated room labels), timed
  drill.py statechange LABEL     a topic change from each side, compare
  drill.py compare L1 L2         compare two baselines (B side vs B side)
"""
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

STATE = os.environ.get("DRILL_STATE", "/state")
SERVERS = {
    "A": {"url": os.environ.get("DRILL_A", "http://drill-a:8008"), "name": "witness.lab",
          "secret": "/secrets/a/secrets.yaml"},
    "B": {"url": os.environ.get("DRILL_B", "http://drill-b:8008"), "name": "reilly.asia",
          "secret": "/secrets/b/secrets.yaml"},
}
USERS = {"witness": "A", "wit2": "A", "drill-b1": "B", "drill-b2": "B"}
ADMINS = {"witness", "drill-b1"}


def path(name):
    return os.path.join(STATE, name)


def load(name, default=None):
    try:
        with open(path(name)) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save(name, value):
    tmp = path(name + ".tmp")
    with open(tmp, "w") as f:
        json.dump(value, f, indent=2, sort_keys=True)
    os.replace(tmp, path(name))


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, file=sys.stderr, flush=True)


class HTTPError(Exception):
    def __init__(self, code, body):
        super().__init__(f"{code} {body}")
        self.code, self.body = code, body


def call(side, method, p, body=None, token=None, timeout=60):
    url = SERVERS[side]["url"] + p
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            j = json.loads(raw)
        except ValueError:
            j = {"raw": raw[:200].decode(errors="replace")}
        raise HTTPError(e.code, j) from None


def mxid(user):
    return f"@{user}:{SERVERS[USERS[user]]['name']}"


def side_of(user):
    return USERS[user]


def q(s):
    return urllib.parse.quote(s, safe="")


# ------------------------------------------------------------------ accounts

def shared_secret(side):
    for line in open(SERVERS[side]["secret"]):
        if line.startswith("registration_shared_secret:"):
            return line.split(":", 1)[1].strip().strip('"')
    raise SystemExit(f"no registration_shared_secret for {side}")


def cmd_users():
    pw = load("passwords.json", {})
    for user, side in USERS.items():
        if user in pw:
            continue
        pw[user] = secrets.token_urlsafe(18)
        nonce = call(side, "GET", "/_synapse/admin/v1/register")["nonce"]
        admin = user in ADMINS
        mac = hmac.new(shared_secret(side).encode(), digestmod=hashlib.sha1)
        mac.update(b"\x00".join([nonce.encode(), user.encode(), pw[user].encode(),
                                 b"admin" if admin else b"notadmin"]))
        call(side, "POST", "/_synapse/admin/v1/register", {
            "nonce": nonce, "username": user, "password": pw[user], "admin": admin,
            "mac": mac.hexdigest()})
        save("passwords.json", pw)
        log("registered", mxid(user), "admin" if admin else "")
    for user in USERS:
        token(user, fresh=True)


def token(user, fresh=False):
    toks = load("tokens.json", {})
    if user in toks and not fresh:
        return toks[user]
    pw = load("passwords.json")[user]
    r = call(side_of(user), "POST", "/_matrix/client/v3/login", {
        "type": "m.login.password", "identifier": {"type": "m.id.user", "user": user},
        "password": pw, "initial_device_display_name": "drill.py"})
    toks[user] = r["access_token"]
    save("tokens.json", toks)
    return toks[user]


def as_user(user, method, p, body=None, timeout=60):
    """A client call as `user` on their own server; logs in again once if
    the server no longer knows the token (as after the cut-over)."""
    try:
        return call(side_of(user), method, p, body, token(user), timeout)
    except HTTPError as e:
        if e.code == 401:
            log(f"{user}: token refused ({e.body.get('errcode')}); logging in again")
            return call(side_of(user), method, p, body, token(user, fresh=True), timeout)
        raise


TXN = [int(time.time() * 1000)]


def send(user, room, content, etype="m.room.message"):
    TXN[0] += 1
    return as_user(user, "PUT", f"/_matrix/client/v3/rooms/{q(room)}/send/{etype}/drill{TXN[0]}",
                   content)["event_id"]


def put_state(user, room, etype, content, state_key=""):
    return as_user(user, "PUT", f"/_matrix/client/v3/rooms/{q(room)}/state/{etype}/{q(state_key)}",
                   content)["event_id"]


def get_state(user, room, etype, state_key=""):
    return as_user(user, "GET", f"/_matrix/client/v3/rooms/{q(room)}/state/{etype}/{q(state_key)}")


def join(user, room, via):
    for attempt in range(30):
        try:
            return as_user(user, "POST", f"/_matrix/client/v3/join/{q(room)}?server_name={via}", {})
        except HTTPError as e:
            if attempt == 29:
                raise
            log(f"join {user} {room}: {e}; retrying")
            time.sleep(2)


def wait_event(user, room, event_id, timeout=120):
    """Seconds until `event_id` is visible to `user` on their own server."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            as_user(user, "GET", f"/_matrix/client/v3/rooms/{q(room)}/event/{q(event_id)}", timeout=10)
            return round(time.time() - t0, 2)
        except HTTPError as e:
            if e.code not in (404, 403):
                log(f"wait_event {user} {event_id}: {e}")
        time.sleep(0.5)
    return None


# --------------------------------------------------------------------- rooms

ROOMS = [
    # label, creator, version, other users, extra
    ("v10-general", "drill-b1", "10", ["witness", "wit2", "drill-b2"], {}),
    ("v12-witness-created", "witness", "12", ["drill-b1", "drill-b2", "wit2"], {}),
    ("v9", "drill-b1", "9", ["witness", "drill-b2"], {}),
    ("v6", "drill-b1", "6", ["witness", "drill-b2"], {}),
    ("v1", "drill-b1", "1", ["witness", "drill-b2"], {}),
    ("history-v10", "drill-b1", "10", ["witness", "wit2", "drill-b2"], {}),
    ("fork-v10", "drill-b1", "10", ["witness", "wit2", "drill-b2"], {"fork": True}),
]


def cmd_rooms():
    rooms = load("rooms.json", {})
    for label, creator, version, others, extra in ROOMS:
        if label in rooms:
            continue
        body = {"name": f"drill {label}", "preset": "private_chat", "room_version": version,
                "invite": [mxid(u) for u in others], "topic": f"drill {label} initial topic"}
        if extra.get("fork"):
            # Both sides hold power 100, so either can change anything:
            # concurrent changes are then genuinely contested.
            pl = {"users": {mxid(creator): 100, mxid("witness"): 100, mxid("drill-b2"): 50}}
            body["power_level_content_override"] = pl
        try:
            room = as_user(creator, "POST", "/_matrix/client/v3/createRoom", body)["room_id"]
        except HTTPError as e:
            log(f"room {label}: create failed: {e}")
            rooms[label] = {"error": str(e), "version": version}
            save("rooms.json", rooms)
            continue
        for u in others:
            join(u, room, SERVERS[side_of(creator)]["name"])
        rooms[label] = {"room_id": room, "version": version, "creator": mxid(creator),
                        "members": [mxid(u) for u in [creator] + others]}
        save("rooms.json", rooms)
        # A little history in every room, from both sides.
        for i in range(10):
            u = [creator] + others
            send(u[i % len(u)], room, {"msgtype": "m.text", "body": f"warm-up {label} #{i}"})
        log(f"room {label}: {room} v{version}")


def cmd_history(n):
    rooms = load("rooms.json")
    room = rooms["history-v10"]["room_id"]
    users = ["drill-b1", "witness", "drill-b2", "wit2"]
    t0 = time.time()
    count = rooms["history-v10"].get("generated", 0)
    for i in range(n):
        u = users[i % 4] if i % 7 else users[(i // 7) % 4]
        if i % 500 == 499:
            put_state("drill-b1", room, "m.room.name", {"name": f"drill history-v10 ({count + i})"})
        elif i % 250 == 249:
            put_state("drill-b1", room, "m.room.topic", {"topic": f"history topic {count + i}"})
        else:
            send(u, room, {"msgtype": "m.text", "body": f"history {count + i} from {u}"})
        if i % 500 == 0:
            log(f"history: {i}/{n} in {time.time() - t0:.0f}s")
    rooms["history-v10"]["generated"] = count + n
    save("rooms.json", rooms)
    log(f"history: {n} events in {time.time() - t0:.0f}s")


def cmd_fork(phase):
    """Concurrent, conflicting state on both sides while federation is cut.

    `drill.sh partition on` makes both fronts answer 503 to every
    federation request, so each side keeps its own branch. `fork write`
    then changes the same state on both sides: topic, and the power level
    of drill-b2 (75 on B, 0 on A), plus a name on A. After `drill.sh
    partition off`, `fork check` waits until each side holds the other's
    branch and records which state each side resolved to.
    """
    rooms = load("rooms.json")
    room = rooms["fork-v10"]["room_id"]
    out = rooms["fork-v10"].setdefault("fork", {"room_id": room, "events": {}})
    ev = out["events"]
    if phase == "write":
        ev["B_topic"] = put_state("drill-b1", room, "m.room.topic", {"topic": "fork: B side topic"})
        ev["A_topic"] = put_state("witness", room, "m.room.topic", {"topic": "fork: A side topic"})
        pl_b = get_state("drill-b1", room, "m.room.power_levels")
        pl_b["users"][mxid("drill-b2")] = 75
        ev["B_power"] = put_state("drill-b1", room, "m.room.power_levels", pl_b)
        pl_a = get_state("witness", room, "m.room.power_levels")
        pl_a["users"][mxid("drill-b2")] = 0
        pl_a["users"][mxid("wit2")] = 50
        ev["A_power"] = put_state("witness", room, "m.room.power_levels", pl_a)
        ev["A_name"] = put_state("witness", room, "m.room.name", {"name": "fork: A side name"})
        for i in range(5):
            send("drill-b1", room, {"msgtype": "m.text", "body": f"fork B branch {i}"})
            send("witness", room, {"msgtype": "m.text", "body": f"fork A branch {i}"})
        log("fork: both branches written", json.dumps(ev))
    else:
        out["A_sees_B_topic_s"] = wait_event("witness", room, ev["B_topic"], 300)
        out["B_sees_A_topic_s"] = wait_event("drill-b1", room, ev["A_topic"], 300)
        # One more message from each side merges the two extremities.
        out["merge_B"] = send("drill-b1", room, {"msgtype": "m.text", "body": "fork merge from B"})
        out["merge_A"] = send("witness", room, {"msgtype": "m.text", "body": "fork merge from A"})
        wait_event("witness", room, out["merge_B"])
        wait_event("drill-b1", room, out["merge_A"])
        for side, user in (("A", "witness"), ("B", "drill-b1")):
            out[f"{side}_topic"] = get_state(user, room, "m.room.topic").get("topic")
            out[f"{side}_b2_power"] = get_state(user, room, "m.room.power_levels")["users"].get(mxid("drill-b2"))
            out[f"{side}_name"] = get_state(user, room, "m.room.name").get("name")
        out["sides_agree"] = all(out[f"A_{k}"] == out[f"B_{k}"] for k in ("topic", "b2_power", "name"))
    save("rooms.json", rooms)
    print(json.dumps(out, indent=2))


# ------------------------------------------------------------------ baseline

def room_snapshot(user, room):
    st = as_user(user, "GET", f"/_matrix/client/v3/rooms/{q(room)}/state")
    state_map = {f"{e['type']}|{e.get('state_key', '')}": e["event_id"] for e in st}
    msgs = as_user(user, "GET", f"/_matrix/client/v3/rooms/{q(room)}/messages?dir=b&limit=1")
    newest = msgs["chunk"][0]["event_id"] if msgs.get("chunk") else None
    return {"state": state_map, "state_events": len(state_map), "newest_event": newest}


def cmd_baseline(label):
    rooms = load("rooms.json")
    out = {"label": label, "taken_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "rooms": {}}
    for rl, r in rooms.items():
        if "room_id" not in r:
            continue
        out["rooms"][rl] = {}
        for side, user in (("A", "witness"), ("B", "drill-b1")):
            try:
                out["rooms"][rl][side] = room_snapshot(user, r["room_id"])
            except HTTPError as e:
                out["rooms"][rl][side] = {"error": str(e)}
        a, b = out["rooms"][rl].get("A", {}), out["rooms"][rl].get("B", {})
        out["rooms"][rl]["A_equals_B_state"] = a.get("state") == b.get("state") and "state" in a
        if a.get("state") and b.get("state") and a["state"] != b["state"]:
            keys = set(a["state"]) | set(b["state"])
            out["rooms"][rl]["A_B_differ"] = sorted(k for k in keys if a["state"].get(k) != b["state"].get(k))
    save(f"baseline-{label}.json", out)
    summary = {rl: {"A_equals_B_state": v["A_equals_B_state"],
                    "state_events": v.get("B", {}).get("state_events"),
                    "differ": v.get("A_B_differ")} for rl, v in out["rooms"].items()}
    print(json.dumps(summary, indent=2))


def cmd_compare(l1, l2):
    """State maps of B at two points (e.g. Synapse B at the seal and Spindle
    B after the import), room by room."""
    b1, b2 = load(f"baseline-{l1}.json"), load(f"baseline-{l2}.json")
    out = {}
    for rl in b1["rooms"]:
        for side in ("A", "B"):
            s1 = b1["rooms"][rl].get(side, {}).get("state")
            s2 = b2["rooms"].get(rl, {}).get(side, {}).get("state")
            if s1 is None or s2 is None:
                out[f"{rl}/{side}"] = {"equal": False, "why": "missing on one side"}
                continue
            keys = set(s1) | set(s2)
            diff = sorted(k for k in keys if s1.get(k) != s2.get(k))
            out[f"{rl}/{side}"] = {"equal": not diff, "differ": diff,
                                   "newest_equal": b1["rooms"][rl][side].get("newest_event") ==
                                   b2["rooms"][rl][side].get("newest_event")}
    save(f"compare-{l1}-{l2}.json", out)
    print(json.dumps(out, indent=2))


# ------------------------------------------------------- traffic both ways

def cmd_pingpong(label, only=None):
    rooms = load("rooms.json")
    out = {"label": label, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "rooms": {}}
    for rl, r in rooms.items():
        if "room_id" not in r or (only and rl not in only):
            continue
        room, res = r["room_id"], {}
        try:
            eb = send("drill-b1", room, {"msgtype": "m.text", "body": f"{label}: B -> A {secrets.token_hex(4)}"})
            res["B_to_A_event"] = eb
            res["B_to_A_s"] = wait_event("witness", room, eb)
        except HTTPError as e:
            res["B_to_A_error"] = str(e)
        try:
            ea = send("witness", room, {"msgtype": "m.text", "body": f"{label}: A -> B {secrets.token_hex(4)}"})
            res["A_to_B_event"] = ea
            res["A_to_B_s"] = wait_event("drill-b1", room, ea)
        except HTTPError as e:
            res["A_to_B_error"] = str(e)
        res["ok"] = res.get("B_to_A_s") is not None and res.get("A_to_B_s") is not None
        out["rooms"][rl] = res
        log(f"pingpong {label} {rl}: {res}")
    out["all_ok"] = all(v["ok"] for v in out["rooms"].values())
    save(f"pingpong-{label}.json", out)
    print(json.dumps(out, indent=2))


def cmd_statechange(label):
    rooms = load("rooms.json")
    out = {"label": label, "rooms": {}}
    for rl, r in rooms.items():
        if "room_id" not in r:
            continue
        room, res = r["room_id"], {}
        # A power-level change first, from whichever side holds power 100
        # (the creator): it raises the other side's account to 100, so that
        # side can change state too. Both servers must then show it.
        try:
            creator = r.get("creator", mxid("drill-b1"))
            owner, other = (("drill-b1", "witness") if creator.endswith(":reilly.asia")
                            else ("witness", "drill-b1"))
            pl = get_state(owner, room, "m.room.power_levels")
            if pl.get("users", {}).get(mxid(other)) != 100:
                pl.setdefault("users", {})[mxid(other)] = 100
                eid = put_state(owner, room, "m.room.power_levels", pl)
                res["power_event"] = eid
                res["power_by"] = side_of(owner)
                res["power_seen_by_peer_s"] = wait_event(other, room, eid)
            for u in ("witness", "drill-b1"):
                level = get_state(u, room, "m.room.power_levels")["users"].get(mxid(other))
                res[f"power_on_{side_of(u)}"] = level == 100
        except HTTPError as e:
            res["power_error"] = str(e)
        for side, user, peer in (("B", "drill-b1", "witness"), ("A", "witness", "drill-b1")):
            topic = f"{label}: topic set from {side} {secrets.token_hex(3)}"
            try:
                eid = put_state(user, room, "m.room.topic", {"topic": topic})
                res[f"{side}_event"] = eid
                res[f"{side}_seen_by_peer_s"] = wait_event(peer, room, eid)
                time.sleep(1)
                res[f"{side}_topic_on_A"] = get_state("witness", room, "m.room.topic").get("topic") == topic
                res[f"{side}_topic_on_B"] = get_state("drill-b1", room, "m.room.topic").get("topic") == topic
            except HTTPError as e:
                res[f"{side}_error"] = str(e)
        res["ok"] = all(res.get(k) for k in ("A_topic_on_A", "A_topic_on_B", "B_topic_on_A", "B_topic_on_B", "power_on_A", "power_on_B"))
        out["rooms"][rl] = res
        log(f"statechange {label} {rl}: ok={res['ok']}")
    out["all_ok"] = all(v["ok"] for v in out["rooms"].values())
    save(f"statechange-{label}.json", out)
    print(json.dumps(out, indent=2))


def main():
    os.makedirs(STATE, exist_ok=True)
    cmd, args = (sys.argv[1] if len(sys.argv) > 1 else ""), sys.argv[2:]
    if cmd == "users":
        cmd_users()
    elif cmd == "rooms":
        cmd_rooms()
    elif cmd == "addroom":
        rooms = load("rooms.json", {})
        rooms[args[0]] = {"room_id": args[1], "version": args[2], "encrypted": True}
        save("rooms.json", rooms)
    elif cmd == "history":
        cmd_history(int(args[0]))
    elif cmd == "fork":
        cmd_fork(args[0])
    elif cmd == "baseline":
        cmd_baseline(args[0])
    elif cmd == "compare":
        cmd_compare(args[0], args[1])
    elif cmd == "pingpong":
        cmd_pingpong(args[0], args[1].split(",") if len(args) > 1 else None)
    elif cmd == "statechange":
        cmd_statechange(args[0])
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
