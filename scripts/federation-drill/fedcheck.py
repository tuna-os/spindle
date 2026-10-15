#!/usr/bin/env python3
"""The witness's view of reilly.asia (drill plan steps 4.1.5, 4.5.1, 4.5.5).

Runs inside Synapse A's container (drill-a, container `synapse`), so every
request takes A's path: A's resolver, A's trust store (the private CA), A's
signing key for X-Matrix, and A's database for what A has cached. It uses
Synapse's own libraries for the event format, so "verifies" means what it
means to Synapse.

  fedcheck.py keys                 B's key document as A fetches it now,
                                   and the keys A has cached for B
  fedcheck.py event EVENT_ID...    GET /_matrix/federation/v1/event/{id}
                                   from B, signed as A; check the content
                                   hash and B's signature with the key A
                                   cached, and compare with A's own copy
  fedcheck.py events N             the same for N events of each shared
                                   room, oldest first, sent by reilly.asia
"""
import base64
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request

import psycopg2
import signedjson.key
import signedjson.sign
from canonicaljson import encode_canonical_json
from unpaddedbase64 import decode_base64, encode_base64

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.crypto.event_signing import check_event_content_hash
from synapse.events import make_event_from_dict
from synapse.events.utils import prune_event

ORIGIN = "witness.lab"
PEER = "reilly.asia"
CTX = ssl.create_default_context(cafile="/tls/ca.crt")


def db():
    return psycopg2.connect(host="rehearsal-pg", user="postgres", dbname="drill_a",
                            password=os.environ["PGPASSWORD"])


def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
        return json.loads(r.read())


def delegated_base():
    wk = get(f"https://{PEER}/.well-known/matrix/server")
    return "https://" + wk["m.server"], wk


def signing_key():
    with open("/secrets/signing.key") as f:
        return signedjson.key.read_signing_keys(f)[0]


def xmatrix_get(base, path):
    key = signing_key()
    req = {"method": "GET", "uri": path, "origin": ORIGIN, "destination": PEER}
    signed = signedjson.sign.sign_json(req, ORIGIN, key)
    sig = signed["signatures"][ORIGIN][f"{key.alg}:{key.version}"]
    auth = (f'X-Matrix origin="{ORIGIN}",destination="{PEER}",'
            f'key="{key.alg}:{key.version}",sig="{sig}"')
    return get(base + path, {"Authorization": auth})


def cached_keys():
    """reilly.asia's keys as A holds them: server_keys_json rows."""
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT key_id, from_server, ts_added_ms, ts_valid_until_ms, key_json "
                    "FROM server_keys_json WHERE server_name = %s ORDER BY ts_added_ms",
                    (PEER,))
        out = []
        for key_id, from_server, added, until, key_json in cur.fetchall():
            doc = json.loads(bytes(key_json))
            out.append({"key_id": key_id, "from_server": from_server, "ts_added_ms": added,
                        "ts_valid_until_ms": until,
                        "public_key": doc.get("verify_keys", {}).get(key_id, {}).get("key")
                        or doc.get("old_verify_keys", {}).get(key_id, {}).get("key")})
        return out


def cmd_keys():
    base, wk = delegated_base()
    doc = get(base + "/_matrix/key/v2/server")
    self_signed = {}
    for key_id, k in doc.get("verify_keys", {}).items():
        vk = signedjson.key.decode_verify_key_bytes(key_id, decode_base64(k["key"]))
        try:
            signedjson.sign.verify_signed_json(doc, PEER, vk)
            self_signed[key_id] = True
        except Exception as e:  # noqa: BLE001
            self_signed[key_id] = f"FAILED: {e}"
    print(json.dumps({
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "well_known": wk, "fetched_from": base,
        "server_name": doc.get("server_name"),
        "verify_keys": {k: v["key"] for k, v in doc.get("verify_keys", {}).items()},
        "old_verify_keys": {k: v.get("key") for k, v in doc.get("old_verify_keys", {}).items()},
        "valid_until_ts": doc.get("valid_until_ts"),
        "self_signature_verifies": self_signed,
        "a_cached": cached_keys(),
    }, indent=2))


def a_copy(event_id):
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT j.json, r.room_version FROM event_json j JOIN rooms r USING (room_id) "
                    "WHERE j.event_id = %s", (event_id,))
        row = cur.fetchone()
        return (json.loads(row[0]), row[1]) if row else (None, None)


def check_event(base, event_id, keys):
    path = "/_matrix/federation/v1/event/" + urllib.parse.quote(event_id, safe="")
    res = {"event_id": event_id}
    try:
        txn = xmatrix_get(base, path)
    except Exception as e:  # noqa: BLE001
        res["error"] = f"fetch: {e}"
        return res
    pdu = txn["pdus"][0]
    mine, version = a_copy(event_id)
    rv = KNOWN_ROOM_VERSIONS[version] if version else None
    res["origin_field"] = txn.get("origin")
    res["room_version"] = version
    if rv is None:
        res["error"] = "A has no copy of this event"
        return res
    # Keys B served that A's own copy does not have (e.g. an `event_id`,
    # which a v3+ PDU must not carry).
    res["extra_keys"] = sorted(set(pdu) - set(mine) - {"unsigned"})
    res["missing_keys"] = sorted(set(mine) - set(pdu) - {"unsigned"})
    try:
        ev = make_event_from_dict(dict(pdu), rv)
    except Exception as e:  # noqa: BLE001
        res["error"] = f"Synapse refuses the PDU as served: {e!r}"
        res["pass"] = False
        return res
    res["content_hash_ok"] = check_event_content_hash(ev)
    pruned = prune_event(ev).get_pdu_json()
    sigs = pdu.get("signatures", {}).get(PEER, {})
    res["signed_with"] = sorted(sigs)
    ok = {}
    for key_id in sigs:
        k = keys.get(key_id)
        if not k:
            ok[key_id] = "key not in A's cache"
            continue
        vk = signedjson.key.decode_verify_key_bytes(key_id, decode_base64(k))
        try:
            signedjson.sign.verify_signed_json(pruned, PEER, vk)
            ok[key_id] = True
        except Exception as e:  # noqa: BLE001
            ok[key_id] = f"FAILED: {e}"
    res["signature_ok"] = ok
    # Byte-for-byte: B serves the event A already holds (minus unsigned).
    strip = lambda d: {k: v for k, v in d.items() if k not in ("unsigned", "age_ts")}
    res["identical_to_a_copy"] = (encode_canonical_json(strip(pdu)) ==
                                  encode_canonical_json(strip(mine)))
    res["pass"] = (res["content_hash_ok"] and ok and all(v is True for v in ok.values())
                   and res["identical_to_a_copy"])
    return res


def a_keys():
    return {k["key_id"]: k["public_key"] for k in cached_keys() if k["public_key"]}


def cmd_event(ids):
    base, _ = delegated_base()
    keys = a_keys()
    out = [check_event(base, i, keys) for i in ids]
    print(json.dumps(out, indent=2))


def cmd_events(n):
    base, _ = delegated_base()
    keys = a_keys()
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT room_id FROM rooms ORDER BY room_id")
        rooms = [r[0] for r in cur.fetchall()]
        out = {}
        for room in rooms:
            cur.execute("SELECT event_id FROM events WHERE room_id = %s AND sender LIKE %s "
                        "ORDER BY stream_ordering LIMIT %s", (room, f"%:{PEER}", n))
            ids = [r[0] for r in cur.fetchall()]
            results = [check_event(base, i, keys) for i in ids]
            out[room] = {"checked": len(results), "pass": sum(1 for r in results if r.get("pass")),
                         "failures": [r for r in results if not r.get("pass")]}
    print(json.dumps({"a_cached_key_ids": sorted(keys), "rooms": out,
                      "all_pass": all(v["checked"] == v["pass"] and v["checked"] > 0
                                      for v in out.values())}, indent=2))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "keys":
        cmd_keys()
    elif cmd == "event":
        cmd_event(sys.argv[2:])
    elif cmd == "events":
        cmd_events(int(sys.argv[2]))
    else:
        print(__doc__)
        sys.exit(2)
