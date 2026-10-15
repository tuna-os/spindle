#!/usr/bin/env python3
"""#563 MAS gate driver: dark MAS 1.23.0 (production mas.dump) in front of a
dark Spindle. Runs on the workstation against port-forwards:
  MAS      http://127.0.0.1:18080  (svc/dark-mas)
  Spindle  http://127.0.0.1:18008  (svc/dark-spindle-mas)
Secrets come from secret/dark-mas-secrets via kubectl and are never printed.
Only rig users (spindle-mig-*, spindle-mas-*) are touched."""
import base64, json, os, subprocess, sys, time, urllib.request, urllib.error, urllib.parse

MAS = os.environ.get("MAS", "http://127.0.0.1:18080")
HS = os.environ.get("HS", "http://127.0.0.1:18008")
NS = "spindle-rehearsal"
KUBE = {**os.environ, "KUBECONFIG": os.path.expanduser("~/.kube/config-aws-migration")}
RESULTS = []


def secret(key):
    out = subprocess.run(["kubectl", "-n", NS, "get", "secret", "dark-mas-secrets", "-o", "json"],
                         env=KUBE, check=True, capture_output=True).stdout
    return base64.b64decode(json.loads(out)["data"][key]).decode()


def call(method, url, body=None, token=None, basic=None, form=None):
    headers = {}
    data = None
    if body is not None:
        data = json.dumps(body).encode(); headers["Content-Type"] = "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode(); headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if basic:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read(); status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read(); status = e.code
    try:
        return status, json.loads(raw) if raw else None
    except ValueError:
        return status, raw.decode(errors="replace")[:300]


def check(name, ok, detail=""):
    RESULTS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + (f"  -- {detail}" if detail else ""), flush=True)
    return ok


def wait_for(fn, timeout=60, every=2):
    end = time.time() + timeout
    while True:
        v = fn()
        if v or time.time() > end:
            return v
        time.sleep(every)


def main():
    matrix_secret = secret("matrix_secret")
    admin_secret = secret("admin_client_secret")

    # --- discovery -----------------------------------------------------------
    for path in ("/_matrix/client/v1/auth_metadata",
                 "/_matrix/client/unstable/org.matrix.msc2965/auth_metadata"):
        s, b = call("GET", HS + path)
        check(f"discovery {path}", s == 200 and isinstance(b, dict) and b.get("issuer", "").startswith("http://dark-mas."),
              f"{s} issuer={isinstance(b, dict) and b.get('issuer')}")
    s, b = call("GET", HS + "/_matrix/client/v3/login")
    check("legacy /login is MAS's, not Spindle's (404 M_UNRECOGNIZED)", s == 404, f"{s} {b}")

    # --- admin API token -----------------------------------------------------
    s, b = call("POST", MAS + "/oauth2/token", basic=("0000000000000000000MASADMN", admin_secret),
                form={"grant_type": "client_credentials", "scope": "urn:mas:admin"})
    assert s == 200, (s, b)
    admin = b["access_token"]

    def mas_user(username, create=True, skip_check=True):
        s, b = call("GET", f"{MAS}/api/admin/v1/users/by-username/{username}", token=admin)
        if s == 200:
            return b["data"]["id"], False
        if not create:
            return None, False
        s, b = call("POST", f"{MAS}/api/admin/v1/users", token=admin,
                    body={"username": username, "skip_homeserver_check": skip_check})
        assert s in (200, 201), (s, b)
        return b["data"]["id"], True

    def query_user(localpart):
        return call("GET", f"{HS}/_synapse/mas/query_user?localpart={localpart}", token=matrix_secret)

    def personal(user_id, scope, name):
        s, b = call("POST", f"{MAS}/api/admin/v1/personal-sessions", token=admin,
                    body={"actor_user_id": user_id, "human_name": name, "scope": scope, "expires_in": 3600})
        assert s in (200, 201), (s, b)
        return b["data"]["id"], b["data"]["attributes"].get("access_token")

    def whoami(token):
        return call("GET", HS + "/_matrix/client/v3/account/whoami", token=token)

    # --- existing (imported) rig user a gets a MAS identity ---------------------
    a_id, created = mas_user("spindle-mig-a")
    check("MAS knows rig user a (created via admin API)" if created else "MAS knows rig user a", a_id)
    s, b = query_user("spindle-mig-a")
    check("Spindle /_synapse/mas/query_user for the imported user", s == 200 and b.get("user_id") == "@spindle-mig-a:reilly.asia", f"{s} {b}")

    # --- MAS-issued sessions authenticate against Spindle ----------------------
    for label, scope in (
        ("stable MSC2967 scopes", "urn:matrix:client:api:* urn:matrix:client:device:MASGATESTABLE"),
        ("unstable MSC2967 scopes", "urn:matrix:org.matrix.msc2967.client:api:* urn:matrix:org.matrix.msc2967.client:device:MASGATEUNSTABLE"),
    ):
        sid, tok = personal(a_id, scope, f"masgate {label}")
        s, b = whoami(tok)
        want_dev = scope.rsplit(":", 1)[1]
        check(f"MAS personal session ({label}) -> Spindle whoami", s == 200 and b.get("user_id") == "@spindle-mig-a:reilly.asia" and b.get("device_id") == want_dev, f"{s} {b}")
        s, b = call("GET", HS + "/_matrix/client/v3/devices", token=tok) if s == 200 else (None, None)
        if s == 200:
            check(f"device {want_dev} listed by Spindle ({label})", any(d["device_id"] == want_dev for d in b["devices"]), f"{len(b['devices'])} devices")
            # E2EE history for this user is reachable with the MAS token
            s2, b2 = call("GET", HS + "/_matrix/client/v3/room_keys/version", token=tok)
            check(f"key backup visible with MAS token ({label})", s2 == 200 and "version" in b2, f"{s2}")
        if label.startswith("stable"):
            stable_sid, stable_tok = sid, tok

    # --- compat (legacy /login through MAS) ------------------------------------
    # Production has 2 active compat sessions; a compat token is mct_…
    import secrets as _s
    pw = _s.token_urlsafe(18)
    s, b = call("POST", f"{MAS}/api/admin/v1/users/{a_id}/set-password", token=admin,
                body={"password": pw, "skip_password_check": True})
    check("MAS set-password for rig user a", s in (200, 204), f"{s}")
    s, b = call("POST", f"{MAS}/_matrix/client/v3/login", body={
        "type": "m.login.password", "identifier": {"type": "m.id.user", "user": "spindle-mig-a"},
        "password": pw, "device_id": "MASGATECOMPAT", "initial_device_display_name": "masgate compat"})
    if check("MAS compat /login (m.login.password)", s == 200 and "access_token" in b, f"{s} {b if s != 200 else ''}"):
        ctok = b["access_token"]
        s, b = whoami(ctok)
        check("compat token (mct_) -> Spindle whoami", s == 200 and b.get("device_id") == "MASGATECOMPAT", f"{s} {b}")
        s, b = call("GET", HS + "/_matrix/client/v3/devices/MASGATECOMPAT", token=ctok)
        check("compat device display name provisioned to Spindle", s == 200 and b.get("display_name") == "masgate compat", f"{s} {b}")
        s, b = call("POST", f"{MAS}/_matrix/client/v3/logout", token=ctok)
        check("MAS compat /logout", s == 200, f"{s}")
        s, b = wait_for(lambda: (lambda r: r if r[0] == 401 else None)(whoami(ctok)), timeout=150, every=5) or whoami(ctok)
        check("compat token refused by Spindle after logout (<=120s cache)", s == 401, f"{s} {b}")
        s, b = call("GET", HS + "/_matrix/client/v3/devices", token=stable_tok)
        check("compat device deleted on Spindle after logout", s == 200 and not any(d["device_id"] == "MASGATECOMPAT" for d in b["devices"]), f"{[d['device_id'] for d in b['devices']] if s == 200 else b}")

    # --- provisioning: new user, devices, deactivate, reactivate ---------------
    d_id, created = mas_user("spindle-mas-d", skip_check=False)
    check("MAS register spindle-mas-d (localpart check against Spindle)", d_id, "created" if created else "existed")
    s, b = wait_for(lambda: (lambda r: r if r[0] == 200 else None)(query_user("spindle-mas-d")), timeout=60) or query_user("spindle-mas-d")
    check("provision_user: spindle-mas-d exists in Spindle", s == 200 and b.get("is_deactivated") is False, f"{s} {b}")
    s, b = call("GET", f"{HS}/_synapse/mas/is_localpart_available?localpart=spindle-mas-d", token=matrix_secret)
    check("is_localpart_available now says taken", s == 400, f"{s} {b}")
    sid, dtok = personal(d_id, "urn:matrix:client:api:* urn:matrix:client:device:MASGATED1", "masgate d device")
    s, b = whoami(dtok)
    check("new user's MAS token -> Spindle whoami", s == 200 and b.get("user_id") == "@spindle-mas-d:reilly.asia", f"{s} {b}")
    s, b = call("POST", f"{MAS}/api/admin/v1/personal-sessions/{sid}/revoke", token=admin)
    check("MAS revoke personal session", s in (200, 204), f"{s}")
    s, b = call("POST", f"{MAS}/api/admin/v1/users/{d_id}/deactivate", token=admin, body={})
    check("MAS deactivate spindle-mas-d", s in (200, 204), f"{s} {b if s >= 300 else ''}")
    s, b = wait_for(lambda: (lambda r: r if r[0] == 200 and r[1].get("is_deactivated") else None)(query_user("spindle-mas-d")), timeout=90) or query_user("spindle-mas-d")
    check("delete_user: Spindle reports spindle-mas-d deactivated", s == 200 and b.get("is_deactivated") is True, f"{s} {b}")
    s, b = call("POST", f"{MAS}/api/admin/v1/users/{d_id}/reactivate", token=admin, body={})
    check("MAS reactivate spindle-mas-d", s in (200, 204), f"{s} {b if s >= 300 else ''}")
    s, b = wait_for(lambda: (lambda r: r if r[0] == 200 and r[1].get("is_deactivated") is False else None)(query_user("spindle-mas-d")), timeout=90) or query_user("spindle-mas-d")
    check("reactivate_user: Spindle reports spindle-mas-d active", s == 200 and b.get("is_deactivated") is False, f"{s} {b}")

    # --- revocation of an OAuth/personal session propagates --------------------
    s, b = call("POST", f"{MAS}/api/admin/v1/personal-sessions/{stable_sid}/revoke", token=admin)
    check("MAS revoke a's stable-scope session", s in (200, 204), f"{s}")
    s, b = wait_for(lambda: (lambda r: r if r[0] == 401 else None)(whoami(stable_tok)), timeout=150, every=5) or whoami(stable_tok)
    check("revoked MAS token refused by Spindle (<=120s cache)", s == 401, f"{s} {b}")

    json.dump(RESULTS, open(os.environ.get("OUT", "/dev/stdout") if os.environ.get("OUT") else sys.stdout, "w") if os.environ.get("OUT") else sys.stdout, indent=1)
    print()
    fails = [r for r in RESULTS if not r["ok"]]
    print(f"{len(RESULTS) - len(fails)}/{len(RESULTS)} checks passed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
