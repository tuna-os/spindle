"""MatrixRTC pieces Element Call needs from the homeserver, with a MAS-issued
token on the dark Spindle: OpenID token minting, MSC4140 delayed leave with
lk-jwt-service's token-less restart/send, MSC4354 sticky flag, versions."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mas_gate import call, secret, MAS, check, RESULTS
HS = "http://127.0.0.1:18008"
ROOM = "!fJgacLfsDbkATqEtqO:reilly.asia"  # rig plain room; b is joined
s, b = call("POST", MAS + "/oauth2/token", basic=("0000000000000000000MASADMN", secret("admin_client_secret")),
            form={"grant_type": "client_credentials", "scope": "urn:mas:admin"})
admin = b["access_token"]
s, b = call("GET", f"{MAS}/api/admin/v1/users/by-username/spindle-mig-b", token=admin)
s, b = call("POST", f"{MAS}/api/admin/v1/personal-sessions", token=admin, body={
    "actor_user_id": b["data"]["id"], "human_name": "rtc check", "expires_in": 600,
    "scope": "urn:matrix:client:api:* urn:matrix:client:device:RTCCHECK"})
tok = b["data"]["attributes"]["access_token"]
me = "@spindle-mig-b:reilly.asia"
s, b = call("POST", f"{HS}/_matrix/client/v3/createRoom", token=tok, body={"name": "rtc check", "power_level_content_override": {"events": {"org.matrix.msc3401.call.member": 0}}})
ROOM = b["room_id"]

s, v = call("GET", HS + "/_matrix/client/versions")
for f in ("org.matrix.msc4140", "org.matrix.msc4143", "org.matrix.msc4354"):
    check(f"/versions advertises {f}", v["unstable_features"].get(f) is True)
s, b = call("POST", f"{HS}/_matrix/client/v3/user/{me}/openid/request_token", token=tok, body={})
check("OpenID token for lk-jwt-service (MAS session)", s == 200 and b.get("matrix_server_name") == "reilly.asia", f"{s} {list(b) if isinstance(b, dict) else b}")
s, b = call("GET", f"{HS}/_matrix/client/v1/rtc/transports", token=tok)
check("MSC4143 /rtc/transports served", s == 200, f"{s} {b}")

# Element Call's delayed leave: an empty m.rtc.member state event, delayed.
key = f"_{me}_RTCCHECK_m.call"
s, b = call("PUT", f"{HS}/_matrix/client/v3/rooms/{ROOM}/state/org.matrix.msc3401.call.member/{key}?org.matrix.msc4140.delay=8000", token=tok, body={})
delay_id = b.get("delay_id") if isinstance(b, dict) else None
check("delayed leave scheduled", s == 200 and delay_id, f"{s} {b}")
# Join: the live membership.
s, b = call("PUT", f"{HS}/_matrix/client/v3/rooms/{ROOM}/state/org.matrix.msc3401.call.member/{key}", token=tok,
            body={"application": "m.call", "call_id": "", "scope": "m.room", "device_id": "RTCCHECK", "focus_active": {"type": "livekit"}, "foci_preferred": []})
check("call membership sent", s == 200, f"{s}")
# lk-jwt-service keeps it pending, with no access token, past the original delay.
for i in range(4):
    time.sleep(4)
    s, b = call("POST", f"{HS}/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/restart", body={})
    if s != 200:
        break
check("token-less restart x4 over 16 s (delay 8 s)", s == 200, f"{s} {b}")
s, b = call("GET", f"{HS}/_matrix/client/v3/rooms/{ROOM}/state/org.matrix.msc3401.call.member/{key}", token=tok)
check("membership still live after 16 s", s == 200 and b.get("application") == "m.call", f"{s} {b}")
# Participant drops: lk-jwt-service sends the leave.
s, b = call("POST", f"{HS}/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/send", body={})
check("token-less send", s == 200, f"{s} {b}")
s, b = call("GET", f"{HS}/_matrix/client/v3/rooms/{ROOM}/state/org.matrix.msc3401.call.member/{key}", token=tok)
check("membership cleared by the delegated send", s == 200 and b == {}, f"{s} {b}")
s, b = call("POST", f"{HS}/_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/send", body={})
check("second send is 404 (lk-jwt reads as already sent)", s == 404, f"{s}")
print(f"{sum(r['ok'] for r in RESULTS)}/{len(RESULTS)} checks passed")
