"""Mint a MAS session for a rig user on the dark MAS and run ssprobe
(Element X's matrix-sdk-ui SyncService) against the dark Spindle."""
import base64, json, os, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mas_gate import call, secret, MAS, KUBE

u = sys.argv[1] if len(sys.argv) > 1 else "b"
lp = f"spindle-mig-{u}"
here = os.path.dirname(os.path.abspath(__file__))
rig = json.loads(subprocess.run(["kubectl", "-n", "spindle-rehearsal", "get", "secret", "spindle-mig-rig", "-o", "json"],
                                env=KUBE, check=True, capture_output=True).stdout)["data"]
recovery = base64.b64decode(rig[f"recovery-key-{u}"]).decode()
manifest = json.loads(json.loads(subprocess.run(["kubectl", "-n", "spindle-rehearsal", "get", "configmap", "spindle-mig-rig-manifest", "-o", "json"],
                                                env=KUBE, check=True, capture_output=True).stdout)["data"]["manifest.json"])
rooms = [r["room_id"] for r in manifest["rooms"] if any(u in e.get("readable_by", []) for e in r["events"])]
if os.environ.get("ONLY"): rooms = [r for r in rooms if os.environ["ONLY"] in r]

s, b = call("POST", MAS + "/oauth2/token", basic=("0000000000000000000MASADMN", secret("admin_client_secret")),
            form={"grant_type": "client_credentials", "scope": "urn:mas:admin"})
admin = b["access_token"]
s, b = call("GET", f"{MAS}/api/admin/v1/users/by-username/{lp}", token=admin)
uid = b["data"]["id"]
device = f"SSPROBE{int(time.time()) % 100000}"
s, b = call("POST", f"{MAS}/api/admin/v1/personal-sessions", token=admin, body={
    "actor_user_id": uid, "human_name": "ssprobe (Element X sync stack)", "expires_in": 3600,
    "scope": f"urn:matrix:client:api:* urn:matrix:client:device:{device}"})
token = b["data"]["attributes"]["access_token"]
store = tempfile.mkdtemp(prefix="ssprobe-")
env = {**os.environ, "HS": "http://127.0.0.1:18008", "TOKEN": token, "USER_ID": f"@{lp}:reilly.asia",
       "DEVICE_ID": device, "RECOVERY_KEY": recovery, "EXPECT_ROOMS": ",".join(rooms),
       "STORE": store, "OUT": os.path.join(here, f"report-{u}.json")}
print(f"user {lp} device {device} rooms {len(rooms)}", flush=True)
rc = subprocess.run([os.path.join(here, "target/release/ssprobe")], env=env).returncode
sys.exit(rc)
