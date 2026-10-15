import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mas_gate import call, secret, MAS

lp = os.environ["RIG_USER_LOCALPART"]
s, b = call("POST", MAS + "/oauth2/token", basic=("0000000000000000000MASADMN", secret("admin_client_secret")),
            form={"grant_type": "client_credentials", "scope": "urn:mas:admin"})
admin = b["access_token"]
s, b = call("GET", f"{MAS}/api/admin/v1/users/by-username/{lp}", token=admin)
if s != 200:
    s, b = call("POST", f"{MAS}/api/admin/v1/users", token=admin, body={"username": lp, "skip_homeserver_check": True})
uid = b["data"]["id"]
s, b = call("POST", f"{MAS}/api/admin/v1/users/{uid}/set-password", token=admin,
            body={"password": os.environ["RIG_PASSWORD"], "skip_password_check": True})
print(f"MAS password for {lp}: {s}")
sys.exit(0 if s in (200, 204) else 1)
