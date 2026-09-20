#!/usr/bin/env bash
# synadm, the Synapse admin CLI, against Spindle's /_synapse/admin alias:
# does tooling written for Synapse drive this server without a patch?
# Each command is run the way an operator runs it (`-o json --batch`), and
# the answer is checked for the fields the operator would read. A command
# whose endpoint this server does not serve is listed at the end as a gap
# rather than hidden in a failure.
#
#   contrib/synadm/run.sh
#
#   SPINDLE_BIN   the server (default target/debug/spindle)
#   OUT_DIR       where logs go (default tmp/synadm)
#
# Needs synadm (`pip install synadm==0.49.2`), curl, python3. Port 8008.
set -euo pipefail

SPINDLE_BIN="${SPINDLE_BIN:-target/debug/spindle}"
OUT_DIR="${OUT_DIR:-tmp/synadm}"
SERVER_NAME="localhost:8008"
S="http://127.0.0.1:8008"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
[[ -x $SPINDLE_BIN ]] || { echo "no server at $SPINDLE_BIN" >&2; exit 1; }
SPINDLE_BIN="$(cd "$(dirname "$SPINDLE_BIN")" && pwd)/$(basename "$SPINDLE_BIN")"

rig=$(mktemp -d "${TMPDIR:-/tmp}/spindle-synadm.XXXXXX")
spindle_pid=""
cleanup() { [[ -n $spindle_pid ]] && kill "$spindle_pid" 2>/dev/null || true; rm -rf "$rig"; }
trap cleanup EXIT
json() { python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get(sys.argv[1], d))' "$1"; }

# --- the server, an admin, a user, a room ------------------------------------
cat > "$rig/spindle.toml" <<TOML
[server]
name = "$SERVER_NAME"
bind = "127.0.0.1:8008"

[storage]
path = "$rig/data"

[ratelimit]
enabled = false
TOML
register() {
  curl -s -X POST "$S/_matrix/client/v3/register" -H 'content-type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"correct-horse-$1\",\"auth\":{\"type\":\"m.login.dummy\",\"session\":\"register\"}}"
}
start() {
  "$SPINDLE_BIN" "$rig/spindle.toml" >> "$OUT_DIR/spindle.log" 2>&1 &
  spindle_pid=$!
  for _ in $(seq 1 50); do curl -sf "$S/_matrix/client/versions" >/dev/null && break; sleep 0.2; done
  curl -sf "$S/_matrix/client/versions" >/dev/null || { echo "Spindle did not start; see $OUT_DIR/spindle.log" >&2; exit 1; }
}
start
register admin >/dev/null
ALICE="$(register alice | json access_token)"
ROOM="$(curl -s -X POST "$S/_matrix/client/v3/createRoom" -H "authorization: Bearer $ALICE" -H 'content-type: application/json' \
  -d '{"name":"Operations","preset":"public_chat"}' | json room_id)"
curl -s -X PUT "$S/_matrix/client/v3/rooms/$ROOM/send/m.room.message/t1" -H "authorization: Bearer $ALICE" \
  -H 'content-type: application/json' -d '{"msgtype":"m.text","body":"hello"}' >/dev/null
# The admin flag is minted offline, against the store, by the CLI: the
# server has to be down for that, as an operator's would be.
kill "$spindle_pid"; wait "$spindle_pid" 2>/dev/null || true; spindle_pid=""
"$SPINDLE_BIN" promote-admin "$rig/spindle.toml" admin
start
ADMIN="$(curl -s -X POST "$S/_matrix/client/v3/login" -H 'content-type: application/json' \
  -d '{"type":"m.login.password","identifier":{"type":"m.id.user","user":"admin"},"password":"correct-horse-admin"}' | json access_token)"

# --- synadm, configured the way its own `synadm config` writes it -------------
cat > "$rig/synadm.yaml" <<YAML
user: admin
token: $ADMIN
protocol: http
base_url: $S
admin_path: /_synapse/admin
matrix_path: /_matrix
format: json
timeout: 7
server_discovery: well-known
homeserver: $SERVER_NAME
ssl_verify: true
YAML
sa() { synadm -c "$rig/synadm.yaml" --batch -o json "$@"; }

pass=0; fail=0; gaps=()
# check <label> <python expression over d, the JSON answer> -- <synadm args>
check() {
  local label="$1" expr="$2"; shift 2; [[ $1 == -- ]] && shift
  local out
  if ! out="$(sa "$@" 2>"$rig/err")"; then
    if grep -q "404\|Not Found\|M_UNRECOGNIZED" "$rig/err"; then
      gaps+=("$label: synadm $*"); echo "gap   $label ($(head -c 120 "$rig/err" | tr '\n' ' '))"; return
    fi
    fail=$((fail+1)); echo "FAIL  $label: synadm $* -> $(head -c 300 "$rig/err" | tr '\n' ' ')"; return
  fi
  # synadm prints prose before some answers (the account before a modify,
  # a warning before a deactivate, the room before a delete); the answer
  # is the last JSON document in the output.
  if echo "$out" | python3 -c "
import sys, json
text = sys.stdin.read()
start = text.rfind('\n{')
d = json.loads(text[start + 1:] if start >= 0 else text)
sys.exit(0 if ($expr) else 1)" 2>/dev/null; then
    pass=$((pass+1)); echo "ok    $label"
  else
    fail=$((fail+1)); echo "FAIL  $label: $(echo "$out" | head -c 300 | tr '\n' ' ')"
  fi
}

check "version"              'd["server_version"].startswith("spindle")'      -- version
check "user list"            'any(u["name"]=="@alice:'"$SERVER_NAME"'" for u in d["users"])' -- user list
check "user details"         'd["name"]=="@alice:'"$SERVER_NAME"'" and d["admin"] is False'  -- user details "@alice:$SERVER_NAME"
# `--ids`: with aliases, synadm resolves each room's aliases through the
# client API as the admin, who is not a member, and this server answers a
# non-member's alias read with 403 where Synapse lets a server admin
# through. An interop gap to name, not to paper over here.
check "user membership"      '"'"$ROOM"'" in (d if isinstance(d, list) else d["joined_rooms"])' -- user membership --ids "@alice:$SERVER_NAME"
check "user whois"           'd["user_id"]=="@alice:'"$SERVER_NAME"'"'        -- user whois "@alice:$SERVER_NAME"
check "user modify (create)" 'd["name"]=="@carol:'"$SERVER_NAME"'" and d["displayname"]=="Carol"' -- user modify "@carol:$SERVER_NAME" --display-name Carol --password "correct-horse-carol"
check "user password"        'isinstance(d, dict)'                             -- user password "@carol:$SERVER_NAME" --password "new-horse" --no-logout
check "user deactivate"      'isinstance(d, dict)'                             -- user deactivate "@carol:$SERVER_NAME"
check "user list -d shows it" 'any(u["name"]=="@carol:'"$SERVER_NAME"'" and u["deactivated"] for u in d["users"])' -- user list -d
check "room list"            'any(r["room_id"]=="'"$ROOM"'" for r in d["rooms"])' -- room list
check "room details"         'd["room_id"]=="'"$ROOM"'" and d.get("name")=="Operations"' -- room details "$ROOM"
check "room members"         '"@alice:'"$SERVER_NAME"'" in d["members"]'      -- room members "$ROOM"
check "room state"           'any(e["type"]=="m.room.create" for e in d["state"])' -- room state "$ROOM"
check "room make-admin"      'isinstance(d, dict)'                             -- room make-admin "$ROOM" -u "@admin:$SERVER_NAME"
check "history purge"        'isinstance(d, dict)'                             -- history purge "$ROOM" --before-days 0 --delete-local
check "room delete"          'isinstance(d, dict)'                             -- room delete "$ROOM" --v1

echo
echo "synadm against Spindle: $pass ok, $fail failed, ${#gaps[@]} not served"
for g in "${gaps[@]:-}"; do [[ -n $g ]] && echo "  not served: $g"; done
[[ $fail -eq 0 ]]
