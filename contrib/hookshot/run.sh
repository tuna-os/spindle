#!/usr/bin/env bash
# A real bridge against Spindle: matrix-hookshot, through the Application
# Service API, doing what a bridge does -- register, be invited, join,
# answer a command, provision a ghost user in its namespace, and relay an
# outside event into the room. Generic webhooks are the feature, because
# they need nothing outside this rig: no GitHub, no IRC server, only an
# HTTP POST to the URL the bot hands back.
#
#   contrib/hookshot/run.sh
#
#   SPINDLE_BIN      the server (default target/release/spindle)
#   HOOKSHOT_IMAGE   the bridge (default: the pinned release below)
#   OUT_DIR          where logs go (default tmp/hookshot)
#
# Needs docker (the bridge runs as a container on the host network),
# curl, python3, openssl. Ports 8008, 9993 and 9723 on loopback.
#
# What it proves, in order, and fails on:
#   1. the registration loads and the bridge's transaction endpoint answers
#   2. the bot joins a room it is invited to (an inbound transaction
#      carried the invite, the bridge acted on it through the client API
#      with its as_token)
#   3. `!hookshot webhook ci-hook` gets an answer: the bot opens an admin room,
#      invites alice into it, and hands over the webhook URL there (its
#      real flow; the URL is a secret and the bridged room may be public)
#   4. a POST to that URL lands in the room as a message from the
#      webhook's ghost user, `@_webhook_ci-hook:<server>`, a user the bridge
#      minted in its exclusive namespace
#   5. the bridge restarted comes back with the connection it stored as
#      room state on the homeserver, and the same URL still routes
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
SPINDLE_BIN="${SPINDLE_BIN:-target/release/spindle}"
HOOKSHOT_IMAGE="${HOOKSHOT_IMAGE:-ghcr.io/matrix-org/matrix-hookshot:7.4.4}"
OUT_DIR="${OUT_DIR:-tmp/hookshot}"
SERVER_NAME="hookshot.test"
S="http://127.0.0.1:8008"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
[[ -x $SPINDLE_BIN ]] || { echo "no server at $SPINDLE_BIN" >&2; exit 1; }
SPINDLE_BIN="$(cd "$(dirname "$SPINDLE_BIN")" && pwd)/$(basename "$SPINDLE_BIN")"

rig=$(mktemp -d "${TMPDIR:-/tmp}/spindle-hookshot.XXXXXX")
mkdir -p "$rig/hookshot" "$rig/data"
chmod 777 "$rig/hookshot"
container=""
spindle_pid=""
cleanup() {
  [[ -n $container ]] && { docker logs "$container" > "$OUT_DIR/hookshot.log" 2>&1 || true; docker rm -f "$container" >/dev/null 2>&1 || true; }
  [[ -n $spindle_pid ]] && kill "$spindle_pid" 2>/dev/null || true
  rm -rf "$rig"
}
trap cleanup EXIT

json() { python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get(sys.argv[1], d))' "$1"; }
rnd() { openssl rand -hex 32; }
step() { echo "--- $1"; }

# --- the bridge's papers ------------------------------------------------------
AS_TOKEN="$(rnd)"; HS_TOKEN="$(rnd)"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$rig/hookshot/passkey.pem" 2>/dev/null
cat > "$rig/hookshot/registration.yml" <<YAML
id: hookshot
as_token: $AS_TOKEN
hs_token: $HS_TOKEN
namespaces:
  rooms: []
  users:
    - regex: "@_webhook_.*:$SERVER_NAME"
      exclusive: true
    - regex: "@hookshot:$SERVER_NAME"
      exclusive: true
  aliases: []
sender_localpart: hookshot
url: "http://127.0.0.1:9993"
rate_limited: false
de.sorunome.msc2409.push_ephemeral: true
YAML
cat > "$rig/hookshot/config.yml" <<YAML
bridge:
  domain: $SERVER_NAME
  url: $S
  mediaUrl: $S
  port: 9993
  bindAddress: 127.0.0.1
passFile: /data/passkey.pem
generic:
  enabled: true
  urlPrefix: http://127.0.0.1:9723/webhook/
  userIdPrefix: _webhook_
  allowJsTransformationFunctions: false
  waitForComplete: true
listeners:
  - port: 9723
    bindAddress: 127.0.0.1
    resources:
      - webhooks
permissions:
  - actor: "*"
    services:
      - service: "*"
        level: admin
logging:
  level: info
  json: false
  colorize: false
YAML
chmod 644 "$rig/hookshot/"*

# --- the server, with the bridge registered -----------------------------------
cat > "$rig/spindle.toml" <<TOML
[server]
name = "$SERVER_NAME"
bind = "127.0.0.1:8008"

[storage]
path = "$rig/data"

[ratelimit]
enabled = false

[appservices]
registrations = ["$rig/hookshot/registration.yml"]
TOML
"$SPINDLE_BIN" "$rig/spindle.toml" > "$OUT_DIR/spindle.log" 2>&1 &
spindle_pid=$!
for _ in $(seq 1 50); do curl -sf "$S/_matrix/client/versions" >/dev/null && break; sleep 0.2; done
curl -sf "$S/_matrix/client/versions" >/dev/null || { echo "Spindle did not start; see $OUT_DIR/spindle.log" >&2; exit 1; }

# --- the bridge -------------------------------------------------------------------
step "the bridge starts against the registration"
container="$(docker run -d --network host -v "$rig/hookshot:/data" "$HOOKSHOT_IMAGE")"
# Ready means the bridge's own appservice port answers: it opens once the
# registration is read and the homeserver connection is up. The webhook
# listener is probed too, since that is the feature under test. Neither
# probe may be fatal on its own (a `$(...)` assignment is, under set -e),
# and the loop must not trust a port something else on the host answers.
bridge_up() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' -X PUT "http://127.0.0.1:9993/_matrix/app/v1/transactions/probe" \
    -H "authorization: Bearer $HS_TOKEN" -H 'content-type: application/json' -d '{"events":[]}' || true)"
  [[ $code == 2* ]] && curl -s -o /dev/null "http://127.0.0.1:9723/" 2>/dev/null
}
for _ in $(seq 1 120); do
  bridge_up && break
  sleep 1
done
bridge_up || { echo "the bridge never came up" >&2; docker logs "$container" | tail -40 >&2; exit 1; }
echo "the bridge's transaction endpoint answers, and its webhook listener is up"

# --- a user, a room, the bot ----------------------------------------------------
step "alice invites the bot and it joins"
REG="$(curl -s -X POST "$S/_matrix/client/v3/register" -H 'content-type: application/json' \
  -d '{"username":"alice","password":"correct-horse","auth":{"type":"m.login.dummy","session":"register"}}')"
TOK="$(echo "$REG" | json access_token)"
ROOM="$(curl -s -X POST "$S/_matrix/client/v3/createRoom" -H "authorization: Bearer $TOK" -H 'content-type: application/json' \
  -d "{\"name\":\"bridged\",\"preset\":\"private_chat\",\"invite\":[\"@hookshot:$SERVER_NAME\"],\"power_level_content_override\":{\"users\":{\"@alice:$SERVER_NAME\":100,\"@hookshot:$SERVER_NAME\":50}}}" | json room_id)"
[[ $ROOM == !* ]] || { echo "no room: $ROOM" >&2; exit 1; }
joined=""
for _ in $(seq 1 60); do
  M="$(curl -s "$S/_matrix/client/v3/rooms/$ROOM/members?membership=join" -H "authorization: Bearer $TOK")"
  echo "$M" | grep -q "@hookshot:$SERVER_NAME" && joined=yes && break
  sleep 0.5
done
[[ -n $joined ]] || { echo "the bot never joined; last members: $(echo "$M" | head -c 300)" >&2; docker logs "$container" | tail -40 >&2; exit 1; }
echo "@hookshot:$SERVER_NAME is joined"

# --- the command, and the URL it answers with -----------------------------------
step "alice asks for a webhook"
curl -s -X PUT "$S/_matrix/client/v3/rooms/$ROOM/send/m.room.message/cmd1" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' -d '{"msgtype":"m.text","body":"!hookshot webhook ci-hook"}' >/dev/null
# The bot answers by opening an admin room and inviting alice into it;
# the invite shows up in her sync. Join every room the bot invites her to
# and look for the URL in all of them, the bridged room included.
find_url() {
  python3 -c '
import sys, json, re
d = json.load(sys.stdin)
for e in d.get("chunk", []):
    if e.get("sender", "").startswith("@hookshot:") and e.get("type") == "m.room.message":
        c = e["content"]
        m = re.search(r"https?://[^\s\"<>]+/webhook/[A-Za-z0-9_-]+", c.get("body", "") + " " + c.get("formatted_body", ""))
        if m:
            print(m.group(0)); break
'
}
URL=""
ADMIN_ROOMS=()
for _ in $(seq 1 90); do
  SYNC="$(curl -s "$S/_matrix/client/v3/sync?timeout=0" -H "authorization: Bearer $TOK")"
  for invited in $(echo "$SYNC" | python3 -c 'import sys,json; print(" ".join(json.load(sys.stdin).get("rooms",{}).get("invite",{}).keys()))'); do
    curl -s -X POST "$S/_matrix/client/v3/join/$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$invited")" \
      -H "authorization: Bearer $TOK" -H 'content-type: application/json' -d '{}' >/dev/null
    ADMIN_ROOMS+=("$invited")
    echo "joined the room the bot opened: $invited"
  done
  for r in "$ROOM" "${ADMIN_ROOMS[@]:-}"; do
    [[ -n $r ]] || continue
    MSGS="$(curl -s "$S/_matrix/client/v3/rooms/$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$r")/messages?dir=b&limit=30" -H "authorization: Bearer $TOK")"
    URL="$(echo "$MSGS" | find_url)"
    [[ -n $URL ]] && break 2
  done
  sleep 0.5
done
[[ -n $URL ]] || { echo "no webhook URL from the bot; last messages: $(echo "$MSGS" | head -c 600)" >&2; docker logs "$container" | tail -40 >&2; exit 1; }
echo "the bot handed over $URL"

# --- the outside world knocks -------------------------------------------------
step "a webhook fires into the room"
CODE="$(curl -s -o "$rig/hook.out" -w '%{http_code}' -X POST "$URL" -H 'content-type: application/json' -d '{"text":"hello from the outside"}' || true)"
echo "POST $URL -> $CODE $(head -c 120 "$rig/hook.out")"
landed=""
for _ in $(seq 1 60); do
  MSGS="$(curl -s "$S/_matrix/client/v3/rooms/$ROOM/messages?dir=b&limit=20" -H "authorization: Bearer $TOK")"
  landed="$(echo "$MSGS" | python3 -c '
import sys, json
d = json.load(sys.stdin)
for e in d.get("chunk", []):
    if e.get("type") == "m.room.message" and "hello from the outside" in e["content"].get("body", ""):
        print(e["sender"]); break
')"
  [[ -n $landed ]] && break
  sleep 0.5
done
[[ -n $landed ]] || { echo "the webhook's message never reached the room" >&2; docker logs "$container" | tail -60 >&2; exit 1; }
echo "the message arrived from $landed"
case "$landed" in
  "@_webhook_"*":$SERVER_NAME") echo "a ghost in the bridge's exclusive namespace, minted by the bridge" ;;
  *) echo "sent by $landed, not a namespace ghost" >&2; exit 1 ;;
esac

# --- the bridge restarts, and remembers ----------------------------------------
step "the bridge restarts and the same URL still routes"
docker restart "$container" >/dev/null
for _ in $(seq 1 120); do bridge_up && break; sleep 1; done
CODE=""
for _ in $(seq 1 30); do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL" -H 'content-type: application/json' -d '{"text":"still here after a restart"}' || true)"
  [[ $CODE == 2* ]] && break
  sleep 1
done
echo "POST after restart -> $CODE"
again=""
for _ in $(seq 1 60); do
  MSGS="$(curl -s "$S/_matrix/client/v3/rooms/$ROOM/messages?dir=b&limit=20" -H "authorization: Bearer $TOK")"
  echo "$MSGS" | grep -q "still here after a restart" && again=yes && break
  sleep 0.5
done
[[ -n $again ]] || { echo "after the restart the webhook no longer reaches the room" >&2; docker logs "$container" | tail -60 >&2; exit 1; }
echo "the connection survived the restart: it was stored as room state on the homeserver"
echo "hookshot bridge: ok"
