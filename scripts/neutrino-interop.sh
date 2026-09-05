#!/usr/bin/env bash
# Probe a Spindle against a real Neutrino mesh node on loopback.
#
#   NEUTRINO_LAN=/path/to/neutrino-lan scripts/neutrino-interop.sh
#
# Starts one `neutrino-lan` node (the companion project's LAN build of
# Element's P2P homeserver, from hanthor/neutrino-iroh) and one Spindle
# whose `[federation] peers` names the node at its loopback URL, then runs
# the probes docs/mesh-federation.md reports on, in both directions, and
# prints a table. Nothing here asserts: the point is to see exactly where
# the two stop understanding each other today, so that every convergence
# step on either side can be measured against the same rig.
#
# Needs: a release Spindle (`cargo build --release -p spindle-server`),
# curl, python3, and NEUTRINO_LAN. Ports 8008 and 8101 on loopback.
set -eu -o pipefail

NEUTRINO_LAN="${NEUTRINO_LAN:?set NEUTRINO_LAN to a neutrino-lan binary}"
SPINDLE_BIN="${SPINDLE_BIN:-target/release/spindle}"
RIG="$(mktemp -d -t neutrino-interop-XXXXXX)"
S=http://127.0.0.1:8008
N=http://127.0.0.1:8101
PIDS=""
trap 'kill $PIDS 2>/dev/null; echo "rig kept at $RIG"' EXIT

mkdir -p "$RIG/neutrino" "$RIG/spindle"
"$NEUTRINO_LAN" --bind 127.0.0.1:8101 --storage "$RIG/neutrino" --fed-port 8449 \
  --relay-bind 127.0.0.2:0 > "$RIG/neutrino.log" 2>&1 &
PIDS="$PIDS $!"
NODE=""
for _ in $(seq 1 60); do
  NODE="$(grep -oE '^[0-9a-f]{64}$' "$RIG/neutrino.log" 2>/dev/null | head -1 || true)"
  [ ${#NODE} -eq 64 ] && curl -sf "$N/_matrix/client/versions" >/dev/null 2>&1 && break
  sleep 0.5
done
[ ${#NODE} -eq 64 ] || { echo "neutrino-lan did not start; see $RIG/neutrino.log"; exit 1; }

cat > "$RIG/spindle.toml" <<TOML
[server]
name = "127.0.0.1:8008"
bind = "127.0.0.1:8008"
[storage]
path = "$RIG/spindle/data"
[ratelimit]
enabled = false
[federation]
insecure_http = true
allow_internal = ["127.0.0.0/8"]
retry_base_ms = 200
peers = { "$NODE" = { url = "$N", max_backoff_ms = 5000 } }
TOML
"$SPINDLE_BIN" "$RIG/spindle.toml" > "$RIG/spindle.log" 2>&1 &
PIDS="$PIDS $!"
for _ in $(seq 1 60); do curl -sf "$S/_matrix/client/versions" >/dev/null 2>&1 && break; sleep 0.5; done

json() { python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get(sys.argv[1], d))' "$1"; }
row() { printf '| %-52s | %-12s | %s\n' "$1" "$2" "$3"; }

echo "| probe | outcome | detail"
echo "|---|---|---|"

# The node's key document, as Spindle fetches it.
KEYS="$(curl -s "$N/_matrix/key/v2/server")"
row "mesh node key document at its loopback URL" "$(echo "$KEYS" | grep -q verify_keys && echo served || echo missing)" \
  "server_name is the node id; key ed25519:1"

TOK="$(curl -s -X POST "$S/_matrix/client/v3/register" -H 'content-type: application/json' \
  -d '{"username":"alice","password":"hunter2","auth":{"type":"m.login.dummy","session":"s"}}' | json access_token)"
ROOM="$(curl -s -X POST "$S/_matrix/client/v3/createRoom" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' -d '{"name":"Interop","room_version":"12"}' | json room_id)"

# 1. Spindle invites the mesh user into a v12 room.
OUT="$(curl -s -X POST "$S/_matrix/client/v3/rooms/$ROOM/invite" -H "authorization: Bearer $TOK" \
  -H 'content-type: application/json' -d "{\"user_id\":\"@n:$NODE\"}")"
row "Spindle invites @n:<node> into a v12 room" "$(echo "$OUT" | grep -q errcode && echo refused || echo accepted)" \
  "$(echo "$OUT" | grep -o 'M_INCOMPATIBLE_ROOM_VERSION[^}]*' | head -c 120)"

# 2. The mesh node invites the Spindle user.
NROOM="$(curl -s -X POST "$N/_matrix/client/v3/createRoom" -H 'content-type: application/json' -d '{"name":"Mesh"}' | json room_id)"
START=$(date +%s)
OUT="$(curl -s -X POST "$N/_matrix/client/v3/rooms/$NROOM/invite" -H 'content-type: application/json' \
  -d '{"user_id":"@alice:127.0.0.1:8008"}')"
# Unpatched fork: the request goes to the egress as http://127.0.0.1~:8008 and
# the link cannot address a name (60 s, then 502). With contrib/neutrino applied
# the node dials Spindle directly and signs the request; Spindle authenticates
# it (a bad signature would be 401) and refuses the room version (400).
PEER="$(grep -o 'peer returned non-2xx.*' "$RIG/neutrino.log" | head -1 | sed 's/\x1b\[[0-9;]*m//g' | grep -o 'status.*' | head -c 110 || true)"
UNROUTED="$(grep -o 'error sending request for url ([^)]*' "$RIG/neutrino.log" | head -1 | head -c 90 || true)"
row "mesh node invites @alice:<spindle>" "$(echo "$OUT" | grep -q errcode && echo refused || echo accepted)" \
  "after $(( $(date +%s) - START )) s; ${PEER:-$UNROUTED}"

# 3. An alias on the mesh node, resolved by Spindle over federation.
AROOM="$(curl -s -X POST "$N/_matrix/client/v3/createRoom" -H 'content-type: application/json' -d '{"name":"Aliased"}' | json room_id)"
ALIAS="%23mesh-session-1:$NODE"
curl -s -X PUT "$N/_matrix/client/v3/directory/room/$ALIAS" -H 'content-type: application/json' -d "{\"room_id\":\"$AROOM\"}" >/dev/null
OUT="$(curl -s "$S/_matrix/client/v3/directory/room/$ALIAS" -H "authorization: Bearer $TOK")"
row "Spindle resolves #mesh-session-1:<node> over federation" "$(echo "$OUT" | grep -q room_id && echo resolved || echo failed)" \
  "$(echo "$OUT" | head -c 80)"

# 4. The mesh node's federation directory endpoint, with no authorization at all.
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$N/_matrix/federation/v1/query/directory?room_alias=$ALIAS")"
row "mesh node answers federation query with no X-Matrix header" "$CODE" "inbound federation requests are not verified"

# 5. Spindle's own key document, as the mesh node would need to fetch it.
CODE="$(curl -s -o /dev/null -w '%{http_code}' "$S/_matrix/key/v2/server")"
row "Spindle key document over plain http" "$CODE" "what an HTTP KeyResolver on the gateway would fetch"
