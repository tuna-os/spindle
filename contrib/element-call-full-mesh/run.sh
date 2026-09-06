#!/usr/bin/env bash
# Two people meet in a peer-to-peer call through Element Call's full-mesh
# build, on a Spindle that was empty a moment ago, with no SFU anywhere.
#
# Element Call's current line carries media through LiveKit only; its
# peer-to-peer implementation lives on the frozen `full-mesh` branch,
# built on matrix-js-sdk's MSC3401 group calls: membership as room state,
# WebRTC signalling over to-device messages, media straight between the
# browsers. That is the call a mesh needs when no SFU is reachable, and
# everything it asks of the homeserver this server already serves. This
# rig builds that branch, points it at a Spindle, and drives two browsers
# through a call with e2e.cjs.
#
#   contrib/element-call-full-mesh/run.sh
#
# Environment:
#   SPINDLE_BIN     the server binary (default: builds crates/spindle-server)
#   FULL_MESH_SRC   an existing checkout of the branch (default: clones the
#                   pin into tmp/element-call-full-mesh)
#   FULL_MESH_DIST  a prebuilt dist/ (default: builds it; needs node 22,
#                   yarn 1 and the git-reachable matrix-js-sdk pin)
#   NODE_PATH       where `require('playwright')` resolves (default: the
#                   node_modules of scripts/element-web-e2e; `npm ci` there
#                   installs the pinned version, `npx playwright install
#                   chromium` the browser)
#   OUT_DIR         screenshots and logs (default: tmp/element-call-full-mesh)
#   HS_PORT         Spindle's port (default 8299); WEB_PORT the app's (8298)
#   NEUTRINO_LAN    a neutrino-lan binary (contrib/neutrino, both patches):
#                   with it set, the call crosses the mesh seam. A node
#                   starts beside the Spindle, a second copy of the app is
#                   served with the node as its homeserver, the creator is
#                   on the node and the joiner on the Spindle, and the
#                   room is the node's, in the version it speaks.
set -euo pipefail

# The last commit of the full-mesh branch (2023-07), pinned so an upstream
# force-push cannot repaint the result.
FULL_MESH_REV=ec810cde5eed90fdb0b9685645eadd3a5f55a6a2

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"

HS_PORT=${HS_PORT:-8299}
WEB_PORT=${WEB_PORT:-8298}
SERVER_NAME=fullmesh.local
OUT_DIR=${OUT_DIR:-tmp/element-call-full-mesh}
export NODE_PATH=${NODE_PATH:-$root/scripts/element-web-e2e/node_modules}
mkdir -p "$OUT_DIR" tmp
OUT_DIR=$(cd "$OUT_DIR" && pwd)

if [[ -z ${SPINDLE_BIN:-} ]]; then
  cargo build -q -p spindle-server --bin spindle
  SPINDLE_BIN=target/debug/spindle
fi

# --- the client -------------------------------------------------------------
if [[ -z ${FULL_MESH_DIST:-} ]]; then
  FULL_MESH_SRC=${FULL_MESH_SRC:-tmp/element-call-full-mesh}
  if [[ ! -d $FULL_MESH_SRC/.git ]]; then
    git clone --quiet https://github.com/element-hq/element-call.git "$FULL_MESH_SRC"
  fi
  git -C "$FULL_MESH_SRC" fetch --quiet origin "$FULL_MESH_REV"
  git -C "$FULL_MESH_SRC" checkout --quiet "$FULL_MESH_REV"
  # The branch names its matrix-js-sdk pin as a GitHub tarball; a git URL
  # reaches the same commit where tarball downloads are not allowed.
  sed -i 's#"matrix-js-sdk": "github:matrix-org/matrix-js-sdk\#\([0-9a-f]*\)"#"matrix-js-sdk": "git+https://github.com/matrix-org/matrix-js-sdk.git\#\1"#' \
    "$FULL_MESH_SRC/package.json"
  (cd "$FULL_MESH_SRC" && yarn install --non-interactive --network-timeout 600000 \
    && NODE_OPTIONS=--max-old-space-size=6144 npx vite build) > "$OUT_DIR/build.log" 2>&1 \
    || { echo "the full-mesh build failed; see $OUT_DIR/build.log" >&2; exit 1; }
  FULL_MESH_DIST=$FULL_MESH_SRC/dist
fi
# This Spindle as the only homeserver.
cat > "$FULL_MESH_DIST/config.json" <<JSON
{
  "default_server_config": {
    "m.homeserver": { "base_url": "http://127.0.0.1:$HS_PORT", "server_name": "$SERVER_NAME" }
  }
}
JSON

# --- the servers ------------------------------------------------------------
store=$(mktemp -d "${TMPDIR:-/tmp}/spindle-fullmesh.XXXXXX")
pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do
    [[ -n $pid ]] && kill "$pid" 2>/dev/null || true
  done
  rm -rf "$store"
}
trap cleanup EXIT

NODE=""
NODE_PORT=${NODE_PORT:-8101}
WEB_PORT_B=${WEB_PORT_B:-8297}
if [[ -n ${NEUTRINO_LAN:-} ]]; then
  mkdir -p "$store/neutrino"
  "$NEUTRINO_LAN" --bind "127.0.0.1:$NODE_PORT" --storage "$store/neutrino" --fed-port 8449 \
    --relay-bind 127.0.0.2:0 > "$OUT_DIR/neutrino.log" 2>&1 &
  pids+=($!)
  for _ in $(seq 1 60); do
    NODE="$(grep -oE '^[0-9a-f]{64}$' "$OUT_DIR/neutrino.log" 2>/dev/null | head -1 || true)"
    [[ ${#NODE} -eq 64 ]] && curl -sf "http://127.0.0.1:$NODE_PORT/_matrix/client/versions" >/dev/null 2>&1 && break
    sleep 0.5
  done
  [[ ${#NODE} -eq 64 ]] || { echo "neutrino-lan did not start; see $OUT_DIR/neutrino.log" >&2; exit 1; }
  # A second copy of the app with the node as its homeserver.
  rm -rf "$store/dist-node" && cp -r "$FULL_MESH_DIST" "$store/dist-node"
  cat > "$store/dist-node/config.json" <<JSON
{
  "default_server_config": {
    "m.homeserver": { "base_url": "http://127.0.0.1:$NODE_PORT", "server_name": "$NODE" }
  }
}
JSON
fi

# The Spindle is a mesh peer of the node when there is one: its name is
# a loopback address (a node dials names directly with the gateway
# patch) and the node is listed under peers at its loopback URL.
if [[ -n $NODE ]]; then
  SERVER_NAME="127.0.0.1:$HS_PORT"
  cat > "$FULL_MESH_DIST/config.json" <<JSON
{
  "default_server_config": {
    "m.homeserver": { "base_url": "http://127.0.0.1:$HS_PORT", "server_name": "$SERVER_NAME" }
  }
}
JSON
fi
cat > "$store/spindle.toml" <<TOML
[server]
name = "$SERVER_NAME"
bind = "127.0.0.1:$HS_PORT"

[storage]
path = "$store/data"

[ratelimit]
enabled = false
TOML
if [[ -n $NODE ]]; then
  cat >> "$store/spindle.toml" <<TOML

[federation]
insecure_http = true
allow_internal = ["127.0.0.0/8"]
retry_base_ms = 200
peers = { "$NODE" = { url = "http://127.0.0.1:$NODE_PORT", max_backoff_ms = 5000 } }
TOML
fi

"$SPINDLE_BIN" "$store/spindle.toml" > "$OUT_DIR/spindle.log" 2>&1 &
pids+=($!)
# A single-page app: every path serves index.html, which is what the
# `/room/…` and `/<call-name>` links need.
cat > "$store/spa.py" <<'PY'
import http.server, os, sys
class Spa(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?', 1)[0].split('#', 1)[0].lstrip('/')
        if path and not os.path.exists(path):
            self.path = '/index.html'
        return super().do_GET()
    def log_message(self, *args):
        pass
http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), Spa).serve_forever()
PY
(cd "$FULL_MESH_DIST" && exec python3 "$store/spa.py" "$WEB_PORT") > "$OUT_DIR/web.log" 2>&1 &
pids+=($!)
if [[ -n $NODE ]]; then
  (cd "$store/dist-node" && exec python3 "$store/spa.py" "$WEB_PORT_B") > "$OUT_DIR/web-node.log" 2>&1 &
  pids+=($!)
fi

up() { curl -sf -o /dev/null "$1"; }
for _ in $(seq 1 50); do
  up "http://127.0.0.1:$HS_PORT/_matrix/client/versions" && up "http://127.0.0.1:$WEB_PORT/config.json" && break
  sleep 0.2
done
up "http://127.0.0.1:$HS_PORT/_matrix/client/versions" || { echo "spindle did not come up; see $OUT_DIR/spindle.log" >&2; exit 1; }
up "http://127.0.0.1:$WEB_PORT/config.json" || { echo "the static server did not come up; see $OUT_DIR/web.log" >&2; exit 1; }

# --- the call ---------------------------------------------------------------
if [[ -n $NODE ]]; then
  for _ in $(seq 1 50); do up "http://127.0.0.1:$WEB_PORT_B/config.json" && break; sleep 0.2; done
  echo "the creator is on the mesh node $NODE, the joiner on the Spindle"
  WEB_URL="http://127.0.0.1:$WEB_PORT" WEB_URL_CREATOR="http://127.0.0.1:$WEB_PORT_B" \
    CREATOR_SERVER="$NODE" OUT_DIR="$OUT_DIR" node "$here/e2e.cjs"
else
  WEB_URL="http://127.0.0.1:$WEB_PORT" OUT_DIR="$OUT_DIR" node "$here/e2e.cjs"
fi
