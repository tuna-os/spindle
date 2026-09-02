#!/usr/bin/env bash
# Two people meet in a room through Element Web, on a Spindle that was empty
# a moment ago (docs/conformance-testing.md, section 4.1).
#
# Starts a Spindle on a throwaway store, serves a pinned Element Web release
# pointed at it, and drives two browsers through e2e.cjs: register, log in,
# create a room, invite, accept, a message each way, leave. Everything it
# starts is stopped on exit, and every screenshot lands in $OUT_DIR.
#
#   scripts/element-web-e2e/run.sh
#
# Environment:
#   SPINDLE_BIN   the server binary (default: builds crates/spindle-server)
#   NODE_PATH     where `require('playwright')` resolves (default: the
#                 node_modules next to this script; `npm ci` there installs
#                 the pinned version, `npx playwright install chromium` the
#                 browser)
#   OUT_DIR       screenshots and logs (default: tmp/element-web-e2e)
#   HS_PORT       Spindle's port (default 8199); WEB_PORT Element's (8198)
#
# Element Web is a release tarball, pinned by tag and by digest, cached in
# tmp/element-web so a second run downloads nothing.
set -euo pipefail

ELEMENT_TAG=v1.11.112
ELEMENT_SHA256=0231387379f6e81d41718dd87d866d2e4168de0f4b1c9dbe0791e388e8e1dd2a

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"

HS_PORT=${HS_PORT:-8199}
WEB_PORT=${WEB_PORT:-8198}
SERVER_NAME=e2e.local
OUT_DIR=${OUT_DIR:-tmp/element-web-e2e}
export NODE_PATH=${NODE_PATH:-$here/node_modules}
mkdir -p "$OUT_DIR" tmp/element-web
OUT_DIR=$(cd "$OUT_DIR" && pwd)

if [[ -z ${SPINDLE_BIN:-} ]]; then
  cargo build -q -p spindle-server --bin spindle
  SPINDLE_BIN=target/debug/spindle
fi

# --- Element Web ------------------------------------------------------------
tarball=tmp/element-web/element-$ELEMENT_TAG.tar.gz
webroot=tmp/element-web/element-$ELEMENT_TAG
if [[ ! -f $tarball ]]; then
  curl -sSfL --retry 3 -o "$tarball" \
    "https://github.com/element-hq/element-web/releases/download/$ELEMENT_TAG/element-$ELEMENT_TAG.tar.gz"
fi
echo "$ELEMENT_SHA256  $tarball" | sha256sum -c --quiet
if [[ ! -f $webroot/config.sample.json ]]; then
  tar -xzf "$tarball" -C tmp/element-web
fi
# The sample config, with this Spindle as the only homeserver. Custom URLs
# and guests are off so the client cannot wander to matrix.org, and the
# integration manager is removed so it does not phone scalar.vector.im.
python3 - "$webroot" "$HS_PORT" "$SERVER_NAME" <<'PY'
import json, sys
webroot, port, name = sys.argv[1], sys.argv[2], sys.argv[3]
c = json.load(open(f"{webroot}/config.sample.json"))
c["default_server_config"] = {"m.homeserver": {"base_url": f"http://127.0.0.1:{port}", "server_name": name}}
c["disable_custom_urls"] = True
c["disable_guests"] = True
for k in ("integrations_ui_url", "integrations_rest_url", "integrations_widgets_urls"):
    c.pop(k, None)
json.dump(c, open(f"{webroot}/config.json", "w"), indent=1)
PY

# --- servers ----------------------------------------------------------------
store=$(mktemp -d "${TMPDIR:-/tmp}/spindle-e2e.XXXXXX")
cat > "$store/spindle.toml" <<TOML
[server]
name = "$SERVER_NAME"
bind = "127.0.0.1:$HS_PORT"

[storage]
path = "$store/data"

[ratelimit]
enabled = false
TOML

pids=()
cleanup() {
  for pid in "${pids[@]:-}"; do
    [[ -n $pid ]] && kill "$pid" 2>/dev/null || true
  done
  rm -rf "$store"
}
trap cleanup EXIT

"$SPINDLE_BIN" "$store/spindle.toml" > "$OUT_DIR/spindle.log" 2>&1 &
pids+=($!)
(cd "$webroot" && exec python3 -m http.server --bind 127.0.0.1 "$WEB_PORT") > "$OUT_DIR/web.log" 2>&1 &
pids+=($!)

up() { curl -sf -o /dev/null "$1"; }
hs="http://127.0.0.1:$HS_PORT/_matrix/client/versions"
web="http://127.0.0.1:$WEB_PORT/config.json"
for _ in $(seq 1 50); do
  up "$hs" && up "$web" && break
  sleep 0.2
done
up "$hs" || { echo "spindle did not come up; see $OUT_DIR/spindle.log" >&2; exit 1; }
up "$web" || { echo "the static server did not come up; see $OUT_DIR/web.log" >&2; exit 1; }

# --- the flow ---------------------------------------------------------------
WEB_URL="http://127.0.0.1:$WEB_PORT" OUT_DIR="$OUT_DIR" SERVER_NAME="$SERVER_NAME" \
  node "$here/e2e.cjs"
