#!/usr/bin/env bash
# Start the Spindle service from deploy/compose/compose.yaml and drive it
# through the first things an operator does (#825): wait for /health,
# register, log in, create a room and send a message. It keeps the files
# under deploy/ from rotting in a way that a render check cannot see.
#
#   scripts/deploy-smoke.sh                       # builds the repo Dockerfile
#   SPINDLE_IMAGE=ghcr.io/tuna-os/spindle:v0.1.0 scripts/deploy-smoke.sh
#
# Needs docker with the compose plugin, curl and jq. Caddy is not started:
# it only adds TLS, and the test talks to Spindle's HTTP port.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
port=${SMOKE_PORT:-18008}
base="http://127.0.0.1:${port}"
work=$(mktemp -d)
export SPINDLE_IMAGE=${SPINDLE_IMAGE:-spindle-deploy-smoke:local}
# The Compose file requires this for Caddy even when Caddy is not started.
export SPINDLE_DOMAIN=localhost
export COMPOSE_PROJECT_NAME=spindle-smoke

compose() {
  docker compose -f "$work/compose.yaml" -f "$work/override.yaml" "$@"
}

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    compose logs --no-color spindle 2>&1 | tail -n 100 || true
  fi
  compose down --volumes --timeout 30 >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT

step() { printf '== %s\n' "$*"; }

# The Compose file as shipped, with two changes the test needs: the config
# opens registration and names the host the test uses, and the port is
# published on loopback (in production only Caddy publishes one).
cp "$root/deploy/compose/compose.yaml" "$work/compose.yaml"
sed -e 's|^name = .*|name = "localhost"|' \
    -e "s|^public_base_url = .*|public_base_url = \"${base}\"|" \
    -e 's|^require_token = .*|require_token = false|' \
    "$root/deploy/compose/spindle.toml" > "$work/spindle.toml"
for key in 'name = "localhost"' 'require_token = false'; do
  grep -qF "$key" "$work/spindle.toml" || { echo "smoke config edit did not apply: $key" >&2; exit 1; }
done
cat > "$work/override.yaml" <<YAML
services:
  spindle:
    ports:
      - "127.0.0.1:${port}:8008"
YAML

if [ -z "$(docker image ls -q "$SPINDLE_IMAGE" 2>/dev/null)" ]; then
  step "build $SPINDLE_IMAGE from the Dockerfile"
  docker build -t "$SPINDLE_IMAGE" "$root"
fi

step "start spindle"
compose up -d --no-deps spindle

step "wait for /health"
for _ in $(seq 1 60); do
  if curl -fsS "$base/health" >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "${ready:-0}" = 1 ] || { echo "/health did not answer in 60 s" >&2; exit 1; }

# `--fail-with-body` prints the Matrix error when a call is refused.
api() { curl -sS --fail-with-body "$@"; }

step "register"
user="smoke$RANDOM"
password="correct-horse-$RANDOM-battery"
register=$(api -X POST "$base/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$user" --arg p "$password" \
        '{username:$u,password:$p,auth:{type:"m.login.dummy"}}')")
user_id=$(jq -er .user_id <<<"$register")
[ "$user_id" = "@${user}:localhost" ] || { echo "unexpected user id $user_id" >&2; exit 1; }

step "log in"
login=$(api -X POST "$base/_matrix/client/v3/login" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$user" --arg p "$password" \
        '{type:"m.login.password",identifier:{type:"m.id.user",user:$u},password:$p}')")
token=$(jq -er .access_token <<<"$login")

step "create a room"
room=$(api -X POST "$base/_matrix/client/v3/createRoom" \
  -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"name":"deploy smoke"}')
room_id=$(jq -er .room_id <<<"$room")
room_path=${room_id//!/%21}

step "send a message"
sent=$(api -X PUT "$base/_matrix/client/v3/rooms/${room_path}/send/m.room.message/smoke-1" \
  -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"msgtype":"m.text","body":"hello from the deploy smoke test"}')
event_id=$(jq -er .event_id <<<"$sent")

step "read the message back"
event=$(api "$base/_matrix/client/v3/rooms/${room_path}/event/${event_id//\$/%24}" \
  -H "Authorization: Bearer $token")
[ "$(jq -er .content.body <<<"$event")" = "hello from the deploy smoke test" ]

step "ok: $user_id sent $event_id in $room_id"
