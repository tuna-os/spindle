#!/usr/bin/env bash
#
# Bring up all four servers of a four-way sitting on loopback, cold, with
# every rate limit the competitors expose lifted, and leave them running
# for `bench-rounds.sh`. `down` stops them.
#
#   BENCH_BIN=/path/with/continuwuity/and/tuwunel SYNAPSE_VENV=/path/to/venv \
#     scripts/bench-four-way.sh up
#   scripts/bench-rounds.sh --group m7-progress --rounds 3 \
#       --server spindle=http://127.0.0.1:8099 --server synapse=http://127.0.0.1:8098 \
#       --server continuwuity=http://127.0.0.1:8097 --server tuwunel=http://127.0.0.1:8096 \
#       --registration-token continuwuity=benchtoken --registration-token tuwunel=benchtoken
#   scripts/bench-four-way.sh down
#
# Committed because the M7 sitting lost most of an evening to details that
# had all been solved once before and written down nowhere: see the notes
# inline. Expects `target/release/spindle` to exist; the competitors are
# whatever binaries `BENCH_BIN` holds, named `continuwuity` and `tuwunel`.
set -euo pipefail
cd "$(dirname "$0")/.."
BENCH=${BENCH_DIR:-tmp/bench}
BIN=${BENCH_BIN:-/home/user/bench-bin}
VENV=${SYNAPSE_VENV:-/tmp/synvenv}
TOKEN=${BENCH_TOKEN:-benchtoken}
export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true
mkdir -p "$BENCH"

wait_up() {
  for _ in $(seq 1 120); do
    curl -sS -m 2 -o /dev/null "http://127.0.0.1:$1/_matrix/client/versions" && return 0
    sleep 1
  done
  echo "server on :$1 did not come up" >&2; return 1
}

down() {
  for f in "$BENCH"/*.pid; do [ -f "$f" ] && { kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; }; done
  pkill -f 'synapse.app.homeserver' 2>/dev/null || true
  sleep 2
}

up() {
  rm -rf "$BENCH/spindle-data"
  cat > "$BENCH/spindle.toml" <<TOML
[server]
name = "bench.local"
bind = "127.0.0.1:8099"

[storage]
path = "./$BENCH/spindle-data"

[ratelimit]
enabled = false
TOML
  setsid ./target/release/spindle "$BENCH/spindle.toml" > "$BENCH/spindle-run.log" 2>&1 < /dev/null &
  echo $! > "$BENCH/spindle.pid"

  rm -rf "$BENCH/synapse"; mkdir -p "$BENCH/synapse"
  "$VENV/bin/python" -m synapse.app.homeserver \
    --server-name bench.local --config-path "$BENCH/synapse/homeserver.yaml" \
    --generate-config --report-stats=no >/dev/null
  # The generated file ends without a newline, so an append would glue the
  # first override onto its trailing comment and silently drop it.
  echo >> "$BENCH/synapse/homeserver.yaml"
  cat >> "$BENCH/synapse/homeserver.yaml" <<'YAML'
enable_registration: true
enable_registration_without_verification: true
rc_message: {per_second: 1000, burst_count: 1000}
rc_registration: {per_second: 1000, burst_count: 1000}
rc_login:
  address: {per_second: 1000, burst_count: 1000}
  account: {per_second: 1000, burst_count: 1000}
  failed_attempts: {per_second: 1000, burst_count: 1000}
rc_joins:
  local: {per_second: 1000, burst_count: 1000}
  remote: {per_second: 1000, burst_count: 1000}
rc_invites:
  per_room: {per_second: 1000, burst_count: 1000}
  per_user: {per_second: 1000, burst_count: 1000}
  per_issuer: {per_second: 1000, burst_count: 1000}
rc_presence:
  per_user: {per_second: 1000, burst_count: 1000}
rc_media_create: {per_second: 1000, burst_count: 1000}
rc_delayed_event_mgmt: {per_second: 1000, burst_count: 1000}
rc_reports: {per_second: 1000, burst_count: 1000}
rc_admin_redaction: {per_second: 1000, burst_count: 1000}
rc_joins_per_room: {per_second: 1000, burst_count: 1000}
rc_room_creation: {per_second: 1000, burst_count: 1000}
rc_key_requests: {per_second: 1000, burst_count: 1000}
rc_3pid_validation: {per_second: 1000, burst_count: 1000}
rc_third_party_invite: {per_second: 1000, burst_count: 1000}
rc_user_directory: {per_second: 1000, burst_count: 1000}
rc_registration_token_validity: {per_second: 1000, burst_count: 1000}
suppress_key_server_warning: true
YAML
  sed -i '0,/port: 8008/s//port: 8098/' "$BENCH/synapse/homeserver.yaml"
  # no IPv6 loopback on this host: Synapse refuses to start if ::1 cannot bind
  sed -i '/^    - ::1$/d' "$BENCH/synapse/homeserver.yaml"
  setsid "$VENV/bin/python" -m synapse.app.homeserver \
    --config-path "$BENCH/synapse/homeserver.yaml" > "$BENCH/synapse-run.log" 2>&1 < /dev/null &
  echo $! > "$BENCH/synapse.pid"

  for pair in continuwuity:8097 tuwunel:8096; do
    name=${pair%%:*}; port=${pair#*:}
    rm -rf "$BENCH/$name-data"; mkdir -p "$BENCH/$name-data"
    cat > "$BENCH/$name.toml" <<TOML
[global]
server_name = "bench.local"
database_path = "$PWD/$BENCH/$name-data"
address = "127.0.0.1"
port = $port
allow_registration = true
registration_token = "$TOKEN"
allow_federation = false
log = "warn"
TOML
    setsid "$BIN/$name" -c "$BENCH/$name.toml" > "$BENCH/$name-run.log" 2>&1 < /dev/null &
    echo $! > "$BENCH/$name.pid"
  done

  wait_up 8099; wait_up 8098; wait_up 8097; wait_up 8096

  # Continuwuity's release build refuses the configured registration token
  # until a first account has been created with the one-time token it
  # prints at startup, so create that account here and out of the way.
  for _ in $(seq 1 30); do
    once=$(sed 's/\x1b\[[0-9;]*m//g' "$BENCH/continuwuity-run.log" \
      | sed -n 's/.*using the registration token \([A-Za-z0-9]*\) .*/\1/p' | tail -1)
    [ -n "$once" ] && break
    sleep 1
  done
  [ -n "$once" ] || { echo "continuwuity printed no first-user token" >&2; return 1; }
  curl -sS -m 10 -X POST "http://127.0.0.1:8097/_matrix/client/v3/register" \
    -H 'content-type: application/json' \
    -d "{\"username\":\"bootstrap\",\"password\":\"bootstrap-$RANDOM$RANDOM\",\"auth\":{\"type\":\"m.login.registration_token\",\"token\":\"$once\"}}" \
    | grep -q '"user_id"' || { echo "continuwuity first-user bootstrap failed" >&2; return 1; }
  echo "all four up"
}

case ${1:-up} in up) up ;; down) down ;; *) echo "up|down" >&2; exit 2 ;; esac
