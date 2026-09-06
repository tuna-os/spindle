#!/usr/bin/env bash
#
# Bring up every server of a sitting on loopback, cold, with every rate limit
# the competitors expose lifted, and leave them running for
# `bench-rounds.sh`. `down` stops them.
#
#   BENCH_BIN=/path/with/the/competitor/binaries SYNAPSE_VENV=/path/to/venv \
#     scripts/bench-servers.sh up
#   scripts/bench-rounds.sh --group m7-progress-2 --rounds 3 \
#       --server spindle=http://127.0.0.1:8099 --server synapse=http://127.0.0.1:8098 \
#       --server continuwuity=http://127.0.0.1:8097 --server tuwunel=http://127.0.0.1:8096 \
#       --server dendrite=http://127.0.0.1:8095 \
#       --registration-token continuwuity=benchtoken --registration-token tuwunel=benchtoken
#   scripts/bench-servers.sh down
#
# Committed because the M7 sitting lost most of an evening to details that
# had all been solved once before and written down nowhere: see the notes
# inline. Expects `target/release/spindle` to exist; the competitors are
# whatever binaries `BENCH_BIN` holds, named `continuwuity`, `tuwunel` and
# `dendrite` (with Dendrite's `generate-keys` beside it). A competitor whose
# binary is absent is skipped and named, so a sitting can be three servers
# or five and the page says which.
#
# The five, and why each is in the field: Synapse is the reference
# implementation and the one most deployments run; Continuwuity and Tuwunel
# are the conduwuit lineage, Rust on RocksDB, and the performance bar;
# Dendrite is Element's second-generation Go server, a different design
# again (a NATS event bus between components) and the other server an
# operator picks when Synapse is too heavy. Spindle is the subject.
set -euo pipefail
cd "$(dirname "$0")/.."
BENCH=${BENCH_DIR:-tmp/bench}
BIN=${BENCH_BIN:-/home/user/bench-bin}
VENV=${SYNAPSE_VENV:-/tmp/synvenv}
# Absolute, whatever the caller passed: the Dendrite steps below `cd` into
# the server's own directory before running its binaries, and CI names the
# field as `tmp/bench-bin`. The first scheduled sitting died there with a
# silent 127 -- "no such file", from a path that was right one directory up.
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
case $VENV in /*) ;; *) VENV=$PWD/$VENV ;; esac
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
  # A port already bound is a server already running -- a previous sitting's,
  # a probe's -- and the driver would measure it, not the cold one launched
  # below. That happened once: a stale Dendrite from a probe answered a
  # whole leg with M_USER_IN_USE. Refuse, and name what holds the port.
  for port in 8099 8098 8097 8096 8095; do
    holder=$(ss -ltnp 2>/dev/null | grep -E ":$port " | grep -o 'pid=[0-9]*' | head -1 || true)
    [ -z "$holder" ] || { echo "port $port is already bound ($holder); stop it before a sitting" >&2; return 1; }
  done
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
    if [ ! -x "$BIN/$name" ]; then
      echo "no $BIN/$name: the sitting runs without $name" >&2
      continue
    fi
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

  # Dendrite: Element's Go server. SQLite per component (its global database
  # block is Postgres-only), the NATS bus in-process, federation off, its
  # rate limiter off, and open registration -- which it refuses without a
  # flag whose name says what it thinks of the idea. Fair: this is a
  # loopback benchmark, not a deployment.
  if [ -x "$BIN/dendrite" ]; then
    rm -rf "$BENCH/dendrite"; mkdir -p "$BENCH/dendrite"
    # stderr kept: a key generator that cannot run must say so, not fail
    # the sitting with a bare exit code.
    ( cd "$BENCH/dendrite" && "$BIN/generate-keys" --private-key matrix_key.pem >/dev/null )
    {
      cat <<'YAML'
version: 2
global:
  server_name: bench.local
  private_key: matrix_key.pem
  key_validity_period: 168h0m0s
  cache:
    max_size_estimated: 1gb
    max_age: 1h
  disable_federation: true
  presence:
    enable_inbound: false
    enable_outbound: false
  report_stats:
    enabled: false
  jetstream:
    addresses: []
    storage_path: ./jetstream
    topic_prefix: Dendrite
    in_memory: false
  metrics:
    enabled: false
client_api:
  registration_disabled: false
  guests_disabled: true
  registration_shared_secret: ""
  enable_registration_captcha: false
  rate_limiting:
    enabled: false
user_api:
  bcrypt_cost: 4
  account_database:
    connection_string: file:userapi.db
logging:
  - type: std
    level: warn
YAML
      for pair in app_service_api:appservice key_server:keyserver mscs:mscs relay_api:relayapi \
                  room_server:roomserver sync_api:syncapi; do
        printf '%s:\n  database:\n    connection_string: file:%s.db\n' "${pair%%:*}" "${pair#*:}"
      done
      printf 'federation_api:\n  send_max_retries: 1\n  disable_tls_validation: true\n  database:\n    connection_string: file:federationapi.db\n'
      printf 'media_api:\n  base_path: ./media_store\n  max_file_size_bytes: 10485760\n  dynamic_thumbnails: false\n  database:\n    connection_string: file:mediaapi.db\n' 
    } > "$BENCH/dendrite/dendrite.yaml"
    ( cd "$BENCH/dendrite" && setsid "$BIN/dendrite" -config dendrite.yaml \
        -http-bind-address 127.0.0.1:8095 -really-enable-open-registration \
        > ../dendrite-run.log 2>&1 < /dev/null & echo $! > ../dendrite.pid )
  else
    echo "no $BIN/dendrite: the sitting runs without Dendrite" >&2
  fi

  wait_up 8099; wait_up 8098
  [ -x "$BIN/continuwuity" ] && wait_up 8097
  [ -x "$BIN/tuwunel" ] && wait_up 8096
  [ -x "$BIN/dendrite" ] && wait_up 8095

  # Continuwuity's release build refuses the configured registration token
  # until a first account has been created with the one-time token it
  # prints at startup, so create that account here and out of the way.
  [ -x "$BIN/continuwuity" ] || { echo "all up"; return 0; }
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
  echo "all up"
}

case ${1:-up} in up) up ;; down) down ;; *) echo "up|down" >&2; exit 2 ;; esac
