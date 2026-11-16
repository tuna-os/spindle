#!/usr/bin/env bash
#
# Start Synapse and Spindle side by side on loopback for the sliding sync
# differential harness, or stop them.
#
#   scripts/sliding-sync-diff/up.sh [--spindle build|image:REF|binary:PATH]
#   scripts/sliding-sync-diff/up.sh --down
#   scripts/sliding-sync-diff/up.sh --restart synapse|spindle
#
# Each server is an island: one server name for both (so a user ID is the
# same string on each side), no federation, no TLS. Synapse runs from its
# official image on SQLite; Spindle runs from this checkout (the default,
# `build`), from a release image, or from a binary you name.
#
# Docker or Podman, whichever is on PATH. compare-against.sh installs
# Synapse into a virtualenv instead; this harness pins an image, because the
# comparison is only as good as knowing which Synapse answered.
set -euo pipefail
cd "$(dirname "$0")/../.."

SYNAPSE_IMAGE=${SYNAPSE_IMAGE:-docker.io/matrixdotorg/synapse:v1.164.2}
SERVER_NAME=${SSDIFF_SERVER_NAME:-diff.test}
SYNAPSE_PORT=${SSDIFF_SYNAPSE_PORT:-18008}
SPINDLE_PORT=${SSDIFF_SPINDLE_PORT:-18009}
SECRET=${SSDIFF_SHARED_SECRET:-ssdiff-shared-secret}
WORK=${SSDIFF_WORK:-tmp/sliding-sync-diff}
SPINDLE=build
DOWN=0
RESTART=

while [ $# -gt 0 ]; do
  case $1 in
    --spindle) SPINDLE=$2; shift 2 ;;
    --down) DOWN=1; shift ;;
    --restart) RESTART=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if command -v docker >/dev/null 2>&1; then
  CT=docker
elif command -v podman >/dev/null 2>&1; then
  CT=podman
else
  echo "neither docker nor podman is on PATH" >&2
  exit 1
fi

say() { printf '== %s\n' "$1"; }

down() {
  $CT rm -f ssdiff-synapse >/dev/null 2>&1 || true
  $CT rm -f ssdiff-spindle >/dev/null 2>&1 || true
  if [ -f "$WORK/spindle.pid" ]; then
    kill "$(cat "$WORK/spindle.pid")" 2>/dev/null || true
    rm -f "$WORK/spindle.pid"
  fi
}

# Restart one server with its data, for the harness's server-restart step:
# what a deploy does to a client that holds a pos.
if [ -n "$RESTART" ]; then
  case $RESTART in
    synapse) $CT restart ssdiff-synapse >/dev/null ;;
    spindle)
      if [ -f "$WORK/spindle.bin" ]; then
        kill "$(cat "$WORK/spindle.pid")" 2>/dev/null || true
        while kill -0 "$(cat "$WORK/spindle.pid")" 2>/dev/null; do sleep 0.2; done
        setsid "$(cat "$WORK/spindle.bin")" "$WORK/spindle.toml" >> "$WORK/spindle.log" 2>&1 < /dev/null &
        echo $! > "$WORK/spindle.pid"
      else
        $CT restart ssdiff-spindle >/dev/null
      fi
      ;;
    *) echo "--restart takes synapse or spindle" >&2; exit 2 ;;
  esac
  exit 0
fi

if [ "$DOWN" = 1 ]; then
  down
  exit 0
fi

down
rm -f "$WORK/spindle.bin"
# A previous run's rooms would be a different scenario on one side only.
rm -rf "$WORK/synapse" "$WORK/spindle-data"
mkdir -p "$WORK/synapse"
WORK_ABS=$(cd "$WORK" && pwd)

# Rootless Podman maps container root to the invoking user, so Synapse runs
# as "root" there to own its files; under Docker it runs as the invoking user.
if [ "$CT" = podman ]; then SUID=0; SGID=0; else SUID=$(id -u); SGID=$(id -g); fi

say "Synapse $SYNAPSE_IMAGE on 127.0.0.1:$SYNAPSE_PORT"
$CT run --rm --network none -v "$WORK_ABS/synapse:/data:Z" \
  -e SYNAPSE_SERVER_NAME="$SERVER_NAME" -e SYNAPSE_REPORT_STATS=no \
  -e UID="$SUID" -e GID="$SGID" \
  "$SYNAPSE_IMAGE" generate >/dev/null
# The generated file ends without a newline; an append would glue the first
# override onto its last comment.
echo >> "$WORK/synapse/homeserver.yaml"
cat >> "$WORK/synapse/homeserver.yaml" <<YAML
registration_shared_secret: "$SECRET"
enable_registration: false
suppress_key_server_warning: true
trusted_key_servers: []
federation_domain_whitelist: []
presence:
  enabled: false
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
rc_joins_per_room: {per_second: 1000, burst_count: 1000}
rc_room_creation: {per_second: 1000, burst_count: 1000}
rc_3pid_validation: {per_second: 1000, burst_count: 1000}
rc_key_requests: {per_second: 1000, burst_count: 1000}
YAML
# Host networking, with the listener moved to a loopback port: rootless
# Podman without slirp4netns or pasta cannot publish a port, and loopback on
# the host is all either server needs.
python3 - "$WORK/synapse/homeserver.yaml" "$SYNAPSE_PORT" <<'PY'
import re, sys
path, port = sys.argv[1], sys.argv[2]
text = open(path).read()
text = re.sub(r"bind_addresses: \[[^\]]*\]\n\s*", "", text)
text = re.sub(r"( *)- port: 8008\n", lambda m: f"{m.group(1)}- port: {port}\n{m.group(1)}  bind_addresses: ['127.0.0.1']\n", text, count=1)
open(path, "w").write(text)
PY
$CT run -d --name ssdiff-synapse --network host -v "$WORK_ABS/synapse:/data:Z" \
  -e UID="$SUID" -e GID="$SGID" "$SYNAPSE_IMAGE" >/dev/null

say "Spindle ($SPINDLE) on 127.0.0.1:$SPINDLE_PORT"
# Synapse's presence is off (above) so that a presence-only change cannot
# end a long poll on one side only; Element X does not ask for the presence
# extension. Spindle's config leaves presence alone: release images before
# its [presence] section would refuse the key.
write_spindle_toml() {
  cat > "$1" <<TOML
[server]
name = "$SERVER_NAME"
bind = "$2"

[storage]
path = "$3"

[ratelimit]
enabled = false

[registration]
shared_secret = "$SECRET"

[logging]
filter = "warn"
TOML
}

case $SPINDLE in
  build|binary:*)
    if [ "$SPINDLE" = build ]; then
      cargo build --release -p spindle-server --bin spindle
      BIN=target/release/spindle
    else
      BIN=${SPINDLE#binary:}
    fi
    write_spindle_toml "$WORK/spindle.toml" "127.0.0.1:$SPINDLE_PORT" "$WORK_ABS/spindle-data"
    setsid "$BIN" "$WORK/spindle.toml" > "$WORK/spindle.log" 2>&1 < /dev/null &
    echo $! > "$WORK/spindle.pid"
    echo "$BIN" > "$WORK/spindle.bin"
    if [ "$SPINDLE" = build ]; then
      echo "build $(git describe --always --dirty 2>/dev/null || echo unknown)" > "$WORK/spindle.version"
    else
      echo "$BIN" > "$WORK/spindle.version"
    fi
    ;;
  image:*)
    REF=${SPINDLE#image:}
    write_spindle_toml "$WORK/spindle.toml" "127.0.0.1:$SPINDLE_PORT" "/var/lib/spindle"
    $CT run -d --name ssdiff-spindle --network host \
      -v "$WORK_ABS/spindle.toml:/etc/spindle/spindle.toml:ro,Z" \
      "$REF" /etc/spindle/spindle.toml >/dev/null
    echo "$REF" > "$WORK/spindle.version"
    ;;
  *) echo "--spindle takes build, image:REF or binary:PATH" >&2; exit 2 ;;
esac

wait_for() {
  for _ in $(seq 1 90); do
    if curl -sf -m 2 -o /dev/null "$1/_matrix/client/versions"; then return 0; fi
    sleep 1
  done
  echo "$2 did not come up at $1" >&2
  return 1
}
export NO_PROXY='*' no_proxy='*'
wait_for "http://127.0.0.1:$SYNAPSE_PORT" synapse || { $CT logs ssdiff-synapse | tail -30 >&2; exit 1; }
wait_for "http://127.0.0.1:$SPINDLE_PORT" spindle || { tail -30 "$WORK/spindle.log" >&2; exit 1; }

# Synapse's version from its own admin-free endpoint, so the report says
# which server answered rather than which image was asked for.
curl -sf "http://127.0.0.1:$SYNAPSE_PORT/_matrix/federation/v1/version" > "$WORK/synapse.version" || true
# A server without MSC4186 cannot be compared, so this stops the run.
for side in synapse:"$SYNAPSE_PORT" spindle:"$SPINDLE_PORT"; do
  if ! curl -sf "http://127.0.0.1:${side#*:}/_matrix/client/versions" \
      | grep -q '"org.matrix.simplified_msc3575": *true'; then
    echo "${side%%:*} does not advertise org.matrix.simplified_msc3575" >&2
    exit 1
  fi
done
say "up: synapse=http://127.0.0.1:$SYNAPSE_PORT spindle=http://127.0.0.1:$SPINDLE_PORT"
