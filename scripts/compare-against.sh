#!/usr/bin/env bash
#
# Run the same client-server workload against Spindle and Synapse, on this
# host, in one sitting of several rounds, and print the comparison.
#
# This is #42's methodology guardrail made executable. A number from one
# machine set against a number from another is noise; the only comparison that
# is evidence is one where both servers ran the same driver, back to back, on
# the same hardware, in the same run. So this script owns both servers.
#
# And since #171 a sitting is several rounds rather than one. One round of
# each server cannot tell a real difference from this host's own run-to-run
# variance -- six rounds of an *identical* binary moved the median cell by
# 1.38x -- so both servers stay up together and `bench-rounds.sh` measures
# them in alternating order, five rounds by default (three is the minimum
# that means anything; `--rounds` sets it). Every round is written to its own
# file and the comparison printed at the end is a median with its range, with
# a cell called only when the two servers' rounds separate.
#
# Synapse is installed into a virtualenv rather than run from Docker, because
# a Docker daemon is not available everywhere this needs to run -- notably not
# in the sandbox where most of this development happens, which is exactly the
# environment where a comparison must not be skippable.
#
#   scripts/compare-against.sh [--rounds 5] [--sizes 200,800,3200] [--samples 25]
#
# Leaves its results in tmp/bench/, which is gitignored: a Synapse run drops a
# database and a signing key there. To publish a sitting, run the four-way
# recipe instead (`bench-four-way.sh` then `bench-rounds.sh`), which writes
# under docs/benchmarks/data/ where the renderer reads.
set -euo pipefail
cd "$(dirname "$0")/.."

SIZES=200,800,3200
SAMPLES=25
WARMUP=5
ROUNDS=5
GROUP=compare
MAX_LOAD=0.6
VENV=${SYNAPSE_VENV:-/tmp/synvenv}
SPINDLE_PORT=8099
SYNAPSE_PORT=8098
BENCH=tmp/bench

while [ $# -gt 0 ]; do
  case $1 in
    --sizes) SIZES=$2; shift 2 ;;
    --samples) SAMPLES=$2; shift 2 ;;
    --warmup) WARMUP=$2; shift 2 ;;
    --rounds) ROUNDS=$2; shift 2 ;;
    --group) GROUP=$2; shift 2 ;;
    --max-load) MAX_LOAD=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$BENCH"
# The driver talks to loopback; a proxy in the environment would send it
# somewhere else entirely and the failure looks like a hung server.
export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

say() { printf '\n== %s ==\n' "$1"; }

# Both servers run for the whole sitting now, so both are stopped on the way
# out whether the sitting finished or a leg failed. A server left bound to
# its port is exactly how an earlier A/B in this project measured a stale
# binary for an afternoon.
cleanup() {
  pkill -f 'synapse.app.homeserver' 2>/dev/null || true
  pkill -f 'release/spindle' 2>/dev/null || true
}
trap cleanup EXIT

# --- Spindle: built first, so the build's load has passed before anything is
# measured. bench-rounds.sh checks the load again before its first leg.

say "building Spindle"
cargo build --release --workspace
cat > "$BENCH/spindle.toml" <<TOML
[server]
name = "bench.local"
bind = "127.0.0.1:$SPINDLE_PORT"

[storage]
path = "./$BENCH/spindle-data"

[ratelimit]
enabled = false

[logging]
filter = "warn"
TOML

# --- Synapse ---------------------------------------------------------------

if [ ! -x "$VENV/bin/synapse_homeserver" ]; then
  say "installing Synapse into $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet matrix-synapse
fi
echo "synapse $("$VENV/bin/python" -c 'import synapse; print(synapse.__version__)')"

if [ ! -f "$BENCH/synapse/homeserver.yaml" ]; then
  say "generating Synapse config"
  mkdir -p "$BENCH/synapse"
  "$VENV/bin/python" -m synapse.app.homeserver \
    --server-name bench.local --config-path "$BENCH/synapse/homeserver.yaml" \
    --generate-config --report-stats=no >/dev/null
  # The generated file ends without a newline, so an append would glue the
  # first override onto its trailing comment and silently drop it.
  echo >> "$BENCH/synapse/homeserver.yaml"
  # Registration without a shared secret or email, and no rate limiting: the
  # driver registers a user per sample, and a throttled server would report
  # its own throttle rather than its cost. The list is the one the four-way
  # recipe settled on -- `rc_joins_per_room` and `rc_invites` are separate
  # from `rc_joins` and fire on the driver's setup phase.
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
rc_joins_per_room: {per_second: 1000, burst_count: 1000}
rc_room_creation: {per_second: 1000, burst_count: 1000}
suppress_key_server_warning: true
YAML
  python3 - "$BENCH/synapse/homeserver.yaml" "$SYNAPSE_PORT" <<'PY'
import re, sys
path, port = sys.argv[1], sys.argv[2]
text = open(path).read()
text = re.sub(r"port: 8008", f"port: {port}", text, count=1)
open(path, "w").write(text)
PY
fi

say "starting Synapse on :$SYNAPSE_PORT"
setsid "$VENV/bin/python" -m synapse.app.homeserver \
  --config-path "$BENCH/synapse/homeserver.yaml" > "$BENCH/synapse-run.log" 2>&1 < /dev/null &
for _ in $(seq 1 60); do
  if curl -sS -m 2 -o /dev/null "http://127.0.0.1:$SYNAPSE_PORT/_matrix/client/versions"; then break; fi
  sleep 1
done
curl -sS -m 5 -o /dev/null "http://127.0.0.1:$SYNAPSE_PORT/_matrix/client/versions" \
  || { echo "synapse did not come up; see $BENCH/synapse-run.log" >&2; exit 1; }

say "starting Spindle on :$SPINDLE_PORT"
rm -rf "$BENCH/spindle-data"
setsid ./target/release/spindle "$BENCH/spindle.toml" > "$BENCH/spindle-run.log" 2>&1 < /dev/null &
for _ in $(seq 1 30); do
  if curl -sS -m 2 -o /dev/null "http://127.0.0.1:$SPINDLE_PORT/health"; then break; fi
  sleep 1
done
# Which binary is answering, not which one was started. An earlier A/B in this
# project was invalid for a whole afternoon because a previous server was
# still bound to the port and every "new" number came from the old build.
serving=$(pgrep -af 'release/spindle' | grep -v pgrep | head -1 || true)
echo "serving: ${serving:-NOTHING}"
[ -n "$serving" ] || { echo "spindle is not running" >&2; exit 1; }

# --- The sitting -----------------------------------------------------------

# Rounds from a previous sitting with a different count would otherwise be
# read as part of this one.
rm -f "$BENCH/$GROUP".*.r*.json
say "sitting: $ROUNDS rounds, alternating order"
scripts/bench-rounds.sh --group "$GROUP" --rounds "$ROUNDS" --out "$BENCH" \
  --sizes "$SIZES" --samples "$SAMPLES" --warmup "$WARMUP" --max-load "$MAX_LOAD" \
  --server "synapse=http://127.0.0.1:$SYNAPSE_PORT" \
  --server "spindle=http://127.0.0.1:$SPINDLE_PORT"

say "comparison"
python3 scripts/compare-benchmarks.py \
  "$BENCH/$GROUP.spindle.r*.json" "$BENCH/$GROUP.synapse.r*.json"
