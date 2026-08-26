#!/usr/bin/env bash
#
# Run the same client-server workload against Spindle and a competitor, on
# this host, in one sitting, and print the comparison.
#
# This is #42's methodology guardrail made executable. A number from one
# machine set against a number from another is noise; the only comparison that
# is evidence is one where both servers ran the same driver, back to back, on
# the same hardware, in the same run. So this script owns both servers.
#
# Synapse is installed into a virtualenv rather than run from Docker, because
# a Docker daemon is not available everywhere this needs to run -- notably not
# in the sandbox where most of this development happens, which is exactly the
# environment where a comparison must not be skippable.
#
#   scripts/compare-against.sh [--sizes 100,400,1600] [--samples 25]
#
# Leaves its results in tmp/bench/, which is gitignored: a Synapse run drops a
# database and a signing key there.
set -euo pipefail
cd "$(dirname "$0")/.."

SIZES=100,400,1600
SAMPLES=25
WARMUP=5
VENV=${SYNAPSE_VENV:-/tmp/synvenv}
SPINDLE_PORT=8099
SYNAPSE_PORT=8098
BENCH=tmp/bench

while [ $# -gt 0 ]; do
  case $1 in
    --sizes) SIZES=$2; shift 2 ;;
    --samples) SAMPLES=$2; shift 2 ;;
    --warmup) WARMUP=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$BENCH"
# The driver talks to loopback; a proxy in the environment would send it
# somewhere else entirely and the failure looks like a hung server.
export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

say() { printf '\n== %s ==\n' "$1"; }

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
  # Registration without a shared secret or email, and no rate limiting: the
  # driver registers a user per sample, and a throttled server would report
  # its own throttle rather than its cost.
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

python3 scripts/api-benchmark.py "http://127.0.0.1:$SYNAPSE_PORT" "$BENCH/synapse.json" \
  --server synapse --sizes "$SIZES" --samples "$SAMPLES" --warmup "$WARMUP"

pkill -f 'synapse.app.homeserver' || true
sleep 2

# --- Spindle ---------------------------------------------------------------

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

python3 scripts/api-benchmark.py "http://127.0.0.1:$SPINDLE_PORT" "$BENCH/spindle.json" \
  --server spindle --sizes "$SIZES" --samples "$SAMPLES" --warmup "$WARMUP"

pkill -f 'release/spindle' || true

say "comparison"
python3 scripts/compare-benchmarks.py "$BENCH/spindle.json" "$BENCH/synapse.json"
