#!/usr/bin/env bash
#
# One sitting, start to finish: every server up cold, the rounds, every
# server down, and a sidecar that says where the numbers came from. The
# pieces exist on their own (`bench-servers.sh`, `bench-rounds.sh`); this is
# the order they go in, so a sitting is one command locally and the same
# command in CI.
#
#   BENCH_BIN=... SYNAPSE_VENV=... scripts/bench-sitting.sh --group m7-progress-2 --rounds 3
#
# Servers whose binary is absent are left out of the sitting and named in
# the sidecar, so the page can say "measured against these" rather than
# carry a column forward from an older run.
set -euo pipefail
cd "$(dirname "$0")/.."

GROUP=; ROUNDS=3; EXTRA=()
while [ $# -gt 0 ]; do
  case $1 in
    --group) GROUP=$2; shift 2 ;;
    --rounds) ROUNDS=$2; shift 2 ;;
    *) EXTRA+=("$1"); shift ;;
  esac
done
[ -n "$GROUP" ] || { echo "--group is required" >&2; exit 2; }
BIN=${BENCH_BIN:-tmp/bench-bin}; VENV=${SYNAPSE_VENV:-tmp/synvenv}
[ -x target/release/spindle ] || { echo "no target/release/spindle: run \`just bench-build\`" >&2; exit 1; }
[ -x "$VENV/bin/python" ] || { echo "no Synapse venv at $VENV: run \`just bench-field\`" >&2; exit 1; }
OUT=docs/benchmarks/data

servers=(--server spindle=http://127.0.0.1:8099 --server synapse=http://127.0.0.1:8098)
absent=()
for pair in continuwuity:8097 tuwunel:8096 dendrite:8095; do
  name=${pair%%:*}; port=${pair#*:}
  if [ -x "$BIN/$name" ]; then
    servers+=(--server "$name=http://127.0.0.1:$port")
    case $name in continuwuity|tuwunel) servers+=(--registration-token "$name=${BENCH_TOKEN:-benchtoken}") ;; esac
  else
    absent+=("$name")
  fi
done

version_of() {
  case $1 in
    # The server takes a config path and nothing else, so its version is the
    # tree it was built from: the crate version, the nearest tag when one
    # exists (`v0.0.1-12-gabc123def456`, or the bare tag on a release
    # commit), and the commit either way.
    spindle) echo "spindle $(grep -m1 '^version' crates/spindle-server/Cargo.toml | cut -d'"' -f2) $(git describe --tags --always --dirty 2>/dev/null || git rev-parse --short=12 HEAD) @ $(git rev-parse --short=12 HEAD)" ;;
    # The database is part of the version: Synapse on SQLite and on
    # Postgres are two different things to compare against.
    synapse) echo "$("$VENV/bin/python" -c 'import synapse; print("synapse", synapse.__version__)') on $([ -n "${BENCH_PG_URL:-}" ] && echo postgres || echo sqlite)" ;;
    # Dendrite prints "0.15.2+e546df2" (tag plus commit) with no name.
    dendrite) echo "dendrite $("$BIN/dendrite" --version 2>/dev/null | head -1 || echo unknown)" ;;
    *) "$BIN/$1" --version 2>/dev/null | head -1 ;;
  esac
}

cleanup() { BENCH_BIN="$BIN" SYNAPSE_VENV="$VENV" scripts/bench-servers.sh down || true; }
trap cleanup EXIT
BENCH_BIN="$BIN" SYNAPSE_VENV="$VENV" scripts/bench-servers.sh up
started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
scripts/bench-rounds.sh --group "$GROUP" --rounds "$ROUNDS" "${servers[@]}" "${EXTRA[@]}"
finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# The sidecar: the host, the versions, what was absent. `<group>.sitting.json`
# sits beside the round files and the renderer reads it as provenance.
python3 - "$OUT/$GROUP.sitting.json" "$GROUP" "$ROUNDS" "$started" "$finished" "${absent[*]:-}" <<'PY' \
  "$(version_of spindle)" "$(version_of synapse)" "$(version_of continuwuity 2>/dev/null)" "$(version_of tuwunel 2>/dev/null)" "$(version_of dendrite)"
import json, os, platform, subprocess, sys
out, group, rounds, started, finished, absent = sys.argv[1:7]
versions = [v for v in sys.argv[7:] if v]
def cpu():
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"
commit = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], capture_output=True, text=True).stdout.strip()
json.dump({
    "group": group,
    "rounds": int(rounds),
    "started": started,
    "finished": finished,
    "host": {
        "cpu": cpu(),
        "cores": os.cpu_count(),
        "kernel": platform.release(),
        "runner": os.environ.get("BENCH_RUNNER", "developer machine"),
    },
    "spindle_commit": commit,
    "versions": versions,
    "absent": [a for a in absent.split() if a],
}, open(out, "w"), indent=2)
print(f"sidecar -> {out}")
PY
echo "sitting $GROUP: $ROUNDS rounds, results in $OUT/$GROUP.*.json"
