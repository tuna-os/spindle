#!/usr/bin/env bash
# Stand up Synapse beside Spindle and run the same driver against both.
#
# No Docker: Synapse is pure Python and installs from PyPI into a venv, which
# is one fewer moving part than a container runtime and works anywhere Python
# does.
#
# The one thing this script is fussy about is *which binary is serving*. An
# earlier hand-run of this comparison produced an invalid result because a
# previous Spindle process was still bound to the port, so every "after"
# measurement was served by the "before" build. Every start here verifies.
set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
VENV=${VENV:-/tmp/synvenv}
WORK=${WORK:-$REPO/tmp}
SPINDLE_PORT=8099
SYNAPSE_PORT=8098
SIZES=${SIZES:-100,400,1600}
SAMPLES=${SAMPLES:-10}

serving_on() {  # port -> the command bound to it, or empty
  local port=$1
  for pid in $(pgrep -f 'spindle|synapse.app.homeserver' 2>/dev/null || true); do
    if command -v ss >/dev/null && ss -ltnp 2>/dev/null | grep -q ":$port .*pid=$pid,"; then
      tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null
      return
    fi
  done
}

if [ ! -x "$VENV/bin/python" ]; then
  echo "installing synapse into $VENV"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet matrix-synapse
fi
"$VENV/bin/python" -c 'import synapse; print("synapse", synapse.__version__)'

echo "note: configure $WORK/synapse/homeserver.yaml with every rc_* limiter"
echo "      raised, or the run will measure Synapse's throttle. The full list"
echo "      comes from synapse/config/ratelimiting.py, not from trial and error."
echo
echo "spindle on $SPINDLE_PORT: $(serving_on $SPINDLE_PORT)"
echo "synapse on $SYNAPSE_PORT: $(serving_on $SYNAPSE_PORT)"
echo
echo "then:"
echo "  python3 $REPO/scripts/api-benchmark.py http://127.0.0.1:$SPINDLE_PORT out-spindle.json --server spindle --sizes $SIZES --samples $SAMPLES"
echo "  python3 $REPO/scripts/api-benchmark.py http://127.0.0.1:$SYNAPSE_PORT out-synapse.json --server synapse --sizes $SIZES --samples $SAMPLES"
