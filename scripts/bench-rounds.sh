#!/usr/bin/env bash
#
# Run a sitting several times, alternating the order, and write one results
# file per server per round.
#
# This is #171's finding made executable. A single round cannot separate a
# real difference from this host's run-to-run variance: six rounds of an
# *identical* binary moved the median cell by 1.38x and the worst by 2.80x,
# and all 21 cells exceeded the +/-10% band the page used to colour them by.
# So a sitting is now several rounds, and `render-comparisons.py` calls a cell
# only when the two servers' rounds separate.
#
# Two things this does that a loop around the driver would not:
#
# **It alternates the order every round.** If the machine drifts during a
# sitting -- a thermal ramp, a background job -- a fixed order bakes that
# drift into whichever server always runs last. Alternating turns it into
# spread, which the renderer can see, instead of bias, which it cannot.
#
# **It refuses to start on a busy machine, and says so.** An earlier sitting
# in this project was discarded for beginning at load 2.28. Idleness is part
# of the method, so it is checked rather than assumed.
#
#   scripts/bench-rounds.sh --group m5-final --rounds 3 \
#       --server spindle=http://127.0.0.1:8099 \
#       --server continuwuity=http://127.0.0.1:8097
#
# Servers must already be running: what they are and how they are configured
# is the caller's business, and baking it in here is what made the previous
# harness single-purpose. Results land in docs/benchmarks/data/ as
# `<group>.<server>.r<N>.json`, which is what the renderer reads.
set -euo pipefail
cd "$(dirname "$0")/.."

GROUP=
ROUNDS=3
SIZES=200,800,3200
SAMPLES=25
WARMUP=5
DIMENSION=events
OUT=docs/benchmarks/data
MAX_LOAD=0.6
declare -a SERVERS=()
declare -a TOKENS=()

while [ $# -gt 0 ]; do
  case $1 in
    --group) GROUP=$2; shift 2 ;;
    --rounds) ROUNDS=$2; shift 2 ;;
    --sizes) SIZES=$2; shift 2 ;;
    --samples) SAMPLES=$2; shift 2 ;;
    --warmup) WARMUP=$2; shift 2 ;;
    --dimension) DIMENSION=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --max-load) MAX_LOAD=$2; shift 2 ;;
    # name=url, repeated. Order is the round-1 order; it alternates after.
    --server) SERVERS+=("$2"); shift 2 ;;
    # name=token, for a server that gates registration behind one.
    --registration-token) TOKENS+=("$2"); shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$GROUP" ] || { echo "--group is required" >&2; exit 2; }
case $GROUP in *.*) echo "--group must not contain a dot: the renderer takes the group from the first segment of the filename" >&2; exit 2 ;; esac
[ "${#SERVERS[@]}" -ge 1 ] || { echo "--server name=url is required at least once" >&2; exit 2; }
[ "$ROUNDS" -ge 2 ] || echo "warning: $ROUNDS round(s) cannot separate anything; the renderer will mark this sitting unresolved" >&2

# The driver talks to loopback; a proxy would send it somewhere else entirely
# and the failure looks like a hung server.
export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

token_for() {
  local name=$1 entry
  for entry in ${TOKENS[@]+"${TOKENS[@]}"}; do
    [ "${entry%%=*}" = "$name" ] && { printf '%s' "${entry#*=}"; return; }
  done
}

load_now() { cut -d' ' -f1 /proc/loadavg; }

wait_for_idle() {
  local waited=0
  while [ "$(awk -v l="$(load_now)" -v m="$MAX_LOAD" 'BEGIN{print (l<m)?1:0}')" != 1 ]; do
    [ "$waited" = 0 ] && echo "waiting for load to fall below $MAX_LOAD (now $(load_now))"
    sleep 20
    waited=$((waited + 20))
    if [ "$waited" -ge 900 ]; then
      echo "load stayed above $MAX_LOAD for 15 minutes; refusing to measure on a busy host" >&2
      exit 1
    fi
  done
}

mkdir -p "$OUT"
wait_for_idle
echo "sitting: $GROUP, $ROUNDS rounds, load $(load_now)"

for round in $(seq 1 "$ROUNDS"); do
  # Alternate: odd rounds forwards, even rounds backwards.
  order=("${SERVERS[@]}")
  if [ $((round % 2)) -eq 0 ]; then
    reversed=()
    for ((i = ${#order[@]} - 1; i >= 0; i--)); do reversed+=("${order[i]}"); done
    order=("${reversed[@]}")
  fi

  for entry in "${order[@]}"; do
    name=${entry%%=*}
    url=${entry#*=}
    echo "== round $round · $name =="
    args=(--server "$name" --sizes "$SIZES" --samples "$SAMPLES"
          --warmup "$WARMUP" --dimension "$DIMENSION" --round "$round")
    tok=$(token_for "$name")
    [ -n "$tok" ] && args+=(--registration-token "$tok")
    python3 scripts/api-benchmark.py "$url" "$OUT/$GROUP.$name.r$round.json" "${args[@]}"
  done
done

echo
echo "sitting complete, load $(load_now)"
echo "render with: python3 scripts/render-comparisons.py $OUT <output.html>"
