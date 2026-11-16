#!/usr/bin/env bash
#
# The whole differential run in one command: start both servers, drive the
# scenario, write the report, stop both servers.
#
#   scripts/sliding-sync-diff/run.sh [--spindle build|image:REF|binary:PATH] [--keep]
#                                    [--no-restart] [-- extra sliding_sync_diff.py run options]
#
# The report is printed and kept in tmp/sliding-sync-diff/out/ with the raw
# exchanges of both servers (synapse.jsonl, spindle.jsonl).
set -euo pipefail
cd "$(dirname "$0")/../.."

SPINDLE=build
KEEP=0
RESTART=1
while [ $# -gt 0 ]; do
  case $1 in
    --spindle) SPINDLE=$2; shift 2 ;;
    --keep) KEEP=1; shift ;;
    --no-restart) RESTART=0; shift ;;
    --) shift; break ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

DIR=scripts/sliding-sync-diff
"$DIR/up.sh" --spindle "$SPINDLE"
if [ "$KEEP" = 0 ]; then
  trap '"$DIR/up.sh" --down' EXIT
fi
extra=()
if [ "$RESTART" = 1 ]; then
  extra+=(--restart-cmd "$DIR/up.sh --restart {side}")
fi
python3 "$DIR/sliding_sync_diff.py" run --spindle-label "$(cat tmp/sliding-sync-diff/spindle.version)" \
  "${extra[@]}" "$@"
