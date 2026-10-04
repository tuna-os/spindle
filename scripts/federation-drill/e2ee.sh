#!/bin/sh
# Run drill-e2ee as one test account, inside the drill-client pod.
#   e2ee.sh USER COMMAND [ARGS...]
# USER is witness (on A) or drill-b1 (on B). The state directory is
# /state/e2ee-USER and the password comes from /state/passwords.json, so it
# never appears on a command line.
set -eu
user=$1; shift
DRILL_PASSWORD=$(python3 -c "import json,sys; print(json.load(open('/state/passwords.json'))[sys.argv[1]])" "$user")
export DRILL_PASSWORD
# Rooms the client leaves out of /sync (see drill-e2ee sync_settings).
DRILL_SYNC_EXCLUDE=$(cat /state/sync-exclude 2>/dev/null || true)
export DRILL_SYNC_EXCLUDE
exec /work/drill/bin/drill-e2ee "$@" --state "/state/e2ee-$user"
