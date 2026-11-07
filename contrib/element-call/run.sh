#!/usr/bin/env bash
# Run Element Call's own Playwright suite against Spindle (#269, the gate
# #41 asks for). No fork: upstream element-hq/element-call at a pinned
# revision, its docker-compose-dev.yml and docker-compose-playwright.yml
# untouched, with docker-compose-spindle.yml putting Spindle in Synapse's
# first seat and docker-compose-spindle-othersite.yml in its second. A
# change upstream cannot repaint our results without a revision bump here,
# beside a re-baselined allowlist.
#
#   contrib/element-call/run.sh [results.json]
#
# Environment:
#   ELEMENT_CALL_SRC    existing checkout (default: clones the pin into
#                       tmp/element-call)
#   SPINDLE_IMAGE       image to run (default: builds complement/Dockerfile)
#   SPINDLE_PEER        what sits in the second seat: `spindle` (default)
#                       or `synapse`, upstream's own Synapse (below)
#   ELEMENT_CALL_SPECS  spec files to run, relative to the checkout's
#                       playwright/ (default: the variant's subset below)
#   ELEMENT_CALL_PROJECT  playwright project (default: chromium)
#
# Needs docker with compose, node at the checkout's .node-version and
# corepack for pnpm -- the same things upstream's own CI needs.
#
# The subset is every SPA spec plus the upstream widget scenario that closes
# M7's remaining unattended real-client gate: ringing and decline. Its fixture uses Synapse's
# shared-secret registration API, which the test configs enable explicitly.
# Running a spec costs a minute; protecting it is the allowlist's decision, so
# the default runs wide. The pinned huddle file is not discovered by upstream's
# own `*.spec.ts` pattern, and the federated-call spec contains an interactive
# `page.pause()`, so both remain opt-in until upstream makes them unattended.
# Restricted-SFU stays out: it changes which SFU a user may reach rather than exercising homeserver behaviour.
#
# Beside upstream's specs run Spindle's own (contrib/element-call/specs/,
# copied into the checkout as playwright/spindle/): the scenarios #41 names
# that no upstream spec drives -- five-party churn, a homeserver restart
# mid-call, a ring the caller abandons, and the federated call across the
# two Spindles. They use upstream's fixtures and helpers unchanged, and the
# ratchet names them `spindle/<file> :: <title>` like any other spec.
#
# SPINDLE_PEER=synapse is the Spindle-to-Synapse variant (#795). Spindle
# keeps the first seat and upstream's synapse-1 service keeps the second,
# unmodified: upstream's othersite config already federates with
# synapse.m.localhost, and the first seat is the one the widget fixtures,
# Element Web's default config and the restart spec address, so they all
# keep pointing at Spindle. docker-compose-dead-peers.yml adds three
# homeservers that the ring spec joins to a room and then silences. The
# variant runs its own subset (spindle/synapse-peer-*.spec.ts) against its
# own ratchet, allowlist-synapse-peer.txt: a test of the two-Spindle rig
# that does not run here is not a regression.
set -euo pipefail

ELEMENT_CALL_REV=9f7c35cd8f84b12f9395e6aac56fd396a3921482
case "${SPINDLE_PEER:-spindle}" in
    spindle)
        DEFAULT_SPECS="landing.spec.ts access.spec.ts create-call.spec.ts spa-call-sticky.spec.ts reconnect.spec.ts sfu-reconnect-bug.spec.ts errors.spec.ts widget/voice-call-dm.spec.ts spindle/ring-abandon.spec.ts spindle/five-party-churn.spec.ts spindle/restart-mid-call.spec.ts spindle/federated-call.spec.ts"
        second_seat=docker-compose-spindle-othersite.yml
        allowlist=allowlist.txt
        peer="a second Spindle"
        ;;
    synapse)
        DEFAULT_SPECS="spindle/synapse-peer-call.spec.ts spindle/synapse-peer-ring.spec.ts"
        second_seat=docker-compose-dead-peers.yml
        allowlist="allowlist-synapse-peer.txt"
        peer="upstream's Synapse"
        ;;
    *)
        echo "element-call: SPINDLE_PEER is spindle or synapse, not ${SPINDLE_PEER}" >&2
        exit 2
        ;;
esac

results="${1:-tmp/element-call-results.json}"
toplevel="$(git rev-parse --show-toplevel)"
cd "$toplevel"
mkdir -p "$(dirname "$results")" tmp
results="$(cd "$(dirname "$results")" && pwd)/$(basename "$results")"
contrib="$toplevel/contrib/element-call"

if [[ -z "${SPINDLE_IMAGE:-}" ]]; then
    SPINDLE_IMAGE=complement-spindle:latest
    docker build -f complement/Dockerfile -t "$SPINDLE_IMAGE" .
fi
export SPINDLE_IMAGE SPINDLE_CONTRIB="$contrib"

if [[ -z "${ELEMENT_CALL_SRC:-}" ]]; then
    ELEMENT_CALL_SRC=tmp/element-call
    if [[ ! -d "$ELEMENT_CALL_SRC/.git" ]]; then
        git clone --quiet https://github.com/element-hq/element-call.git "$ELEMENT_CALL_SRC"
    fi
    git -C "$ELEMENT_CALL_SRC" fetch --quiet origin "$ELEMENT_CALL_REV"
    git -C "$ELEMENT_CALL_SRC" checkout --quiet "$ELEMENT_CALL_REV"
fi
cd "$ELEMENT_CALL_SRC"
echo "element-call: $(git rev-parse HEAD) with $SPINDLE_IMAGE in the first seat and $peer in the second"

# Spindle's own specs, beside upstream's and driven by the same config.
rm -rf playwright/spindle
cp -r "$contrib/specs" playwright/spindle

# Upstream's stack, with the overrides last so they win.
compose=(docker compose -f docker-compose-dev.yml -f docker-compose-playwright.yml \
    -f "$contrib/docker-compose-spindle.yml" -f "$contrib/$second_seat")
logged=(synapse synapse-1)
dead_peers=()
if [[ ${SPINDLE_PEER:-spindle} == synapse ]]; then
    dead_peers=(dead-peer-1 dead-peer-2 dead-peer-3)
    logged+=("${dead_peers[@]}")
fi
cleanup() {
    "${compose[@]}" logs --no-color "${logged[@]}" > "$(dirname "$results")/spindle.log" 2>&1 || true
    # A spec that failed half way can leave a dead peer paused, and a
    # paused container does not stop.
    if ((${#dead_peers[@]})); then
        "${compose[@]}" unpause "${dead_peers[@]}" >/dev/null 2>&1 || true
    fi
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
# The compose command, for the specs that act on the stack: the restart
# spec bounces the first homeserver with it, the same container, SIGTERM
# and start, so its store survives as a deployed server's would; the ring
# spec pauses and resumes the dead peers.
SPINDLE_COMPOSE="cd $(printf %q "$PWD") && ${compose[*]}"
SPINDLE_RESTART_HOMESERVER="$SPINDLE_COMPOSE restart synapse"
export SPINDLE_COMPOSE SPINDLE_RESTART_HOMESERVER
"${compose[@]}" pull --ignore-buildable --quiet || true
"${compose[@]}" up -d

# The homeservers answer before anything is asked of them, bounded, and
# the log says which one did not. Two minutes, because Synapse sets up its
# database on its first start.
wait_up() {
    local name=$1
    shift
    for _ in $(seq 1 120); do
        if curl -fsSk "$@" >/dev/null 2>&1; then
            echo "element-call: $name is up"
            return
        fi
        sleep 1
    done
    curl -fsSk "$@" >/dev/null \
        || { echo "element-call: $name never answered /versions" >&2; exit 1; }
}
for site in synapse.m.localhost synapse.othersite.m.localhost; do
    wait_up "$site" --resolve "$site:443:127.0.0.1" "https://$site/_matrix/client/versions"
done
for n in "${!dead_peers[@]}"; do
    wait_up "${dead_peers[n]}" "http://127.0.0.1:2810$((n + 1))/_matrix/client/versions"
done

corepack enable >/dev/null 2>&1 || true
pnpm install --frozen-lockfile --ignore-pnpmfile
if command -v apt-get >/dev/null 2>&1; then
    pnpm exec playwright install --with-deps "${ELEMENT_CALL_PROJECT:-chromium}"
else
    # Playwright's dependency installer only supports apt-based hosts. On
    # Fedora and similar systems, use the host's already installed libraries.
    pnpm exec playwright install "${ELEMENT_CALL_PROJECT:-chromium}"
fi

# shellcheck disable=SC2206
specs=(${ELEMENT_CALL_SPECS:-$DEFAULT_SPECS})
set +e
USE_DOCKER=1 PLAYWRIGHT_JSON_OUTPUT_NAME="$results" \
    pnpm exec playwright test --project "${ELEMENT_CALL_PROJECT:-chromium}" \
    --reporter=json "${specs[@]/#/playwright/}"
status=$?
set -e
echo "element-call: playwright exited $status; results in $results"
python3 "$toplevel/scripts/element-call-check.py" "$results" --allowlist "$contrib/$allowlist"
