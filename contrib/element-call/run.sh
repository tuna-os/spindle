#!/usr/bin/env bash
# Run Element Call's own Playwright suite against Spindle (#269, the gate
# #41 asks for). No fork: upstream element-hq/element-call at a pinned
# revision, its docker-compose-dev.yml and docker-compose-playwright.yml
# untouched, with docker-compose-spindle.yml putting Spindle in Synapse's
# two seats. A change upstream cannot repaint our results without a
# revision bump here, beside a re-baselined allowlist.
#
#   contrib/element-call/run.sh [results.json]
#
# Environment:
#   ELEMENT_CALL_SRC    existing checkout (default: clones the pin into
#                       tmp/element-call)
#   SPINDLE_IMAGE       image to run (default: builds complement/Dockerfile)
#   ELEMENT_CALL_SPECS  spec files to run, relative to the checkout's
#                       playwright/ (default: the subset below)
#   ELEMENT_CALL_PROJECT  playwright project (default: chromium)
#
# Needs docker with compose, node at the checkout's .node-version and
# corepack for pnpm -- the same things upstream's own CI needs.
#
# The subset is every SPA spec that needs only a browser, a homeserver
# that registers and logs users in, a room and a call: the landing and
# access specs of #269's stage 1, and the call specs -- create-call,
# spa-call-sticky (MatrixRTC 2.0 and the improper-leave case), the two
# reconnect specs and errors. Running a spec costs a minute; protecting
# it is the allowlist's decision, so the default runs wide. The widget
# and restricted-sfu specs register users through Synapse's admin API with
# a shared secret, which this server does not serve, and are out of scope
# until they are made to use /register.
set -euo pipefail

ELEMENT_CALL_REV=a03f23e7206fa7d45911ec3da6af988452804614
DEFAULT_SPECS="landing.spec.ts access.spec.ts create-call.spec.ts spa-call-sticky.spec.ts reconnect.spec.ts sfu-reconnect-bug.spec.ts errors.spec.ts"

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
echo "element-call: $(git rev-parse HEAD) with $SPINDLE_IMAGE as both homeservers"

# Upstream's stack, with the override last so it wins.
compose=(docker compose -f docker-compose-dev.yml -f docker-compose-playwright.yml \
    -f "$contrib/docker-compose-spindle.yml")
cleanup() {
    "${compose[@]}" logs --no-color synapse synapse-1 > "$(dirname "$results")/spindle.log" 2>&1 || true
    "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
"${compose[@]}" pull --ignore-buildable --quiet || true
"${compose[@]}" up -d

# The homeservers answer before anything is asked of them, bounded, and
# the log says which one did not.
for site in synapse.m.localhost synapse.othersite.m.localhost; do
    for _ in $(seq 1 60); do
        if curl -fsSk --resolve "$site:443:127.0.0.1" "https://$site/_matrix/client/versions" >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    curl -fsSk --resolve "$site:443:127.0.0.1" "https://$site/_matrix/client/versions" >/dev/null \
        || { echo "element-call: $site never answered /versions" >&2; exit 1; }
    echo "element-call: $site is up"
done

corepack enable >/dev/null 2>&1 || true
pnpm install --frozen-lockfile --ignore-pnpmfile
pnpm exec playwright install --with-deps "${ELEMENT_CALL_PROJECT:-chromium}"

# shellcheck disable=SC2206
specs=(${ELEMENT_CALL_SPECS:-$DEFAULT_SPECS})
set +e
USE_DOCKER=1 PLAYWRIGHT_JSON_OUTPUT_NAME="$results" \
    pnpm exec playwright test --project "${ELEMENT_CALL_PROJECT:-chromium}" \
    --reporter=json "${specs[@]/#/playwright/}"
status=$?
set -e
echo "element-call: playwright exited $status; results in $results"
python3 "$toplevel/scripts/element-call-check.py" "$results"
