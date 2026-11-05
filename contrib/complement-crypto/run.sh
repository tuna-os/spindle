#!/usr/bin/env bash
# complement-crypto against Spindle: matrix-js-sdk clients, in headless
# Chrome, doing E2EE through two Spindles and a mitmproxy -- one-time key
# claims, to-device delivery, device-list changes over federation, key
# backup, verification (docs/conformance-testing.md section 4.2). Upstream
# runs it against Synapse's Complement image; here the same pinned suite
# runs against complement/Dockerfile, unforked.
#
#   contrib/complement-crypto/run.sh [results.jsonl]
#
#   COMPLEMENT_IMAGE  the Spindle image to test (default: builds
#                     complement/Dockerfile as complement-spindle:latest)
#   CRYPTO_SRC        a complement-crypto checkout (default: the pin below,
#                     fetched into tmp/complement-crypto-src)
#   CRYPTO_MATRIX     client permutations (default jj,jJ: two JS clients on
#                     one Spindle, then the same pair across two Spindles,
#                     which is where device lists travel by federation)
#   CRYPTO_RUN        a go -run filter (default: every test)
#
# JS SDK clients only. The Rust SDK's clients need the FFI bindings built
# through a forked uniffi-bindgen-go, a second Rust tree on the runner;
# matrix-rust-sdk's own integration suite already drives Spindle nightly
# (contrib/rust-sdk), so the JS half is the coverage this adds.
#
# Needs Docker, Go, Node with corepack, and Chrome (the GitHub runner image
# ships it). Failing tests are data, not an error: this exits non-zero only
# when the run produced no results at all, which means the rig, not the
# server, is what broke.
set -euo pipefail

# Bump deliberately: what a newer suite asks of the server is what somebody
# should read before CI asks it.
COMPLEMENT_CRYPTO_REV=38a76041346f64a384f569e090248ff947a1ecd3
# What the pinned suite's own yarn.lock resolves `matrix-js-sdk@^41` to;
# named here so the client is a pin rather than whatever ^41 means today.
JS_SDK_VERSION=41.5.0
# The proxy image the pinned suite starts (internal/deploy/deploy.go).
# Pulled up front so a registry hiccup fails in seconds, not mid-suite.
MITMPROXY_IMAGE=mitmproxy/mitmproxy:10.1.5

toplevel="$(git rev-parse --show-toplevel)"
cd "$toplevel"
results="${1:-tmp/complement-crypto/results.jsonl}"
mkdir -p "$(dirname "$results")"
results="$(cd "$(dirname "$results")" && pwd)/$(basename "$results")"
logs="$(dirname "$results")"

if [[ -z "${COMPLEMENT_IMAGE:-}" ]]; then
    COMPLEMENT_IMAGE=complement-spindle:latest
    docker build -f complement/Dockerfile -t "$COMPLEMENT_IMAGE" .
fi
docker pull --quiet "$MITMPROXY_IMAGE"

if [[ -z "${CRYPTO_SRC:-}" ]]; then
    CRYPTO_SRC="$toplevel/tmp/complement-crypto-src"
    if [[ ! -d "$CRYPTO_SRC/.git" ]]; then
        mkdir -p "$CRYPTO_SRC"
        git -C "$CRYPTO_SRC" init -q
    fi
    git -C "$CRYPTO_SRC" fetch -q --depth 1 https://github.com/matrix-org/complement-crypto.git "$COMPLEMENT_CRYPTO_REV"
    git -C "$CRYPTO_SRC" checkout -q FETCH_HEAD
fi

# The browser bundle the JS clients load, built from the pinned SDK.
(cd "$CRYPTO_SRC" && ./rebuild_js_sdk.sh "matrix-js-sdk@$JS_SDK_VERSION")
# The multiprocess client. Without it the suite skips the tests that kill
# and restart a client, which are the ones about keys surviving a crash.
(cd "$CRYPTO_SRC" && go build -tags=jssdk -o rpc ./cmd/rpc)

echo "complement-crypto: suite $COMPLEMENT_CRYPTO_REV, matrix-js-sdk $JS_SDK_VERSION," \
    "every homeserver is $COMPLEMENT_IMAGE"

# The environment upstream's own workflow sets (single_sdk_tests.yml):
# dirty runs because the suite deploys once and shares the servers, and no
# ryuk, which upstream found killing mitmproxy partway through.
: > "$results"
(
    cd "$CRYPTO_SRC"
    export COMPLEMENT_BASE_IMAGE="$COMPLEMENT_IMAGE"
    export COMPLEMENT_ENABLE_DIRTY_RUNS=1
    export TESTCONTAINERS_RYUK_DISABLED=true
    export COMPLEMENT_CRYPTO_TEST_CLIENT_MATRIX="${CRYPTO_MATRIX:-jj,jJ}"
    export COMPLEMENT_CRYPTO_RPC_BINARY="$CRYPTO_SRC/rpc"
    export COMPLEMENT_CRYPTO_MITMDUMP="$logs/mitm.dump"
    go test ./tests -tags=jssdk -count 1 -p 2 -timeout 45m -json \
        ${CRYPTO_RUN:+-run "$CRYPTO_RUN"} || true
) | tee -a "$results" | python3 "$toplevel/scripts/complement-progress.py" || true
# The suite writes each client's console and each server's log here.
cp -r "$CRYPTO_SRC/tests/logs" "$logs/" 2>/dev/null || true

# Nothing is protected yet, so the check only reports: every passing test
# is printed as a candidate, and an empty ledger -- the rig never ran a
# test -- is the one outcome that fails.
python3 scripts/complement-check.py "$results" --allowlist /dev/null
