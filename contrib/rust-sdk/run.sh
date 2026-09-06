#!/usr/bin/env bash
# matrix-rust-sdk's own integration suite against Spindle: the library
# under Element X, driving registration, sync, E2EE, backups and the rest
# the way the flagship client does, with nothing forked and nothing
# patched. Upstream runs it against a Synapse started with its CI
# configuration (registration open, rate limits off, experimental
# features on); here the same tests run against a Spindle started the
# same way, and contrib/rust-sdk/allowlist.txt is the ratchet over what
# passes, enforced by scripts/rust-sdk-check.py.
#
#   contrib/rust-sdk/run.sh [results.log]
#
#   RUST_SDK_SRC   a checkout of matrix-org/matrix-rust-sdk (cloned at the
#                  pin below when unset)
#   SPINDLE_BIN    the server (default target/release/spindle)
#   RUST_SDK_TESTS a filter on test names (default: everything)
#   RUST_SDK_TEST_TIMEOUT
#                  seconds one test may take before it is killed and
#                  recorded as failed (default 180)
#   RUST_SDK_TOOLCHAIN
#                  a rustup toolchain for the suite's build, when the
#                  SDK's floor is above this repository's pin (0.18 wants
#                  1.93); `cargo +<toolchain>` outranks rust-toolchain.toml
#
# Needs a Rust toolchain, git, curl. Port 8228 on loopback.
set -euo pipefail

RUST_SDK_REV=1c44fb66214667c6d00acaf72ab592493653708b  # matrix-sdk-0.18.0
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
RESULTS="${1:-tmp/rust-sdk/results.log}"
SPINDLE_BIN="${SPINDLE_BIN:-target/release/spindle}"
RUST_SDK_SRC="${RUST_SDK_SRC:-tmp/matrix-rust-sdk}"
HS_PORT=8228
SERVER_NAME="localhost:$HS_PORT"
S="http://127.0.0.1:$HS_PORT"

[[ -x $SPINDLE_BIN ]] || { echo "no server at $SPINDLE_BIN" >&2; exit 1; }
SPINDLE_BIN="$(cd "$(dirname "$SPINDLE_BIN")" && pwd)/$(basename "$SPINDLE_BIN")"
mkdir -p "$(dirname "$RESULTS")"
RESULTS="$(cd "$(dirname "$RESULTS")" && pwd)/$(basename "$RESULTS")"

# --- the suite's source -----------------------------------------------------
if [[ ! -d $RUST_SDK_SRC/.git ]]; then
  echo "--- cloning matrix-rust-sdk at $RUST_SDK_REV"
  mkdir -p "$RUST_SDK_SRC"
  git -C "$RUST_SDK_SRC" init -q
  git -C "$RUST_SDK_SRC" fetch -q --depth 1 https://github.com/matrix-org/matrix-rust-sdk.git "$RUST_SDK_REV"
  git -C "$RUST_SDK_SRC" checkout -q FETCH_HEAD
fi

# --- the server ---------------------------------------------------------------
rig=$(mktemp -d "${TMPDIR:-/tmp}/spindle-rust-sdk.XXXXXX")
cat > "$rig/spindle.toml" <<TOML
[server]
name = "$SERVER_NAME"
bind = "127.0.0.1:$HS_PORT"

[storage]
path = "$rig/data"

[ratelimit]
enabled = false
TOML
"$SPINDLE_BIN" "$rig/spindle.toml" > "$(dirname "$RESULTS")/spindle.log" 2>&1 &
spindle_pid=$!
trap 'kill $spindle_pid 2>/dev/null || true; rm -rf "$rig"' EXIT
for _ in $(seq 1 50); do curl -sf "$S/_matrix/client/versions" >/dev/null && break; sleep 0.2; done
curl -sf "$S/_matrix/client/versions" >/dev/null || { echo "Spindle did not start" >&2; exit 1; }

# --- the suite ----------------------------------------------------------------
# Every test runs whatever the others did, one at a time (they share a
# homeserver and register fixed names), and the log is the record the
# checker reads. cargo's own exit status is not the verdict: the allowlist
# is.
#
# One process per test, each under a timeout, and the test binary run
# directly rather than through `cargo test`. The first dispatch of this
# suite hung: a test that waits on a sync long-poll for an event the server
# will never send has no timeout of its own, and under one `cargo test`
# invocation it held the whole suite until the job's 75-minute limit took
# every later test's verdict with it. `timeout` around cargo would not do
# either -- cargo does not forward the signal, so the test binary would
# outlive it and keep talking to the server the next test is using. The
# binary is killed directly, and the timed-out test is written to the log
# in cargo's own line shape, so the checker reads it as the failure it is.
echo "--- building the suite"
cargo_test=(cargo ${RUST_SDK_TOOLCHAIN:+"+$RUST_SDK_TOOLCHAIN"} test --manifest-path "$RUST_SDK_SRC/Cargo.toml" -p matrix-sdk-integration-testing --lib)
suite_bin=$("${cargo_test[@]}" --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import json,sys
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if m.get("executable") and m.get("target", {}).get("name") == "matrix-sdk-integration-testing":
        print(m["executable"])')
[ -x "$suite_bin" ] || { echo "the suite binary was not built" >&2; exit 1; }

mapfile -t tests < <("$suite_bin" --list --format terse ${RUST_SDK_TESTS:-} | sed -n 's/^\(.*\): test$/\1/p')
echo "--- running ${#tests[@]} tests against $S, ${RUST_SDK_TEST_TIMEOUT:-180}s each"
: > "$RESULTS"
set +e
for name in "${tests[@]}"; do
  HOMESERVER_URL="$S" HOMESERVER_DOMAIN="$SERVER_NAME" \
    timeout --kill-after=10 "${RUST_SDK_TEST_TIMEOUT:-180}" \
    "$suite_bin" --exact "$name" --test-threads 1 2>&1 | tee -a "$RESULTS"
  status=${PIPESTATUS[0]}
  if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
    echo "test $name ... FAILED, timed out after ${RUST_SDK_TEST_TIMEOUT:-180}s" | tee -a "$RESULTS"
  fi
done
set -e
python3 "$root/scripts/rust-sdk-check.py" "$RESULTS"
