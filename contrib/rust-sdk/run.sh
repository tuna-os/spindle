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
#   RUST_SDK_TESTS a filter passed to `cargo test` (default: everything)
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
# Every test runs whatever the others did (--no-fail-fast), one at a time
# (they share a homeserver and register fixed names), and the log is the
# record the checker reads. cargo's own exit status is not the verdict:
# the allowlist is.
echo "--- running the suite against $S"
set +e
HOMESERVER_URL="$S" HOMESERVER_DOMAIN="$SERVER_NAME" \
  cargo ${RUST_SDK_TOOLCHAIN:+"+$RUST_SDK_TOOLCHAIN"} test --manifest-path "$RUST_SDK_SRC/Cargo.toml" -p matrix-sdk-integration-testing \
  --no-fail-fast -- --test-threads 1 ${RUST_SDK_TESTS:-} 2>&1 | tee "$RESULTS"
set -e
python3 "$root/scripts/rust-sdk-check.py" "$RESULTS"
