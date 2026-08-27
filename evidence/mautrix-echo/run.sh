#!/usr/bin/env bash
# Run the mautrix-go evidence harness against a freshly built Spindle.
#
# Not wired into CI: it needs a Go toolchain and network access for the
# mautrix module. The committed transcript in docs/evidence records what
# a passing run looks like; this script reproduces it.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(git rev-parse --show-toplevel)"

HS_PORT=28448
AS_PORT=29333
NAME="127.0.0.1:${HS_PORT}"
WORK="$(mktemp -d)"
trap 'kill "${SPINDLE_PID:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

cargo build -p spindle-server --quiet --manifest-path "$ROOT/Cargo.toml"

cat > "$WORK/registration.yaml" <<EOF
id: evidence
url: "http://127.0.0.1:${AS_PORT}"
as_token: as_evidence_token
hs_token: hs_evidence_token
sender_localpart: _bridge_bot
receive_ephemeral: true
namespaces:
  users:
    - exclusive: true
      regex: "@_bridge_.*:.*"
EOF

cat > "$WORK/config.toml" <<EOF
[server]
name = "${NAME}"
bind = "127.0.0.1:${HS_PORT}"
[storage]
path = "${WORK}/data"
[ratelimit]
enabled = false
[federation]
retry_base_ms = 50
[appservices]
registrations = ["${WORK}/registration.yaml"]
EOF

"$ROOT/target/debug/spindle" "$WORK/config.toml" &
SPINDLE_PID=$!
for _ in $(seq 1 50); do
    curl -sf "http://${NAME}/_matrix/client/versions" >/dev/null && break
    sleep 0.2
done

SPINDLE_URL="http://${NAME}" SPINDLE_NAME="${NAME}" go run .
