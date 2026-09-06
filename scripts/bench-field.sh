#!/usr/bin/env bash
#
# The field, at its pins: fetch or build every competitor a sitting
# measures against, into BENCH_BIN, and Synapse into SYNAPSE_VENV. Run
# once per machine; a binary that already reports its pinned version is
# kept, so re-running is cheap and a sitting never silently measures a
# different build than the last one.
#
#   BENCH_BIN=tmp/bench-bin SYNAPSE_VENV=tmp/synvenv scripts/bench-field.sh
#
# The pins are the versions docs/benchmarks.md and the site name. Bumping
# one is a reviewed change, because it changes what every later cell is
# compared against.
#
# Needs: curl, git, go (Dendrite), cargo + a C toolchain + liburing-dev
# (Tuwunel's RocksDB), python3 -m venv (Synapse). Continuwuity is a static
# release binary and needs nothing.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=${BENCH_BIN:-tmp/bench-bin}
VENV=${SYNAPSE_VENV:-tmp/synvenv}
SRC=${BENCH_SRC:-tmp/bench-src}
mkdir -p "$BIN" "$SRC"
BIN="$(cd "$BIN" && pwd)"; SRC="$(cd "$SRC" && pwd)"

CONTINUWUITY_VERSION=26.8.1
TUWUNEL_TAG=v1.9.0
DENDRITE_TAG=v0.15.2
SYNAPSE_VERSION=1.160.0

have() { [ -x "$BIN/$1" ] && "$BIN/$1" --version 2>/dev/null | grep -q "$2"; }

# --- Continuwuity: a static release binary from its forge -------------------
if have continuwuity "$CONTINUWUITY_VERSION"; then
  echo "continuwuity $CONTINUWUITY_VERSION: present"
else
  echo "--- continuwuity $CONTINUWUITY_VERSION"
  curl -sSfL -o "$BIN/continuwuity.tmp" \
    "https://forgejo.ellis.link/continuwuation/continuwuity/releases/download/v$CONTINUWUITY_VERSION/conduwuit-linux-static-amd64"
  chmod +x "$BIN/continuwuity.tmp" && mv "$BIN/continuwuity.tmp" "$BIN/continuwuity"
  "$BIN/continuwuity" --version
fi

# --- Tuwunel: from source at its tag. Its release assets are gated, and
# its toolchain pin is its own (rust-toolchain.toml in the checkout), so the
# build uses that and not this repository's.
if have tuwunel "${TUWUNEL_TAG#v}"; then
  echo "tuwunel $TUWUNEL_TAG: present"
else
  echo "--- tuwunel $TUWUNEL_TAG (from source; this is the slow one)"
  if [ ! -d "$SRC/tuwunel/.git" ]; then
    git clone -q --depth 1 --branch "$TUWUNEL_TAG" https://github.com/matrix-construct/tuwunel.git "$SRC/tuwunel"
  fi
  pkg-config --exists liburing || { echo "tuwunel needs liburing-dev (pkg-config cannot find liburing)" >&2; exit 1; }
  ( cd "$SRC/tuwunel" && cargo build --release --bin tuwunel )
  cp "$SRC/tuwunel/target/release/tuwunel" "$BIN/tuwunel"
  "$BIN/tuwunel" --version
fi

# --- Dendrite: from source at its tag; Go makes that a minute -----------
if [ -x "$BIN/dendrite" ] && [ "$(cat "$BIN/dendrite.tag" 2>/dev/null)" = "$DENDRITE_TAG" ]; then
  echo "dendrite $DENDRITE_TAG: present"
else
  echo "--- dendrite $DENDRITE_TAG"
  rm -rf "$SRC/dendrite"
  git clone -q --depth 1 --branch "$DENDRITE_TAG" https://github.com/element-hq/dendrite.git "$SRC/dendrite"
  ( cd "$SRC/dendrite" && go build -o "$BIN/dendrite" ./cmd/dendrite && go build -o "$BIN/generate-keys" ./cmd/generate-keys )
  echo "$DENDRITE_TAG" > "$BIN/dendrite.tag"
fi

# --- Synapse: a virtualenv, not Docker, so it runs on the same host and
# kernel as everyone else (docs/benchmarks.md says why).
if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c "import synapse,sys; sys.exit(synapse.__version__ != '$SYNAPSE_VERSION')" 2>/dev/null; then
  echo "synapse $SYNAPSE_VERSION: present"
else
  echo "--- synapse $SYNAPSE_VERSION"
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet "matrix-synapse==$SYNAPSE_VERSION"
  "$VENV/bin/python" -c "import synapse; print('synapse', synapse.__version__)"
fi

echo "the field is at $BIN (and $VENV)"
