#!/usr/bin/env bash
#
# Run the Complement suite against the Spindle image and write a results
# ledger. No fork: upstream matrix-org/complement, pinned to a revision so a
# suite change upstream cannot repaint our results without a diff here.
#
#   scripts/complement.sh [results.jsonl]
#
# Environment:
#   COMPLEMENT_SRC   existing Complement checkout (default: clones the pin)
#   COMPLEMENT_IMAGE image tag to test (default: builds complement/Dockerfile)
#   COMPLEMENT_RUN   go -run filter (default: everything in the packages below)
set -euo pipefail

# Bump deliberately, with the allowlist re-baselined in the same commit.
COMPLEMENT_REV=6d2fdc286c2b44faaddd1037205869b2242a4005
PACKAGES=("./tests/csapi" "./tests")

results="${1:-tmp/complement-results.jsonl}"
toplevel="$(git rev-parse --show-toplevel)"
cd "$toplevel"
mkdir -p "$(dirname "$results")"

if [[ -z "${COMPLEMENT_IMAGE:-}" ]]; then
    COMPLEMENT_IMAGE=complement-spindle:latest
    docker build -f complement/Dockerfile -t "$COMPLEMENT_IMAGE" .
fi

if [[ -z "${COMPLEMENT_SRC:-}" ]]; then
    COMPLEMENT_SRC="$toplevel/tmp/complement-src"
    if [[ ! -d "$COMPLEMENT_SRC" ]]; then
        git clone https://github.com/matrix-org/complement.git "$COMPLEMENT_SRC"
    fi
    git -C "$COMPLEMENT_SRC" fetch --quiet origin "$COMPLEMENT_REV"
    git -C "$COMPLEMENT_SRC" checkout --quiet "$COMPLEMENT_REV"
fi

# `go test` exiting nonzero is expected — failing tests are data, not an
# error; the gate is scripts/complement-check.py against the allowlist.
#
# The ledger is the machine-readable record and goes to the file verbatim;
# the same stream also passes through complement-progress.py so a watcher
# sees each test land. Without that, ten minutes of testing look exactly
# like ten minutes of hanging.
: > "$results"
for package in "${PACKAGES[@]}"; do
    (
        cd "$COMPLEMENT_SRC"
        COMPLEMENT_BASE_IMAGE="$COMPLEMENT_IMAGE" \
            go test "$package" -count 1 -timeout 45m -json \
            ${COMPLEMENT_RUN:+-run "$COMPLEMENT_RUN"} || true
    ) | tee -a "$results" | python3 "$toplevel/scripts/complement-progress.py" || true
done
echo "complement: results in $results"
