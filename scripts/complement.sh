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
#
# Heterogeneous federation (docs/conformance-testing.md §5.1, #16) is the
# same run with another implementation's image on one homeserver:
#   COMPLEMENT_INTEROP_IMAGE  the peer's image, e.g.
#                             ghcr.io/element-hq/synapse/complement-synapse:latest
#   COMPLEMENT_INTEROP_HS     which homeserver it plays: hs2 (default), so
#                             Spindle drives every test and the peer answers
#                             federation, or hs1, the inverse, where the peer
#                             drives and single-server tests exercise it alone
# Complement's own COMPLEMENT_BASE_IMAGE_hs1 / _hs2 overrides pass through
# untouched for any other pairing. The suffix must be lowercase: upstream
# stores it verbatim and looks it up by the blueprint's lowercase name, so
# COMPLEMENT_BASE_IMAGE_HS2 is silently ignored and the run quietly stays
# homogeneous. The interop variables above are lowercased here for that
# reason, and the run says which image plays which server so a log can be
# checked against what was meant.
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

interop_hs=""
if [[ -n "${COMPLEMENT_INTEROP_IMAGE:-}" ]]; then
    interop_hs="${COMPLEMENT_INTEROP_HS:-hs2}"
    interop_hs="${interop_hs,,}"
    if [[ "$interop_hs" != hs1 && "$interop_hs" != hs2 ]]; then
        echo "complement: COMPLEMENT_INTEROP_HS must be hs1 or hs2, not '$interop_hs'" >&2
        exit 2
    fi
    # Pulled here rather than left to the blueprint build, so a peer image
    # that cannot be fetched fails before ten minutes of setup, and so the
    # log records which build of a moving tag the run actually federated
    # with: `latest` is a pointer, the digest is the peer.
    docker pull "$COMPLEMENT_INTEROP_IMAGE"
    echo "complement: $interop_hs is $COMPLEMENT_INTEROP_IMAGE" \
        "($(docker image inspect --format '{{index .RepoDigests 0}}' "$COMPLEMENT_INTEROP_IMAGE" 2>/dev/null || echo 'no digest'))"
    echo "complement: every other homeserver is $COMPLEMENT_IMAGE"
else
    echo "complement: homogeneous, every homeserver is $COMPLEMENT_IMAGE"
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
        export COMPLEMENT_BASE_IMAGE="$COMPLEMENT_IMAGE"
        if [[ -n "$interop_hs" ]]; then
            export "COMPLEMENT_BASE_IMAGE_${interop_hs}=$COMPLEMENT_INTEROP_IMAGE"
        fi
        go test "$package" -count 1 -timeout 45m -json \
            ${COMPLEMENT_RUN:+-run "$COMPLEMENT_RUN"} || true
    ) | tee -a "$results" | python3 "$toplevel/scripts/complement-progress.py" || true
done
echo "complement: results in $results"
