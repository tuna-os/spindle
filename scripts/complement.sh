#!/usr/bin/env bash
#
# Run the Complement suite against the Spindle image and write a results
# ledger. No fork: upstream matrix-org/complement, pinned to a revision so a
# suite change upstream cannot repaint our results without a diff here.
#
#   scripts/complement.sh [results.jsonl]
#
# Environment:
#   COMPLEMENT_SRC            existing Complement checkout (default: clones the pin)
#   COMPLEMENT_IMAGE          image tag to test (default: builds complement/Dockerfile)
#   COMPLEMENT_INTEROP_IMAGE  peer image tag for interop (e.g. ghcr.io/element-hq/synapse/complement-synapse:latest)
#   COMPLEMENT_INTEROP_HS     which homeserver gets the peer image: "hs2" (default) or "hs1" (inverse)
#   COMPLEMENT_BASE_IMAGE_hs1 explicit hs1 image override (must be lowercase)
#   COMPLEMENT_BASE_IMAGE_hs2 explicit hs2 image override (must be lowercase)
#   COMPLEMENT_RUN            go -run filter (default: everything in the packages below)
#   COMPLEMENT_TAGS           build tags to pass to go test (optional)
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

# Configure homeserver image mappings for homogeneous or heterogeneous (interop) runs.
# Upstream Complement deployer looks up overrides by lowercase blueprint name (e.g. hs1, hs2).
base_image="$COMPLEMENT_IMAGE"
hs1_override="${COMPLEMENT_BASE_IMAGE_hs1:-}"
hs2_override="${COMPLEMENT_BASE_IMAGE_hs2:-}"

if [[ -n "${COMPLEMENT_INTEROP_IMAGE:-}" ]]; then
    target_hs="${COMPLEMENT_INTEROP_HS:-hs2}"
    if [[ "$target_hs" == "hs1" ]]; then
        # Inverse interop: hs1 is peer (e.g. Synapse), hs2 is Spindle
        base_image="${COMPLEMENT_INTEROP_IMAGE}"
        hs2_override="$COMPLEMENT_IMAGE"
        echo "complement: running inverse interop (hs1=$base_image, hs2=$hs2_override)"
    else
        # Standard interop: hs1 is Spindle, hs2 is peer (e.g. Synapse)
        base_image="$COMPLEMENT_IMAGE"
        hs2_override="${COMPLEMENT_INTEROP_IMAGE}"
        echo "complement: running interop (hs1=$base_image, hs2=$hs2_override)"
    fi
elif [[ -n "$hs1_override" || -n "$hs2_override" ]]; then
    echo "complement: running with explicit overrides (base=$base_image, hs1=${hs1_override:-default}, hs2=${hs2_override:-default})"
else
    echo "complement: running homogeneous suite (image=$base_image)"
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
        COMPLEMENT_BASE_IMAGE="$base_image" \
        ${hs1_override:+COMPLEMENT_BASE_IMAGE_hs1="$hs1_override"} \
        ${hs2_override:+COMPLEMENT_BASE_IMAGE_hs2="$hs2_override"} \
            go test "$package" -count 1 -timeout 45m -json \
            ${COMPLEMENT_TAGS:+-tags="$COMPLEMENT_TAGS"} \
            ${COMPLEMENT_RUN:+-run "$COMPLEMENT_RUN"} || true
    ) | tee -a "$results" | python3 "$toplevel/scripts/complement-progress.py" || true
done
echo "complement: results in $results"
