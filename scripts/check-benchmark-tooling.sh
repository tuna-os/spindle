#!/usr/bin/env bash
#
# The publishing scripts run on push to main, which is the worst place to
# discover they are broken: the failure lands after the change is already in,
# and the site keeps serving whatever it served last. So they are exercised on
# every pull request against a fixture instead.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

python3 "$here/collect-benchmarks.py" \
    "$here/testdata/criterion" "$work/latest.json" \
    --commit deadbeef --ref main --timestamp 1970-01-01T00:00:00Z --runner fixture

python3 - "$work/latest.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["commit"] == "deadbeef", doc["commit"]
assert doc["runner"] == "fixture", doc["runner"]
marks = doc["benchmarks"]
assert marks["demo group/ours/1"]["mean_ns"] == 100.0, marks
assert marks["demo group/theirs/1"]["mean_ns"] == 200.0, marks
assert marks["demo group/ours/1"]["lower_ns"] == 90.0, marks
print(f"collect: {len(marks)} benchmarks, values intact")
PY

python3 "$here/render-benchmarks.py" "$work/latest.json" "$work/index.html" \
    --repository example/fixture
grep -q "Spindle benchmarks" "$work/index.html"
grep -q "demo group/ours/1" "$work/index.html"
# The humanising must not silently drop precision to zero.
grep -q "100 ns" "$work/index.html"
# The link back to the source is derived from the repository it was told
# about, not baked in. It was baked in once, and pointed at the previous
# owner from the moment the project moved.
grep -q "github.com/example/fixture/blob/main/docs/benchmarks.md" "$work/index.html"
if grep -q "github.com/tuna-os/spindle" "$work/index.html"; then
    echo "the rendered page hardcodes a repository instead of using the one given" >&2
    exit 1
fi
echo "render: page built, measurements intact, source link derived"

# Prose cannot be derived, so it is checked instead: the published-results URL
# in docs/benchmarks.md has to name the repository this actually is. Nothing
# else would have caught the links going stale on a transfer.
if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    owner="${GITHUB_REPOSITORY%%/*}"
    name="${GITHUB_REPOSITORY##*/}"
    expected="https://${owner}.github.io/${name}/"
    if ! grep -qF "$expected" "$here/../docs/benchmarks.md"; then
        echo "docs/benchmarks.md does not point at ${expected}" >&2
        grep -n "github.io" "$here/../docs/benchmarks.md" >&2 || true
        exit 1
    fi
    echo "docs: the published-results URL matches ${GITHUB_REPOSITORY}"
fi

# An empty result set must fail rather than publish, because a page with no
# rows reads as "everything got fast" rather than as "the collector broke".
empty="$work/empty"
mkdir -p "$empty"
if python3 "$here/collect-benchmarks.py" "$empty" "$work/nope.json" 2>/dev/null; then
    echo "collector accepted an empty run; that would publish a blank page" >&2
    exit 1
fi
echo "collect: an empty run is refused"

# The comparisons page renders from the committed milestone results, so the
# committed results themselves are the fixture: every group must have its
# spindle side, every file must parse, and the page must actually carry rows.
python3 "$here/render-comparisons.py" "$here/../docs/benchmarks/data" "$work/comparisons.html"
grep -q "Spindle vs the field" "$work/comparisons.html"
grep -q "m2-progress" "$work/comparisons.html"
grep -q 'class="heatmap"' "$work/comparisons.html"
grep -q "svg" "$work/comparisons.html"
# The page's interactive layer: the animated architecture race, the styled
# heatmap tooltips, and the script that drives counters and chart isolation.
grep -q 'class="archgrid anim"' "$work/comparisons.html"
grep -q 'data-tip=' "$work/comparisons.html"
grep -q 'data-count=' "$work/comparisons.html"
grep -q 'serverchip" data-server=' "$work/comparisons.html"
grep -q "prefers-reduced-motion" "$work/comparisons.html"
echo "comparisons: page built from committed milestone data, charts, heatmap, animation and interactions present"

# And an empty data directory must refuse, same reasoning as the collector.
if python3 "$here/render-comparisons.py" "$empty" "$work/nope.html" 2>/dev/null; then
    echo "comparisons renderer accepted an empty directory" >&2
    exit 1
fi
echo "comparisons: an empty data directory is refused"
