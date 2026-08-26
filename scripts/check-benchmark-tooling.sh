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

python3 "$here/render-benchmarks.py" "$work/latest.json" "$work/index.html"
grep -q "Spindle benchmarks" "$work/index.html"
grep -q "demo group/ours/1" "$work/index.html"
# The humanising must not silently drop precision to zero.
grep -q "100 ns" "$work/index.html"
echo "render: page built and contains the measurements"

# An empty result set must fail rather than publish, because a page with no
# rows reads as "everything got fast" rather than as "the collector broke".
empty="$work/empty"
mkdir -p "$empty"
if python3 "$here/collect-benchmarks.py" "$empty" "$work/nope.json" 2>/dev/null; then
    echo "collector accepted an empty run; that would publish a blank page" >&2
    exit 1
fi
echo "collect: an empty run is refused"
