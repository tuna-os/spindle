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

# A members sweep and an events sweep are different x-axes. The renderer must
# label each from the results rather than assuming events -- and must refuse a
# group that mixes them, because that chart would be wrong rather than merely
# mislabelled.
axes="$work/axes"
mkdir -p "$axes"
python3 - "$axes" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
def doc(server, dimension, sizes, value):
    return {
        "server": server,
        "base_url": "http://127.0.0.1:0",
        "dimension": dimension,
        "sizes": sizes,
        "samples": 1,
        "benchmarks": {
            f"sliding_window/{size}": {
                "mean_ns": value, "lower_ns": value, "upper_ns": value, "samples": 1
            }
            for size in sizes
        },
    }
for name, server, value in (("spindle", "spindle", 1e6), ("rival", "rival", 2e6)):
    (out / f"m9-members.{name}.json").write_text(
        json.dumps(doc(server, "members", [50, 200], value))
    )
# The mixed group: same sitting, two different axes.
(out / "m9-mixed.spindle.json").write_text(json.dumps(doc("spindle", "members", [50], 1e6)))
(out / "m9-mixed.rival.json").write_text(json.dumps(doc("rival", "events", [50], 2e6)))
PY

# With the mixed group present the renderer must refuse outright.
if python3 "$here/render-comparisons.py" "$axes" "$work/axes.html" 2>/dev/null; then
    echo "comparisons renderer charted two different x-axes as one" >&2
    exit 1
fi
echo "comparisons: a group mixing events and members on one axis is refused"

rm "$axes/m9-mixed.spindle.json" "$axes/m9-mixed.rival.json"
python3 "$here/render-comparisons.py" "$axes" "$work/axes.html" >/dev/null
grep -q "joined members in room" "$work/axes.html"
if grep -q "events in room" "$work/axes.html"; then
    echo "a members sweep was labelled as an events sweep" >&2
    exit 1
fi
echo "comparisons: a members sweep is labelled by what it measured"

# Rounds. One round cannot tell a real difference from this host's run-to-run
# variance (#171), so the renderer calls a cell only when the two servers'
# rounds separate -- and must refuse to call one when they overlap, however
# far apart the medians sit.
rounds="$work/rounds"
mkdir -p "$rounds"
python3 - "$rounds" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
def write(group, server, rnd, value):
    (out / f"{group}.{server}.r{rnd}.json").write_text(json.dumps({
        "server": server,
        "base_url": "http://127.0.0.1:0",
        "dimension": "events",
        "round": rnd,
        "sizes": [200],
        "samples": 1,
        "benchmarks": {"send/200": {
            "mean_ns": value, "lower_ns": value, "upper_ns": value, "samples": 1
        }},
    }))
# Overlapping: spindle 1.0-3.0 ms, rival 2.0-4.0 ms. The medians are 2.0 and
# 3.0 -- a 1.50x "win" a single round would have printed in green.
for rnd, value in ((1, 1e6), (2, 3e6), (3, 2e6)):
    write("m9-overlap", "spindle", rnd, value)
for rnd, value in ((1, 2e6), (2, 4e6), (3, 3e6)):
    write("m9-overlap", "rival", rnd, value)
# Separated: spindle 1.0-1.2 ms, rival 5.0-6.0 ms. Nothing crosses.
for rnd, value in ((1, 1.0e6), (2, 1.2e6), (3, 1.1e6)):
    write("m9-clear", "spindle", rnd, value)
for rnd, value in ((1, 5e6), (2, 6e6), (3, 5.5e6)):
    write("m9-clear", "rival", rnd, value)
PY
python3 "$here/render-comparisons.py" "$rounds" "$work/rounds.html" >/dev/null
grep -q "Measured over <strong>3 rounds</strong>" "$work/rounds.html"
python3 - "$work/rounds.html" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
found = re.findall(r'<td class="num (win|loss|noise)"[^>]*>([^<]*)', text)
kinds = {kind for kind, _ in found}
assert "noise" in kinds, f"the overlapping cell was called, not held: {found}"
assert "win" in kinds, f"the separated cell was not called: {found}"
# And the overlapping one must not have been printed as a win.
overlap = [c for c in found if c[1].startswith("1.50")]
assert overlap and overlap[0][0] == "noise", f"a 1.50x overlap was coloured: {overlap}"
print("rounds: overlapping rounds are not called; separated rounds are")
PY
