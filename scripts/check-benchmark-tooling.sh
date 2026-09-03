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
# The title matches the h1 and the nav label, which both said
# "micro-benchmarks" while the title said "benchmarks" — this page is
# specifically not the four-way comparison, and the tab should say so.
grep -q "Spindle micro-benchmarks" "$work/index.html"
# The shared theme really is shared: tokens present, nav marking this page.
grep -q -- "--accent: #7c3aed" "$work/index.html"
grep -q 'href="./index.html" aria-current="page"' "$work/index.html"
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

# The spread is rendered, not just consulted. Under each ratio sits the
# band the rounds allow -- their fastest against our slowest, to their
# slowest against our fastest -- and a call is exactly a band that
# excludes 1.0x. Overlap: rival 2-4 ms over spindle 1-3 ms is 0.67x-4.00x,
# which straddles 1; clear: 5-6 ms over 1.0-1.2 ms is 4.17x-6.00x.
bands = re.findall(r'<span class="band">([^<]*)</span>', text)
assert "0.67–4.00×" in bands, f"the overlapping cell's band is not shown: {bands}"
assert "4.17–6.00×" in bands, f"the separated cell's band is not shown: {bands}"
# Both sides carry their median and range in the tooltip. The rival used to
# get a bare median, which invited reading it as exact.
assert "rival 3.00 ms (3 rounds, 2.00–4.00)" in text, "the rival's spread is missing"
assert "spindle 2.00 ms (3 rounds, 1.00–3.00)" in text, "spindle's spread is missing"
# And the charts draw the range as a band behind the median line.
assert '<polygon class="band"' in text, "the charts do not draw the observed range"
print("rounds: median and observed range rendered for both sides, in cells and charts")
PY

# The terminal comparison reads the same rule as the page, from the same
# round files, so a sitting run through compare-against.sh is judged the
# way it will be judged once committed.
python3 "$here/compare-benchmarks.py" \
    "$rounds/m9-overlap.spindle.r*.json" "$rounds/m9-overlap.rival.r*.json" > "$work/overlap.txt"
grep -q "overlapping" "$work/overlap.txt"
grep -q "2.00 (1.00–3.00)" "$work/overlap.txt"
if grep -q "faster" "$work/overlap.txt"; then
    echo "compare-benchmarks called an overlapping cell" >&2
    exit 1
fi
python3 "$here/compare-benchmarks.py" \
    "$rounds/m9-clear.spindle.r*.json" "$rounds/m9-clear.rival.r*.json" > "$work/clear.txt"
grep -q "faster" "$work/clear.txt"
grep -q "4.17–6.00×" "$work/clear.txt"
echo "compare-benchmarks: rounds summarised as median and range, called by the same rule as the page"

# A single-round sitting has no spread to read, so the band is assumed --
# and the assumption has to be the one the host was measured to have. Six
# rounds of the same binary moved the median cell 1.38x (docs/benchmarks.md),
# so a 1.2x single-round cell is not a result in either direction, and the
# page used to print it green while its own caption said to ignore it.
single="$work/single"
mkdir -p "$single"
python3 - "$single" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
def write(server, values):
    (out / f"m9-single.{server}.json").write_text(json.dumps({
        "server": server,
        "base_url": "http://127.0.0.1:0",
        "dimension": "events",
        "sizes": [200],
        "samples": 1,
        "benchmarks": {
            f"{operation}/200": {
                "mean_ns": value, "lower_ns": value,
                "upper_ns": value, "samples": 1,
            }
            for operation, value in values.items()
        },
    }))
# inside: 1.20x, under this host's repeatability. clears: 3.00x, well over.
# behind: 0.83x, a "loss" the old band printed red and no round can support.
write("spindle", {"inside": 1.0e6, "clears": 1.0e6, "behind": 1.2e6})
write("rival", {"inside": 1.2e6, "clears": 3.0e6, "behind": 1.0e6})
PY
python3 "$here/render-comparisons.py" "$single" "$work/single.html" >/dev/null
python3 - "$work/single.html" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
rows = {}
for row in re.findall(r"<tr><td><strong>.*?</tr>", text, re.S):
    name = re.search(r"<code>(.*?)</code>", row)
    if name:
        rows[name.group(1)] = re.findall(r'<td class="num ([a-z ]+)"[^>]*>([^<]*)', row)
assert rows["inside"] == [("noise", "1.20×")], (
    f"a 1.20x single-round cell was coloured: {rows['inside']}"
)
assert rows["behind"] == [("noise", "0.83×")], (
    f"a 0.83x single-round cell was called a loss: {rows['behind']}"
)
assert rows["clears"][0][0] == "win", (
    f"a 3.00x single-round cell was not called: {rows['clears']}"
)
assert "1 round(s) per server" in text, "the sitting was not labelled unresolved"
# No range was measured, so none may be drawn: a band of one round would be
# a precision the sitting never had.
assert 'class="band"' not in text, "a single-round sitting was given a spread"
print("comparisons: a single round colours only what clears the host's own variance")
PY

# The old two-file form still works -- one round a side -- and says it is
# unresolved rather than calling the 1.20x cell.
python3 "$here/compare-benchmarks.py" \
    "$single/m9-single.spindle.json" "$single/m9-single.rival.json" > "$work/single.txt"
grep -q "unresolved" "$work/single.txt"
grep -q "faster" "$work/single.txt"
echo "compare-benchmarks: a single round a side is printed as unresolved below the measured floor"

# Multiplicity. The separation rule bounds the false-call rate for one cell,
# and a table is many cells: at three rounds a side it is one in ten, so
# eighteen cells expect nearly two calls from luck alone (#183). The page has
# to say so, and has to mark a call that nothing else supports -- because the
# arithmetic says how many are spurious, never which.
lone="$work/lone"
mkdir -p "$lone"
python3 - "$lone" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
def write(server, rnd, values):
    (out / f"m9-lone.{server}.r{rnd}.json").write_text(json.dumps({
        "server": server,
        "base_url": "http://127.0.0.1:0",
        "dimension": "events",
        "round": rnd,
        "sizes": sorted(values),
        "samples": 1,
        "benchmarks": {
            f"{operation}/{size}": {
                "mean_ns": value, "lower_ns": value,
                "upper_ns": value, "samples": 1,
            }
            for size, ops in values.items()
            for operation, value in ops.items()
        },
    }))
# `scales` is called at both sizes and in the same direction -- the shape a
# real per-item cost takes. `only_here` is called at 200 and overlaps at 50:
# one call, nothing agreeing with it.
for rnd, bump in ((1, 0.0), (2, 0.1e6), (3, 0.05e6)):
    write("spindle", rnd, {
        50: {"scales": 1.0e6 + bump, "only_here": 2.0e6 + bump},
        200: {"scales": 2.0e6 + bump, "only_here": 1.0e6 + bump},
    })
for rnd, bump in ((1, 0.0), (2, 0.1e6), (3, 0.05e6)):
    write("rival", rnd, {
        50: {"scales": 5.0e6 + bump, "only_here": 2.0e6 + bump},
        200: {"scales": 9.0e6 + bump, "only_here": 5.0e6 + bump},
    })
PY
python3 "$here/render-comparisons.py" "$lone" "$work/lone.html" >/dev/null
python3 - "$work/lone.html" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
rows = {}
for row in re.findall(r"<tr><td><strong>.*?</tr>", text, re.S):
    name = re.search(r"<code>(.*?)</code>", row)
    if name:
        rows[name.group(1)] = re.findall(r'<td class="num ([a-z ]+)"', row)

assert rows["scales"] == ["win", "win"], (
    f"a call agreeing across sizes was marked as standing alone: {rows['scales']}"
)
assert rows["only_here"].count("win lone") == 1, (
    f"a call with nothing agreeing with it was not marked: {rows['only_here']}"
)
# The count has to be stated, not merely implied by the marker: four
# comparable cells at three rounds expect 4 * 2/C(6,3) = 0.4 by chance.
assert "<strong>4</strong>" in text, "the table's cell count is not reported"
assert "<strong>0.4</strong>" in text, (
    "the expected number of chance calls is not reported"
)
print("comparisons: chance-call count reported; unsupported calls are marked")
PY
