#!/usr/bin/env python3
"""Tests for `ruma-drift.py`, run in CI as a plain script.

No pytest, for the reason complement-check-test.py gives: plain asserts
and a non-zero exit read the same way in a CI log.

What is worth testing is the judgement in both directions: the surface
check passes the patch SPINDLE-PATCH.md lists and refuses anything more,
and the drift report fails on a released change to src/ but not on one
that is only on upstream's main. The synthetic cases run offline; the last
test runs the check against the real vendored tree and a copy of it with a
hunk injected, which needs the base crate from crates.io and says so when
it cannot be fetched.

Usage: python3 scripts/ruma-drift-test.py
"""

from __future__ import annotations

import importlib.util
import pathlib
import shutil
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ruma_drift", HERE / "ruma-drift.py")
drift = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drift)

UPSTREAM_SRC = "".join(f"fn upstream_{n}() {{}}\n" for n in range(40)).encode()
BASE = {
    "Cargo.toml": b'[package]\nname = "ruma-state-res"\nversion = "0.18.0"\n',
    "CHANGELOG.md": b"# 0.18.0\n",
    "src/state_res.rs": UPSTREAM_SRC,
    "src/lib.rs": b"pub mod state_res;\n",
}


def patched_tree() -> dict[str, bytes]:
    """The base with a one-hunk patch, an added note and a dropped changelog."""
    tree = dict(BASE)
    tree["src/state_res.rs"] = UPSTREAM_SRC.replace(
        b"fn upstream_10() {}\n", b"fn upstream_10() { spindle(); }\n"
    )
    tree["SPINDLE-PATCH.md"] = b"the note\n"
    tree["Cargo.lock"] = b"# whatever the last test build resolved\n"
    del tree["CHANGELOG.md"]
    return tree


def note_for(base: dict[str, bytes], vendored: dict[str, bytes]) -> str:
    """A SPINDLE-PATCH.md listing exactly the surface between the two trees,
    with Cargo.lock as tooling output."""
    rows = [
        f"| `{row.file}` | {f'`{row.hunk}`' if row.digest else row.hunk} | {f'`{row.digest}`' if row.digest else ''} | why |"
        for row in drift.surface(base, vendored)
        if row.file != "Cargo.lock"
    ]
    rows.append("| `Cargo.lock` | regenerated | | tooling output |")
    return "\n".join(
        [
            "# Note",
            "",
            drift.SURFACE_HEADING,
            "",
            "| File | Hunk | Digest | Why |",
            "|---|---|---|---|",
            *rows,
            "",
            "## After",
            "",
        ]
    )


def test_the_listed_patch_passes():
    vendored = patched_tree()
    assert drift.check(BASE, vendored, note_for(BASE, vendored)) == []


def test_an_extra_hunk_fails_and_is_printed():
    vendored = patched_tree()
    note = note_for(BASE, vendored)
    vendored["src/state_res.rs"] = vendored["src/state_res.rs"].replace(
        b"fn upstream_30() {}\n", b"fn upstream_30() { quietly_more(); }\n"
    )
    problems = drift.check(BASE, vendored, note)
    assert any(
        "src/state_res.rs: hunk @@" in p
        and "+fn upstream_30() { quietly_more(); }" in p
        for p in problems
    ), problems
    assert any("--hunks" in p for p in problems), problems


def test_editing_a_listed_hunk_fails():
    vendored = patched_tree()
    note = note_for(BASE, vendored)
    vendored["src/state_res.rs"] = vendored["src/state_res.rs"].replace(
        b"spindle();", b"spindle(); more();"
    )
    problems = drift.check(BASE, vendored, note)
    assert any("is not listed" in p for p in problems), problems
    assert any("no longer has it" in p for p in problems), problems


def test_a_reverted_hunk_fails():
    # A listed hunk that is gone means the table no longer describes the
    # patch; the table is fixed, not left to describe a different tree.
    vendored = patched_tree()
    note = note_for(BASE, vendored)
    vendored["src/state_res.rs"] = UPSTREAM_SRC
    problems = drift.check(BASE, vendored, note)
    assert any("src/state_res.rs" in p and "no longer has it" in p for p in problems), (
        problems
    )


def test_an_unlisted_new_file_fails():
    vendored = patched_tree()
    note = note_for(BASE, vendored)
    vendored["src/spindle_extra.rs"] = b"pub fn more() {}\n"
    problems = drift.check(BASE, vendored, note)
    assert any("src/spindle_extra.rs: added" in p for p in problems), problems


def test_a_regenerated_file_may_change_freely():
    vendored = patched_tree()
    note = note_for(BASE, vendored)
    vendored["Cargo.lock"] = b"# a different resolution\n"
    assert drift.check(BASE, vendored, note) == []


def test_a_newline_only_change_is_a_hunk():
    rows = drift.file_hunks("src/lib.rs", b"a\nb\n", b"a\nb")
    assert len(rows) == 1 and rows[0].digest, rows


def report(release_tree, main_tree):
    info = drift.Base("0.18.0", "0" * 64, "1" * 40)
    return drift.upstream_report(
        info,
        BASE,
        ("0.19.0", release_tree),
        ("2" * 40, main_tree),
        {"src/state_res.rs"},
    )


def test_a_released_change_to_src_is_drift():
    released = dict(
        BASE, **{"src/state_res.rs": UPSTREAM_SRC + b"fn upstream_fix() {}\n"}
    )
    lines, status = report(released, released)
    text = "\n".join(lines)
    assert status == 1, text
    assert "Spindle patches this file" in text, text
    assert "+fn upstream_fix() {}" in text, text


def test_a_change_only_on_main_warns_without_failing():
    on_main = dict(BASE, **{"src/state_res.rs": UPSTREAM_SRC + b"fn unreleased() {}\n"})
    lines, status = report(dict(BASE), on_main)
    text = "\n".join(lines)
    assert status == 0, text
    assert "+fn unreleased() {}" in text and "No drift" in text, text


def test_a_release_changing_only_packaging_is_not_drift():
    release = dict(
        BASE, **{"Cargo.toml": BASE["Cargo.toml"].replace(b"0.18.0", b"0.19.0")}
    )
    _, status = report(release, dict(BASE))
    assert status == 0


def test_the_real_vendored_tree_and_an_injected_hunk():
    info = drift.read_base()
    with tempfile.TemporaryDirectory(prefix="ruma-drift-test-") as tmp:
        work = pathlib.Path(tmp)
        (work / "base").mkdir()
        try:
            base = drift.fetch_crate(info.version, info.checksum, work / "base")
        except SystemExit as error:
            print(
                f"skip test_the_real_vendored_tree_and_an_injected_hunk: no base crate ({error})"
            )
            return
        note = drift.NOTE.read_text()
        assert drift.check(base, drift.read_tree(drift.VENDOR), note) == []

        copy = work / "vendored"
        shutil.copytree(drift.VENDOR, copy)
        source = copy / "src" / "state_res.rs"
        text = source.read_text()
        anchor = 'info!("state resolution starting");'
        assert anchor in text
        source.write_text(
            text.replace(
                anchor, anchor + '\n    debug!("one more line nobody listed");', 1
            )
        )
        problems = drift.check(base, drift.read_tree(copy), note)
        assert any("one more line nobody listed" in p for p in problems), problems


def main() -> int:
    tests = [
        value for name, value in sorted(globals().items()) if name.startswith("test_")
    ]
    failed = 0
    for test in tests:
        try:
            test()
        except AssertionError as error:
            failed += 1
            print(f"FAIL {test.__name__}: {error}")
        else:
            print(f"ok   {test.__name__}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
