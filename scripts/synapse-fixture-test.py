#!/usr/bin/env python3
"""Tests for `synapse-fixture.py`, run in CI as a plain script.

Same convention as `complement-check-test.py`: plain asserts and a non-zero
exit, no pytest, because this repository has no Python test harness and two
test files are still not the reason to acquire one.

Most of these build a **synthetic** Synapse-shaped tree rather than needing a
real checkout, so they run in CI where no Synapse exists. That is not a
compromise: the ordering rules are the part with judgement in them — which
files to apply, in which order, and which to leave to Synapse's own migration
runner — and a three-file tree exercises them as sharply as a hundred-file
one, while making the expected answer something a reader can check by eye.

The one test that does need a checkout skips cleanly without one, and says so.

Usage: python3 scripts/synapse-fixture-test.py
"""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "synapse-fixture.py"


def load_module():
    spec = importlib.util.spec_from_file_location("synapse_fixture", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def fake_checkout(root: Path) -> Path:
    """A Synapse-shaped tree with one of every case that matters."""
    schema = root / "synapse" / "storage" / "schema"
    write(
        schema / "common" / "full_schemas" / "10" / "full.sql.sqlite",
        "CREATE TABLE common_base (id INTEGER);",
    )
    # At the full schema's version: already folded in, must be skipped.
    write(schema / "common" / "delta" / "10" / "01_already_folded_in.sql", "SELECT bad syntax;")
    # Above it: must be applied.
    write(schema / "common" / "delta" / "11" / "01_applied.sql", "CREATE TABLE from_delta (id INTEGER);")
    # Not ours to run: the other backend, and Synapse's own migration runner.
    write(schema / "common" / "delta" / "11" / "02_postgres_only.sql.postgres", "SELECT bad syntax;")
    write(schema / "common" / "delta" / "11" / "03_runner.py", "raise SystemExit('never run')")
    # Ordering across versions: 9 sorts after 11 as a string, before it as a
    # number, and this delta depends on the one in 11.
    write(
        schema / "common" / "delta" / "100" / "01_depends_on_11.sql",
        "CREATE TABLE needs_from_delta AS SELECT * FROM from_delta;",
    )
    write(schema / "main" / "full_schemas" / "1" / "full.sql.sqlite", "CREATE TABLE main_base (id INTEGER);")
    return root


def run_script(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "SYNAPSE_SOURCE": ""},
    )


def test_deltas_at_or_below_the_full_schema_are_skipped():
    """Applying one again is at best a no-op and at worst an error."""
    module = load_module()
    with tempfile.TemporaryDirectory() as work:
        root = fake_checkout(Path(work))
        files = module.statement_files(root / "synapse" / "storage" / "schema")
        names = [path.name for path in files]

    assert "01_already_folded_in.sql" not in names, names


def test_the_other_backend_and_the_migration_runner_are_left_alone():
    module = load_module()
    with tempfile.TemporaryDirectory() as work:
        root = fake_checkout(Path(work))
        names = [path.name for path in module.statement_files(root / "synapse" / "storage" / "schema")]

    assert "02_postgres_only.sql.postgres" not in names, names
    assert "03_runner.py" not in names, names


def test_deltas_are_ordered_numerically_not_lexically():
    """`100` sorts before `11` as a string. A delta that depends on an
    earlier one would then fail, and the failure would look like Synapse's
    schema being broken rather than this script's ordering."""
    module = load_module()
    with tempfile.TemporaryDirectory() as work:
        root = fake_checkout(Path(work))
        names = [path.name for path in module.statement_files(root / "synapse" / "storage" / "schema")]

    assert names.index("01_applied.sql") < names.index("01_depends_on_11.sql"), names


def test_a_synthetic_tree_builds_and_the_dependent_delta_applied():
    module = load_module()
    with tempfile.TemporaryDirectory() as work:
        root = fake_checkout(Path(work))
        database, unapplied = module.build(root, None)
        built = module.tables(database)

    assert not unapplied, unapplied
    assert {"common_base", "from_delta", "needs_from_delta", "main_base"} <= built, built


def test_a_missing_required_table_fails_the_check():
    """The whole point of --check: a Synapse that renamed a table the
    importer reads should fail here, loudly, rather than mid-import."""
    with tempfile.TemporaryDirectory() as work:
        root = fake_checkout(Path(work))
        result = run_script("--synapse", str(root), "--check")

    assert result.returncode == 1, result.stdout + result.stderr
    assert "no longer provides tables the importer reads" in result.stderr, result.stderr
    # Named by area, so the reader knows which part of #20 just lost ground.
    assert "rooms, events and state" in result.stderr, result.stderr


def test_something_that_is_not_a_synapse_checkout_is_refused():
    with tempfile.TemporaryDirectory() as work:
        result = run_script("--synapse", work)

    assert result.returncode == 2, result.stdout + result.stderr
    assert "no Synapse schema at" in result.stderr, result.stderr


def test_no_path_at_all_says_where_the_schema_comes_from():
    result = run_script()
    assert result.returncode == 2, result.stdout + result.stderr
    assert "--synapse" in result.stderr, result.stderr
    # The reason nothing is vendored is worth carrying into the error.
    assert "never vendored" in result.stderr, result.stderr


def test_an_existing_fixture_is_not_overwritten():
    """Same refusal as `spindle backup`: silently replacing a fixture is
    discovered later, by a test failing for unrelated-looking reasons."""
    with tempfile.TemporaryDirectory() as work:
        root = fake_checkout(Path(work))
        out = Path(work) / "fixture.db"
        out.write_text("not a database", encoding="utf-8")
        result = run_script("--synapse", str(root), "--out", str(out))

        assert result.returncode == 2, result.stdout + result.stderr
        assert "refusing to overwrite" in result.stderr, result.stderr
        assert out.read_text(encoding="utf-8") == "not a database", "the file was touched"


def test_a_real_synapse_checkout_provides_every_table(skipped: list[str]):
    """The claim recorded on #20, as a test rather than a one-off measurement.

    Skipped where no checkout is available, which is most of CI. Point
    SYNAPSE_SOURCE at one to run it.
    """
    source = os.environ.get("SYNAPSE_SOURCE")
    if not source or not (Path(source) / "synapse" / "storage" / "schema").is_dir():
        skipped.append("no Synapse checkout; set SYNAPSE_SOURCE to run this one")
        return

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--synapse", source, "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "tables the importer reads are present" in result.stdout, result.stdout


def minimal_room(**broken: bool) -> sqlite3.Connection:
    """The columns `verify_populated` reads, and nothing else.

    Not Synapse's DDL -- column *names*, which are interface rather than
    something to copy. That keeps these runnable in CI, where no Synapse
    checkout exists, while the end-to-end build stays behind SYNAPSE_SOURCE.
    """
    module = load_module()
    database = sqlite3.connect(":memory:")
    database.executescript(
        """
        CREATE TABLE event_edges (event_id TEXT, prev_event_id TEXT, is_state BOOL);
        CREATE TABLE events (event_id TEXT, outlier BOOL, rejection_reason TEXT);
        CREATE TABLE current_state_events (event_id TEXT, room_id TEXT, type TEXT, state_key TEXT);
        """
    )
    child, parent = module.LEGACY_STATE_EDGE
    real_parent = next(
        event[3][0] for event in module.TIMELINE if event[0] == child
    )
    database.execute(
        "INSERT INTO event_edges VALUES (?, ?, 0)", (child, real_parent)
    )
    # The mutation under test: the legacy edge written as a real DAG edge.
    database.execute(
        "INSERT INTO event_edges VALUES (?, ?, ?)",
        (child, parent, 0 if broken.get("legacy_edge") else 1),
    )
    database.execute(
        "INSERT INTO events VALUES (?, ?, NULL)",
        (module.OUTLIER[0], 0 if broken.get("outlier") else 1),
    )
    database.execute(
        "INSERT INTO events VALUES (?, 0, ?)",
        (module.REJECTED[0], None if broken.get("rejection") else module.REJECTION_REASON),
    )
    for (event_type, state_key), event_id in module.CURRENT_STATE.items():
        if broken.get("state") and event_type == "m.room.topic":
            continue
        database.execute(
            "INSERT INTO current_state_events VALUES (?, ?, ?, ?)",
            (event_id, module.ROOM_ID, event_type, state_key),
        )
    return database


def test_a_correctly_written_room_verifies_clean():
    module = load_module()
    problems = module.verify_populated(minimal_room())
    assert problems == [], problems


def test_a_legacy_edge_written_as_a_real_one_is_caught():
    """The whole reason the edge is in the fixture. Unfiltered, it fabricates
    a merge that never happened -- and a fabricated merge looks like data, not
    like an error."""
    module = load_module()
    problems = module.verify_populated(minimal_room(legacy_edge=True))
    assert any("not marked is_state" in problem for problem in problems), problems
    assert any("exactly one real parent" in problem for problem in problems), problems


def test_an_unflagged_outlier_is_caught():
    module = load_module()
    problems = module.verify_populated(minimal_room(outlier=True))
    assert any("outlier" in problem for problem in problems), problems


def test_a_rejection_missing_from_events_is_caught():
    """`events.rejection_reason` is where modern Synapse records a rejection.
    A fixture carrying it only in the older `rejections` table would let a
    reader that never looks at the column pass."""
    module = load_module()
    problems = module.verify_populated(minimal_room(rejection=True))
    assert any("rejection_reason" in problem for problem in problems), problems


def test_current_state_drift_is_caught():
    module = load_module()
    problems = module.verify_populated(minimal_room(state=True))
    assert any("current_state_events" in problem for problem in problems), problems


def test_populate_against_a_real_checkout(skipped: list[str]):
    """The end-to-end build, where the schema is Synapse's own.

    Skipped where no checkout is available, which is most of CI. Point
    SYNAPSE_SOURCE at one to run it.
    """
    source = os.environ.get("SYNAPSE_SOURCE")
    if not source or not (Path(source) / "synapse" / "storage" / "schema").is_dir():
        skipped.append("no Synapse checkout; set SYNAPSE_SOURCE to run this one")
        return

    with tempfile.TemporaryDirectory() as work:
        out = Path(work) / "populated.db"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--synapse", source, "--out", str(out), "--populate"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "legacy is_state edge" in result.stdout, result.stdout

        module = load_module()
        database = sqlite3.connect(str(out))
        assert module.verify_populated(database) == []
        # And the room really is readable the way a reader would read it.
        rows = database.execute(
            "SELECT COUNT(*) FROM events WHERE room_id = ? AND NOT outlier "
            "AND rejection_reason IS NULL",
            (module.ROOM_ID,),
        ).fetchone()
        assert rows[0] == len(module.TIMELINE), rows


def main() -> int:
    skipped: list[str] = []
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    failures = 0
    for test in tests:
        wants_skips = "skipped" in test.__code__.co_varnames[: test.__code__.co_argcount]
        before = len(skipped)
        try:
            test(skipped) if wants_skips else test()
        except AssertionError as error:
            failures += 1
            print(f"FAIL {test.__name__}: {error}", file=sys.stderr)
        else:
            if len(skipped) > before:
                print(f"skip {test.__name__}: {skipped[-1]}")
            else:
                print(f"ok   {test.__name__}")
    if failures:
        print(f"\n{failures} of {len(tests)} failed", file=sys.stderr)
        return 1
    print(f"\nall {len(tests) - len(skipped)} passed, {len(skipped)} skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
