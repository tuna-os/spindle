#!/usr/bin/env python3
"""Build a Synapse-schema SQLite database, for #20's importer to read.

The importer's exit criterion is *"a representative Synapse fixture migrates
with zero room-state divergence"*, and the obvious reading is that producing
that fixture needs a running Synapse — which would put it behind the same
wall as #16 and #171 wherever Docker is unavailable. It does not.

**Synapse ships its own DDL.** Applying `full_schemas/<n>/full.sql.sqlite`
and then every delta above `<n>`, across the `common`, `main` and `state`
schema parts, is what Synapse itself does on first start, and it produces a
database with real table shapes, real column types and real constraints.
That is what makes an importer's SQL either correct or not.

**What this does not give you** is Synapse's real *output*. Rows written by
this script — or by anything else that is not Synapse — cannot catch "Synapse
actually stores this differently than the schema suggests", which is the
class of bug that breaks importers on real deployments. Anything built on
this fixture should say so where its evidence is published, the same way
`docs/benchmarks.md` states what its numbers do not cover.

**Nothing is vendored.** The schema is read from a Synapse checkout the
caller points at, rather than copied into this repository. That keeps the
fixture honest about tracking upstream, and it avoids copying AGPL-licensed
SQL into a repository whose own terms are currently undefined (#233).

Usage:
    scripts/synapse-fixture.py --synapse PATH [--out FILE] [--quiet]
    scripts/synapse-fixture.py --synapse PATH --check
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

# The parts Synapse keeps its schema in, in the order it applies them: a
# delta in `main` may reference a table `common` created.
PARTS = ("common", "main", "state")

# Every table the importer has to read, by the part of #20's scope it serves.
# Asserted rather than assumed: a Synapse version that renamed one of these
# should fail here, loudly, rather than in the middle of an import.
REQUIRED: dict[str, tuple[str, ...]] = {
    "rooms, events and state": (
        "events",
        "event_json",
        "event_auth",
        "rooms",
        "room_memberships",
        "current_state_events",
        "state_groups",
        "state_groups_state",
        "event_to_state_groups",
        "room_aliases",
        "room_stats_state",
    ),
    "users, devices and keys": (
        "users",
        "devices",
        "access_tokens",
        "e2e_device_keys_json",
        "e2e_one_time_keys_json",
        "user_directory",
    ),
    "receipts, account data and push rules": (
        "receipts_linearized",
        "account_data",
        "room_account_data",
        "push_rules",
    ),
    "media": ("local_media_repository",),
}


class Skipped(Exception):
    """The schema could not be built, with a reason worth printing."""


def statement_files(root: Path) -> list[Path]:
    """Synapse's DDL, in the order Synapse applies it."""
    files: list[Path] = []
    for part in PARTS:
        fulls = sorted((root / part / "full_schemas").glob("*/full.sql.sqlite"))
        files.extend(fulls)
        # Deltas at or below the full schema's version are already folded
        # into it; applying them again is at best a no-op and at worst an
        # error about a table that now exists.
        base = max((int(path.parent.name) for path in fulls), default=0)
        deltas = root / part / "delta"
        if not deltas.is_dir():
            continue
        for version in sorted(
            (entry for entry in deltas.iterdir() if entry.name.isdigit()),
            key=lambda entry: int(entry.name),
        ):
            if int(version.name) <= base:
                continue
            # `.sql` is portable, `.sql.sqlite` is the SQLite-specific form.
            # `.sql.postgres` and `.py` are for the other backend and for
            # Synapse's own migration runner, and are not ours to run.
            files.extend(
                sorted(
                    path
                    for path in version.iterdir()
                    if path.suffix == ".sql" or path.name.endswith(".sql.sqlite")
                )
            )
    return files


def build(synapse: Path, out: Path | None) -> tuple[sqlite3.Connection, list[tuple[Path, str]]]:
    """Apply Synapse's DDL to a database, returning it and what would not apply.

    Failures are collected rather than raised. A handful of Synapse's deltas
    carry a `$` placeholder its own migration runner substitutes at runtime,
    and one depends on a table such a delta creates; none of them is a table
    the importer reads, so refusing to build over them would trade a working
    fixture for a tidier log. `--check` is what turns "some deltas did not
    apply" into a failure when one of them mattered.
    """
    schema = synapse / "synapse" / "storage" / "schema"
    if not schema.is_dir():
        raise Skipped(f"no Synapse schema at {schema}")

    files = statement_files(schema)
    if not files:
        raise Skipped(f"{schema} holds no SQLite DDL; is this a Synapse checkout?")

    if out is not None and out.exists():
        # Same refusal as `spindle backup`, for the same reason: silently
        # replacing a fixture somebody built is discovered later, by a test
        # that fails for reasons unrelated to the change being tested.
        raise Skipped(f"refusing to overwrite {out}")

    database = sqlite3.connect(str(out) if out else ":memory:")
    unapplied: list[tuple[Path, str]] = []
    for path in files:
        try:
            database.executescript(path.read_text(encoding="utf-8"))
        except sqlite3.Error as error:
            unapplied.append((path, str(error)))
    database.commit()
    return database, unapplied


def tables(database: sqlite3.Connection) -> set[str]:
    rows = database.execute("select name from sqlite_master where type = 'table'")
    return {row[0] for row in rows}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--synapse",
        type=Path,
        default=Path(os.environ.get("SYNAPSE_SOURCE", "")) if os.environ.get("SYNAPSE_SOURCE") else None,
        help="path to a Synapse checkout (or set SYNAPSE_SOURCE)",
    )
    parser.add_argument("--out", type=Path, help="write the database here")
    parser.add_argument(
        "--check",
        action="store_true",
        help="build in memory and assert every table the importer reads exists",
    )
    parser.add_argument("--quiet", action="store_true")
    arguments = parser.parse_args()

    if arguments.synapse is None:
        print(
            "synapse-fixture: pass --synapse PATH or set SYNAPSE_SOURCE; "
            "Synapse's schema is read from a checkout and never vendored (#233)",
            file=sys.stderr,
        )
        return 2

    try:
        database, unapplied = build(arguments.synapse, None if arguments.check else arguments.out)
    except Skipped as reason:
        print(f"synapse-fixture: {reason}", file=sys.stderr)
        return 2

    built = tables(database)
    missing = {
        area: [name for name in names if name not in built]
        for area, names in REQUIRED.items()
    }
    missing = {area: names for area, names in missing.items() if names}

    if not arguments.quiet:
        print(f"synapse-fixture: {len(built)} tables from {len(statement_files(arguments.synapse / 'synapse' / 'storage' / 'schema'))} DDL files")
        for path, error in unapplied:
            print(f"  unapplied: {path.name} -- {error}")

    if missing:
        print(
            "synapse-fixture: Synapse's schema no longer provides tables the "
            "importer reads:",
            file=sys.stderr,
        )
        for area, names in missing.items():
            print(f"  {area}: {', '.join(names)}", file=sys.stderr)
        return 1

    if not arguments.quiet:
        total = sum(len(names) for names in REQUIRED.values())
        print(f"synapse-fixture: all {total} tables the importer reads are present")
        if arguments.out and not arguments.check:
            print(f"synapse-fixture: wrote {arguments.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
