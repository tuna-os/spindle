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
    scripts/synapse-fixture.py --synapse PATH [--out FILE] [--populate] [--quiet]
    scripts/synapse-fixture.py --synapse PATH --check
"""

from __future__ import annotations

import argparse
import json
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


# The room the fixture holds, as a list of events in causal order. Each entry
# is (event_id, type, state_key, prev_events, content).
#
# Deliberately small and deliberately awkward. Every entry is here because it
# is a case the importer has to get right, and a fixture of a hundred ordinary
# messages exercises none of them:
#
# - a fork on two *different* state slots, the arrangement that regressed once
#   already (#225) and which an import is how you find;
# - an outlier, held for somebody else's auth chain and not part of the room;
# - a rejected event, which never entered the room's state and must not enter
#   Spindle's;
# - a legacy `is_state` edge -- see `LEGACY_STATE_EDGE`.
ROOM_ID = "!fixture:example.org"
ROOM_VERSION = "11"
ALICE = "@alice:example.org"
BOB = "@bob:example.org"

TIMELINE: tuple[tuple[str, str, str | None, tuple[str, ...], dict], ...] = (
    ("$create", "m.room.create", "", (), {"room_version": ROOM_VERSION}),
    ("$alice", "m.room.member", ALICE, ("$create",), {"membership": "join"}),
    ("$rules", "m.room.join_rules", "", ("$alice",), {"join_rule": "public"}),
    ("$bob", "m.room.member", BOB, ("$rules",), {"membership": "join"}),
    ("$hello", "m.room.message", None, ("$bob",), {"msgtype": "m.text", "body": "hello"}),
    # The fork: two branches from `$hello`, each moving a slot the other does
    # not touch, and a merge naming both.
    ("$topic", "m.room.topic", "", ("$hello",), {"topic": "a topic"}),
    ("$name", "m.room.name", "", ("$hello",), {"name": "a name"}),
    (
        "$merge",
        "m.room.message",
        None,
        ("$topic", "$name"),
        {"msgtype": "m.text", "body": "merged"},
    ),
)

# Held to check somebody's auth chain. Not part of this room's timeline, and
# an import that takes it puts history into a room that was never in it.
OUTLIER = (
    "$outlier",
    "m.room.member",
    "@mallory:elsewhere.example",
    ("$create",),
    {"membership": "join"},
)

# Synapse refused it. `events.rejection_reason` is where modern Synapse records
# that -- *not* a boolean column, and not only the older `rejections` table,
# both of which are easy to assume and wrong.
REJECTED = ("$rejected", "m.room.power_levels", "", ("$merge",), {"users": {BOB: 100}})
REJECTION_REASON = "auth_error"

# `event_edges` once held two different kinds of edge: the event DAG, and a
# link to the previous state event. The state ones are marked `is_state` and
# have been removed from the code and the schema -- but by a *background
# update*, so Synapse's own queries still say `AND edge.is_state is FALSE` and
# note that "it's not necessarily safe to assume that it will have been
# completed".
#
# A reader that selects every row of `event_edges` therefore invents a parent
# on any database old enough to still carry one, and builds a DAG that is not
# the room's -- silently, because the result is a plausible merge rather than
# an error. The fixture carries one so a reader ignoring the flag fails here
# rather than on somebody's deployment.
LEGACY_STATE_EDGE = ("$topic", "$rules")

# The state the room ends in, which is what an import is checked against. Both
# forked slots survive: they moved different keys.
CURRENT_STATE = {
    ("m.room.create", ""): "$create",
    ("m.room.member", ALICE): "$alice",
    ("m.room.member", BOB): "$bob",
    ("m.room.join_rules", ""): "$rules",
    ("m.room.topic", ""): "$topic",
    ("m.room.name", ""): "$name",
}


def populate(database: sqlite3.Connection) -> None:
    """Write one room into a database that already carries Synapse's schema.

    These rows are **synthesized**, not produced by Synapse. The schema they go
    into is real, so a reader's SQL is either right or wrong against it; what
    this cannot catch is Synapse storing something differently than its own
    schema suggests. Anything published on the strength of this fixture has to
    say so.
    """
    database.execute(
        "INSERT INTO rooms (room_id, is_public, creator, room_version, "
        "has_auth_chain_index) VALUES (?, ?, ?, ?, ?)",
        (ROOM_ID, True, ALICE, ROOM_VERSION, False),
    )
    for user in (ALICE, BOB):
        database.execute(
            "INSERT INTO users (name, password_hash, creation_ts, admin, is_guest) "
            "VALUES (?, ?, ?, ?, ?)",
            (user, None, 1_700_000_000, 0, 0),
        )

    ordering = 0
    for event_id, event_type, state_key, prev_events, content in (
        *TIMELINE,
        OUTLIER,
        REJECTED,
    ):
        ordering += 1
        outlier = event_id == OUTLIER[0]
        rejection = REJECTION_REASON if event_id == REJECTED[0] else None
        sender = state_key if state_key not in (None, "") else ALICE
        database.execute(
            "INSERT INTO events (stream_ordering, topological_ordering, event_id, "
            "type, room_id, content, processed, outlier, depth, origin_server_ts, "
            "sender, state_key, rejection_reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ordering,
                ordering,
                event_id,
                event_type,
                ROOM_ID,
                json.dumps(content),
                True,
                outlier,
                ordering,
                1_700_000_000_000 + ordering,
                sender,
                state_key,
                rejection,
            ),
        )
        pdu = {
            "auth_events": [],
            "content": content,
            "depth": ordering,
            "origin_server_ts": 1_700_000_000_000 + ordering,
            "prev_events": list(prev_events),
            "room_id": ROOM_ID,
            "sender": sender,
            "type": event_type,
        }
        if state_key is not None:
            pdu["state_key"] = state_key
        database.execute(
            "INSERT INTO event_json (event_id, room_id, internal_metadata, json, "
            "format_version) VALUES (?, ?, ?, ?, ?)",
            (event_id, ROOM_ID, json.dumps({"outlier": outlier}), json.dumps(pdu), 3),
        )
        for parent in prev_events:
            database.execute(
                "INSERT INTO event_edges (event_id, prev_event_id, room_id, is_state) "
                "VALUES (?, ?, ?, ?)",
                (event_id, parent, ROOM_ID, False),
            )
        if event_type == "m.room.member":
            database.execute(
                "INSERT INTO room_memberships (event_id, user_id, sender, room_id, "
                "membership, event_stream_ordering) VALUES (?, ?, ?, ?, ?, ?)",
                (event_id, state_key, sender, ROOM_ID, content["membership"], ordering),
            )
        if rejection is not None:
            database.execute(
                "INSERT INTO rejections (event_id, reason, last_check) VALUES (?, ?, ?)",
                (event_id, rejection, "1700000000"),
            )

    child, parent = LEGACY_STATE_EDGE
    database.execute(
        "INSERT INTO event_edges (event_id, prev_event_id, room_id, is_state) "
        "VALUES (?, ?, ?, ?)",
        (child, parent, ROOM_ID, True),
    )

    for (event_type, state_key), event_id in CURRENT_STATE.items():
        membership = "join" if event_type == "m.room.member" else None
        database.execute(
            "INSERT INTO current_state_events (event_id, room_id, type, state_key, "
            "membership) VALUES (?, ?, ?, ?, ?)",
            (event_id, ROOM_ID, event_type, state_key, membership),
        )
    database.commit()


def verify_populated(database: sqlite3.Connection) -> list[str]:
    """Check the written room still says what it was written to say.

    Not a test of this script -- a test of the *schema it wrote into*. The rows
    above are only useful while Synapse's columns still mean what they meant
    when they were written, and the failure if that changes is a fixture that
    loads fine and quietly stops carrying the case it exists for. So the build
    checks its own work rather than handing back a fixture without the trap.
    """
    problems: list[str] = []

    def one(query: str, *parameters: object) -> object:
        row = database.execute(query, parameters).fetchone()
        return row[0] if row else None

    def parents(query: str, *parameters: object) -> list[str]:
        return [row[0] for row in database.execute(query, parameters)]

    child, parent = LEGACY_STATE_EDGE
    every = parents("SELECT prev_event_id FROM event_edges WHERE event_id = ?", child)
    honest = parents(
        "SELECT prev_event_id FROM event_edges WHERE event_id = ? AND is_state = 0",
        child,
    )
    if parent not in every:
        problems.append(f"the legacy is_state edge {child} <- {parent} is missing")
    if parent in honest:
        problems.append(f"the legacy edge {child} <- {parent} is not marked is_state")
    if len(honest) != 1:
        problems.append(f"{child} should have exactly one real parent, has {honest}")

    if one("SELECT COUNT(*) FROM events WHERE outlier") != 1:
        problems.append("the outlier is not recorded as one")
    if one("SELECT rejection_reason FROM events WHERE event_id = ?", REJECTED[0]) is None:
        problems.append(
            f"{REJECTED[0]} has no events.rejection_reason; a reader looking only at "
            "the older `rejections` table would still pass, which is the point"
        )

    state = {
        (row[0], row[1]): row[2]
        for row in database.execute(
            "SELECT type, state_key, event_id FROM current_state_events WHERE room_id = ?",
            (ROOM_ID,),
        )
    }
    if state != CURRENT_STATE:
        problems.append(f"current_state_events does not match: {state}")

    return problems


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
    parser.add_argument(
        "--populate",
        action="store_true",
        help="also write one room, shaped to exercise the importer's hard cases",
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

    problems: list[str] = []
    if arguments.populate:
        populate(database)
        problems = verify_populated(database)

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

    if problems:
        print(
            "synapse-fixture: the room was written but no longer holds what it was "
            "written to hold:",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

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
        if arguments.populate:
            print(
                f"synapse-fixture: wrote {ROOM_ID} -- {len(TIMELINE)} timeline "
                "events, 1 outlier, 1 rejected, 1 legacy is_state edge"
            )
        if arguments.out and not arguments.check:
            print(f"synapse-fixture: wrote {arguments.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
