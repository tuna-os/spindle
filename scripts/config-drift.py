#!/usr/bin/env python3
"""Fail when a config field exists in the code but not in the example.

`spindle.example.toml` is the only place an operator finds out that a setting
exists. Nothing held it to the code, and it drifted: when this check was
written, **22 of 37 fields had never appeared in it** — the whole of S3 media
storage, rate limiting, URL previews, federation TLS, appservice
registrations, and every credential in `[auth.delegated]`.

None of that was a bug in the server. It was a server whose features could
not be found, which for an operator is the same thing.

Two directions, and the code already covers one of them. `Config` and its
sub-structs carry `#[serde(deny_unknown_fields)]`, so an example naming a
field the code has *removed* fails to parse, and `config_example_parses` in
the server's test suite makes that a test failure rather than a surprise at
someone's first boot. This script covers the other direction, which nothing
was watching: a field added to the code and never written down.

Deliberate omissions go in OMITTED below, with the reason, so that skipping
one is a decision somebody made rather than an oversight nobody noticed.

Usage: scripts/config-drift.py [--config PATH] [--example PATH]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Fields that exist in the code and deliberately do not appear in the example.
# Keep the reason: it is the difference between an exemption and a hole.
OMITTED: dict[str, str] = {}


def fields_in(source: str) -> dict[str, list[str]]:
    """struct name -> its `pub` field names, in declaration order."""
    found: dict[str, list[str]] = {}
    current: str | None = None
    for line in source.splitlines():
        opened = re.match(r"\s*pub struct (\w+)", line)
        if opened:
            current = opened.group(1)
            found.setdefault(current, [])
            continue
        if current is None:
            continue
        if line.strip() == "}":
            current = None
            continue
        field = re.match(r"\s*pub (\w+):", line)
        if field:
            found[current].append(field.group(1))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=Path("crates/spindle-server/src/config.rs")
    )
    parser.add_argument("--example", type=Path, default=Path("spindle.example.toml"))
    arguments = parser.parse_args()

    structs = fields_in(arguments.config.read_text(encoding="utf-8"))
    example = arguments.example.read_text(encoding="utf-8")

    # A field counts as documented if its name appears at all — commented out
    # is fine, and is the right shape for a setting with no default. This is a
    # deliberately loose test: it catches "nobody wrote this down", which is
    # the failure that actually happened, without pretending to verify prose.
    missing: list[tuple[str, str]] = []
    for struct, fields in sorted(structs.items()):
        for field in fields:
            if field in OMITTED:
                continue
            if not re.search(rf"\b{re.escape(field)}\b", example):
                missing.append((struct, field))

    total = sum(len(fields) for fields in structs.values())
    if missing:
        print(
            f"config-drift: {len(missing)} of {total} config fields are not in "
            f"{arguments.example}:",
            file=sys.stderr,
        )
        for struct, field in missing:
            print(f"  {struct}.{field}", file=sys.stderr)
        print(
            "\nAdd them to the example with a line on what they are for, or "
            "add them to OMITTED in this script with the reason. A setting an "
            "operator cannot discover is a setting that does not exist.",
            file=sys.stderr,
        )
        return 1

    skipped = f", {len(OMITTED)} deliberately omitted" if OMITTED else ""
    print(
        f"config-drift: all {total - len(OMITTED)} config fields are documented "
        f"in {arguments.example}{skipped}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
