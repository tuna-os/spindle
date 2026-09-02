#!/usr/bin/env python3
"""Keep the README's two headline numbers equal to the gated ones.

The README leads with a route count and a Complement ratchet size and says,
in the same breath, that both are gated so they match `main`. The gates
cover `docs/dashboard.md` (parsed from the router) and
`complement/allowlist.txt` (every entry must pass); the README's copies of
the numbers were typed by hand, and drifted (#310 found 166 against 175).

    scripts/readme-numbers.py --check    # fail if the README's numbers are stale
    scripts/readme-numbers.py --write    # rewrite them from the gated sources

Both numbers are read from the gated artifacts, not recomputed: the route
count from the dashboard's own headline, the ratchet size from the
allowlist's non-comment lines.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
DASHBOARD = REPO / "docs" / "dashboard.md"
ALLOWLIST = REPO / "complement" / "allowlist.txt"

ROUTES = re.compile(r"\*\*(\d+) routes\*\*")
RATCHET = re.compile(r"\*\*(\d+)-test Complement ratchet\*\*")
DASHBOARD_HEADLINE = re.compile(r"\*\*(\d+) routes implemented;")


def gated() -> tuple[int, int]:
    """The numbers the gates hold: routes from the dashboard, tests from the allowlist."""
    headline = DASHBOARD_HEADLINE.search(DASHBOARD.read_text())
    if headline is None:
        sys.exit("readme-numbers: docs/dashboard.md has no routes headline")
    entries = [
        line
        for line in ALLOWLIST.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return int(headline.group(1)), len(entries)


def rewrite(text: str, routes: int, ratchet: int) -> str:
    text, n_routes = ROUTES.subn(f"**{routes} routes**", text, count=1)
    text, n_ratchet = RATCHET.subn(f"**{ratchet}-test Complement ratchet**", text, count=1)
    if n_routes != 1 or n_ratchet != 1:
        sys.exit("readme-numbers: README.md no longer carries the headline sentence")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()

    routes, ratchet = gated()
    current = README.read_text()
    wanted = rewrite(current, routes, ratchet)
    if args.write:
        README.write_text(wanted)
        print(f"readme-numbers: README.md says {routes} routes, {ratchet}-test ratchet")
        return 0
    if wanted != current:
        have = ROUTES.search(current), RATCHET.search(current)
        print(
            "readme-numbers: README.md says "
            f"{have[0].group(1) if have[0] else '?'} routes and a "
            f"{have[1].group(1) if have[1] else '?'}-test ratchet; the gated numbers are "
            f"{routes} and {ratchet}. Run scripts/readme-numbers.py --write.",
            file=sys.stderr,
        )
        return 1
    print(f"readme-numbers: README.md matches ({routes} routes, {ratchet}-test ratchet)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
