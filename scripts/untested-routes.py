#!/usr/bin/env python3
"""List the routes the router serves that no test or rig names.

The dashboard says what is *implemented*; this says what is implemented
and *exercised*. A route is counted as exercised when a test under
`crates/*/tests`, a rig under `contrib/`, or an evidence page under
`docs/evidence/` names it -- by its full path or by its distinctive tail,
since tests often build a path from a prefix. It is a scan of names, not
a coverage measurement: a test that names a route and asserts nothing
about it still counts, and a route reached only through another server's
client (Complement, Element Call, matrix-rust-sdk) may show here although
their suites drive it. Read the list as "nobody here wrote it down".

Exit status is 0 either way for now; the list is printed for a person.
It becomes a gate once it is empty, the way `coverage-dashboard.py
--check` did, so a new route cannot land without something that drives
it.
"""

from __future__ import annotations

import glob
import importlib.util
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# Segments too generic to identify a route on their own; these are matched
# together with the segment before them.
GENERIC = {
    "rooms", "state", "members", "config", "audit", "timeline", "devices",
    "profile", "events", "keys", "query", "list", "room", "user", "users",
}


def routes() -> list[tuple[str, list[str]]]:
    spec = importlib.util.spec_from_file_location(
        "coverage_dashboard", REPO / "scripts" / "coverage-dashboard.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module.parse_routes()


def corpus() -> list[tuple[str, str]]:
    patterns = [
        "crates/*/tests/**/*.rs",
        "contrib/**/*.sh",
        "contrib/**/*.py",
        "contrib/**/*.mjs",
        "contrib/**/*.ts",
        "docs/evidence/*.md",
    ]
    out = []
    for pattern in patterns:
        for name in glob.glob(str(REPO / pattern), recursive=True):
            path = pathlib.Path(name)
            if "node_modules" in path.parts or not path.is_file():
                continue
            out.append((str(path.relative_to(REPO)), path.read_text(errors="ignore")))
    return out


def key_for(path: str) -> re.Pattern[str]:
    segments = [s for s in path.split("/") if s and not s.startswith("{")]
    tail = segments[-1]
    if tail in GENERIC and len(segments) >= 2:
        # `rooms/{room_id}/state` is written as `rooms/{room}/state` or
        # `rooms/!abc:x/state` in a test: allow one parameter between.
        return re.compile(re.escape(segments[-2]) + r"/(?:[^/\"\s]+/)?" + re.escape(tail) + r"\b")
    return re.compile(re.escape(tail) + r"\b")


def main() -> int:
    texts = corpus()
    unexercised = []
    for path, methods in routes():
        pattern = key_for(path)
        if not any(pattern.search(text) for _, text in texts):
            unexercised.append((path, methods))
    for path, methods in unexercised:
        print(f"untested-routes: {'/'.join(methods):16} {path}")
    total = len(routes())
    print(
        f"untested-routes: {total - len(unexercised)} of {total} routes are named by a "
        f"test, rig or evidence page; {len(unexercised)} are not"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
