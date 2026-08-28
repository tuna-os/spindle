#!/usr/bin/env python3
"""Fail if any workflow step runs an action from a mutable ref.

A tag is a pointer somebody else can move. `actions/checkout@v5` means
"whatever the checkout maintainers call v5 the moment our job starts", and a
branch -- this repository ran `dtolnay/rust-toolchain@master` for its whole
history -- means "whatever was pushed there most recently". Either one is a
third party with write access to a step that runs before our code does, in a
job holding a token. Pinning to a commit SHA is the only form of the
reference that names a specific tree.

The pin is only half of it, and the cheaper half. A SHA with nothing
maintaining it is *worse* than a tag: it freezes the action at whatever it
was the day somebody pinned it, security fixes included. `.github/
dependabot.yml` is what keeps them moving, which is why it landed first
(#182) and this check second.

The trailing `# v5` comment is not decoration. Dependabot reads it to know
which version a SHA stands for, and rewrites both together; without it the
pin is opaque to the thing meant to maintain it, and to the next person
reading the file.
"""

from __future__ import annotations

import pathlib
import re
import sys

# `uses: owner/repo@ref` with an optional trailing comment. Local actions
# (`./.github/actions/...`) and container steps (`docker://...`) have no
# upstream ref to pin and are not matched.
USES = re.compile(
    r"^\s*(?:-\s+)?uses:\s*"
    r"(?P<action>[\w.-]+/[\w.-]+(?:/[\w.-]+)*)@(?P<ref>\S+)"
    r"(?:\s+#\s*(?P<comment>.*?))?\s*$"
)
SHA = re.compile(r"^[0-9a-f]{40}$")


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    workflows = sorted((root / ".github" / "workflows").glob("*.yml"))
    if not workflows:
        print("actions-pinned: no workflows found", file=sys.stderr)
        return 1

    problems: list[str] = []
    pinned = 0
    for path in workflows:
        for number, line in enumerate(path.read_text().splitlines(), 1):
            match = USES.match(line)
            if not match:
                continue
            where = f"{path.relative_to(root)}:{number}"
            action, ref = match["action"], match["ref"]
            if not SHA.match(ref):
                problems.append(
                    f"{where}: {action}@{ref} is a mutable ref; pin the commit "
                    f"SHA it points at today and label it `# {ref}`"
                )
            elif not match["comment"]:
                # Not cosmetic: this is the only record of which version the
                # SHA is, and what Dependabot rewrites alongside it.
                problems.append(
                    f"{where}: {action} is pinned but unlabelled; add the "
                    f"version it stands for as a trailing `# vN` comment"
                )
            else:
                pinned += 1

    for problem in problems:
        print(f"actions-pinned: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(
        f"actions-pinned: all {pinned} action references are SHA-pinned "
        f"and labelled across {len(workflows)} workflows"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
