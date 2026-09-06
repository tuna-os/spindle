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


KEY = re.compile(r"^(?P<indent>\s*)(?P<dash>-\s+)?(?P<key>[A-Za-z0-9_.-]+):(?:\s|$)")


def duplicate_keys(text: str) -> list[tuple[int, str]]:
    """Every mapping key that repeats among its siblings, with its line.

    GitHub refuses a workflow whose jobs (or steps' keys, or anything else)
    repeat, while PyYAML keeps the last copy without a word -- so a file
    can pass every local check and fail to parse the moment it is pushed,
    which is exactly what a merge-conflict resolution once did to the
    compliance workflow. This walks the indentation, the way YAML's block
    structure is defined, and skips block scalars (`run: |` bodies), whose
    lines are text and not keys. It is a scan, not a parser: it knows only
    enough to catch the case that bit us.
    """
    found: list[tuple[int, str]] = []
    # (indent, keys seen at that indent) for each open mapping.
    stack: list[tuple[int, set[str]]] = []
    scalar_indent: int | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if scalar_indent is not None:
            if indent > scalar_indent:
                continue
            scalar_indent = None
        match = KEY.match(raw)
        if not match:
            continue
        # A `- key:` item opens a fresh mapping for the item; its own keys
        # sit at the indent of the key, not of the dash.
        if match["dash"]:
            indent += len(match["dash"])
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, set()))
        while stack and stack[-1][0] > indent:
            stack.pop()
        if not stack or stack[-1][0] < indent:
            stack.append((indent, set()))
        seen = stack[-1][1]
        key = match["key"]
        if key in seen:
            found.append((number, key))
        seen.add(key)
        rest = raw[match.end() :].strip()
        if rest in ("|", ">", "|-", ">-", "|+", ">+"):
            scalar_indent = indent
    return found


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    workflows = sorted((root / ".github" / "workflows").glob("*.yml"))
    if not workflows:
        print("actions-pinned: no workflows found", file=sys.stderr)
        return 1

    problems: list[str] = []
    pinned = 0
    for path in workflows:
        for number, key in duplicate_keys(path.read_text()):
            problems.append(
                f"{path.relative_to(root)}:{number}: `{key}` is defined twice "
                "in the same mapping; GitHub refuses the whole workflow"
            )
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
