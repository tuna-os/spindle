#!/usr/bin/env python3
"""Fail if a workflow runs an action from a mutable ref, or loosens the
other three things around it: what goes into a `run:` script, what the
token may do, and which container images are built from or run.

A tag is a pointer somebody else can move. `actions/checkout@v5` means
"whatever the checkout maintainers call v5 the moment our job starts", and a
branch -- this repository ran `dtolnay/rust-toolchain@master` for its whole
history -- means "whatever was pushed there most recently". Either one is a
third party with write access to a step that runs before our code does, in a
job holding a token. A reference has to name a specific tree.

`.github/workflows/actions.lock` is how it does that now. `gh actions-lock`
records the commit each `uses: owner/repo@tag` resolves to, and the
actions transitive ones resolve to, and the `actions-security` workflow
fails when a pin no longer verifies upstream. So an action named by tag
passes here only if the lockfile lists that exact reference for that
workflow. A cross-repository reusable workflow
(`owner/repo/.github/workflows/x.yml@ref`) is outside what the lockfile
covers, so it is still pinned to a commit SHA.

The pin is only half of it, and the cheaper half. A pin with nothing
maintaining it is *worse* than a moving tag: it freezes the action at
whatever it was the day somebody pinned it, security fixes included.
`.github/dependabot.yml` is what keeps them moving, which is why it landed
first (#182) and this check second. Dependabot updates the tag and the
lockfile together.

A SHA pin keeps its trailing `# v5` comment. Dependabot reads it to know
which version a SHA stands for, and rewrites both together; without it the
pin is opaque to the thing meant to maintain it, and to the next person
reading the file.

An expression in a `run:` script is pasted into the shell source before
bash parses it, so `--rounds "${{ inputs.rounds }}"` ran whatever a
dispatcher typed, in a job that could push (#516). The fix is to pass the
value through `env:` and refer to the variable; this check refuses every
`${{ }}` inside a `run:` body, not only the ones that look attacker-owned,
because which context is safe to paste is exactly the judgement that
failed.

A workflow's top-level `permissions:` is the grant every job inherits, so
it must exist and grant nothing that writes (#521, #599). A job that pushes,
publishes or files an issue asks for that itself, beside the steps that
need it.

A container image named by tag is the same moving pointer as an action
named by tag (#652, #687). Dockerfile bases and the images the Kubernetes
rigs and compose files run are pinned `name:tag@sha256:...`: the digest is
what runs, and the tag is what a reader and Dependabot go by.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
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
# One workflow and one of its pinned references in actions.lock, which
# `gh actions-lock` writes in a fixed shape:
#     '.github/workflows/ci.yml':
#         - 'actions/checkout@v7.0.1'
LOCK_WORKFLOW = re.compile(r"^ {4}'(?P<path>[^']+)':")
LOCK_ENTRY = re.compile(r"^ {8}- '(?P<ref>[^']+)'$")


def locked_refs(text: str) -> dict[str, set[str]]:
    """The references actions.lock pins, by workflow path.

    Only the `workflows:` section: it maps each workflow to the exact
    `owner/repo@ref` strings it uses, which is what a `uses:` line has to
    match. GitHub matches owner and repository without case, so the lock
    writes them in lower case and the lookup lowers them too.
    """
    locked: dict[str, set[str]] = {}
    current: set[str] | None = None
    in_workflows = False
    for raw in text.splitlines():
        if not raw.startswith(" "):
            in_workflows = raw.startswith("workflows:")
            current = None
            continue
        if not in_workflows:
            continue
        workflow = LOCK_WORKFLOW.match(raw)
        if workflow:
            current = locked.setdefault(workflow["path"], set())
            continue
        entry = LOCK_ENTRY.match(raw)
        if entry and current is not None:
            current.add(entry["ref"].lower())
    return locked


def unpinned_uses(
    where_file: str, text: str, locked: set[str]
) -> tuple[int, list[tuple[int, str]]]:
    """How many `uses:` references are pinned, and every one that is not.

    `locked` is what actions.lock lists for this workflow. An action named
    by tag passes when its `owner/repo@ref` is in it; a subdirectory action
    (`actions/cache/restore@v6`) is locked under its repository. A
    cross-repository reusable workflow is pinned by SHA, because the lock
    does not cover it.
    """
    pinned = 0
    problems: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        match = USES.match(line)
        if not match:
            continue
        action, ref = match["action"], match["ref"]
        repository = "/".join(action.split("/")[:2])
        if SHA.match(ref):
            if not match["comment"]:
                # Not cosmetic: this is the only record of which version the
                # SHA is, and what Dependabot rewrites alongside it.
                problems.append(
                    (
                        number,
                        f"{action} is pinned but unlabelled; add the version "
                        "it stands for as a trailing `# vN` comment",
                    )
                )
                continue
        elif "/.github/workflows/" in action:
            problems.append(
                (
                    number,
                    f"{action}@{ref} is a mutable ref to a reusable workflow, "
                    "which actions.lock does not cover; pin the commit SHA it "
                    f"points at today and label it `# {ref}`",
                )
            )
            continue
        elif f"{repository}@{ref}".lower() not in locked:
            problems.append(
                (
                    number,
                    f"{action}@{ref} is a mutable ref that "
                    f".github/workflows/actions.lock does not pin for "
                    f"{where_file}; run `gh actions-lock`",
                )
            )
            continue
        pinned += 1
    return pinned, problems


KEY = re.compile(r"^(?P<indent>\s*)(?P<dash>-\s+)?(?P<key>[A-Za-z0-9_.-]+):(?:\s|$)")
# A `run:` key, block or inline. Its body is every following line indented
# deeper than the key itself.
RUN = re.compile(r"^(?P<lead>\s*(?:-\s+)?)run:(?P<rest>.*)$")
EXPRESSION = re.compile(r"\$\{\{.*?\}\}")

# A workflow's top-level `permissions:` and the grants under it.
TOP_PERMISSIONS = re.compile(r"^permissions:(?P<rest>.*)$")
GRANT = re.compile(r"^\s+(?P<scope>[a-z-]+):\s*(?P<level>[a-z]+)")

FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(?P<image>\S+)(?:\s+AS\s+(?P<stage>\S+))?",
    re.IGNORECASE,
)
IMAGE = re.compile(r"""^\s*(?:-\s+)?(?:image|container):\s*['"]?(?P<image>[^'"\s#]+)""")


def expressions_in_run(text: str) -> list[tuple[int, str]]:
    """Every `${{ }}` inside a `run:` script, with its line.

    Shell comments inside the script count too: the runner expands the
    expression before bash ever sees the `#`.
    """
    found: list[tuple[int, str]] = []
    body_indent: int | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        if body_indent is not None:
            if not raw.strip() or len(raw) - len(raw.lstrip(" ")) > body_indent:
                found.extend(
                    (number, expression) for expression in EXPRESSION.findall(raw)
                )
                continue
            body_indent = None
        match = RUN.match(raw)
        if not match:
            continue
        found.extend(
            (number, expression) for expression in EXPRESSION.findall(match["rest"])
        )
        body_indent = len(match["lead"])
    return found


def top_level_permissions(text: str) -> tuple[bool, list[tuple[int, str]]]:
    """Whether the workflow declares top-level permissions, and every grant
    there that can write."""
    lines = text.splitlines()
    for index, raw in enumerate(lines):
        match = TOP_PERMISSIONS.match(raw)
        if not match:
            continue
        rest = match["rest"].split("#", 1)[0].strip()
        if rest:
            return True, [(index + 1, rest)] if rest == "write-all" else []
        writes: list[tuple[int, str]] = []
        for number, line in enumerate(lines[index + 1 :], index + 2):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line[0].isspace():
                break
            grant = GRANT.match(line)
            if grant and grant["level"] == "write":
                writes.append((number, f"{grant['scope']}: write"))
        return True, writes
    return False, []


def unpinned_images(name: str, text: str) -> list[tuple[int, str]]:
    """Every image a Dockerfile builds from, or a manifest runs, that is not
    pinned by digest.

    A Dockerfile's own earlier stages and `scratch` are not images, and a
    reference with a placeholder in it (`__IMAGE__`, `${SPINDLE_IMAGE:-...}`, a Helm `{{ }}`)
    names one the caller supplies, so neither is something to pin here.
    """
    found: list[tuple[int, str]] = []
    dockerfile = name == "Dockerfile" or name.endswith((".Dockerfile", "/Dockerfile"))
    stages: set[str] = set()
    for number, raw in enumerate(text.splitlines(), 1):
        match = FROM.match(raw) if dockerfile else IMAGE.match(raw)
        if not match:
            continue
        image = match["image"]
        if dockerfile and match["stage"]:
            stages.add(match["stage"].lower())
        if (
            image.lower() in stages
            or image == "scratch"
            or "$" in image
            or "__" in image
            or "{{" in image
        ):
            continue
        if "@sha256:" not in image:
            found.append((number, image))
    return found


def image_files(root: pathlib.Path) -> list[str]:
    """Tracked Dockerfiles and YAML, from git so a built `target/` is never
    walked."""
    listed = subprocess.run(
        [
            "git",
            "ls-files",
            "--",
            "Dockerfile",
            "**/Dockerfile",
            "*.Dockerfile",
            "*.yml",
            "*.yaml",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return sorted(set(listed.stdout.split()))


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

    lockfile = root / ".github" / "workflows" / "actions.lock"
    locked = locked_refs(lockfile.read_text()) if lockfile.exists() else {}
    problems: list[str] = []
    pinned = 0
    for path in workflows:
        where_file = path.relative_to(root)
        text = path.read_text()
        for number, key in duplicate_keys(text):
            problems.append(
                f"{where_file}:{number}: `{key}` is defined twice "
                "in the same mapping; GitHub refuses the whole workflow"
            )
        for number, expression in expressions_in_run(text):
            problems.append(
                f"{where_file}:{number}: {expression} is pasted into a `run:` "
                "script before the shell parses it; pass it through `env:` "
                "and use the variable"
            )
        declared, writes = top_level_permissions(text)
        if not declared:
            problems.append(
                f"{where_file}: no top-level `permissions:`, so every job gets "
                "the repository's default token; declare `contents: read` and "
                "grant more per job"
            )
        for number, grant in writes:
            problems.append(
                f"{where_file}:{number}: top-level `{grant}` reaches every job; "
                "move it to the jobs that use it"
            )
        count, unpinned = unpinned_uses(
            str(where_file), text, locked.get(str(where_file), set())
        )
        pinned += count
        for number, problem in unpinned:
            problems.append(f"{where_file}:{number}: {problem}")

    files = image_files(root)
    for name in files:
        for number, image in unpinned_images(name, (root / name).read_text()):
            problems.append(
                f"{name}:{number}: {image} is a mutable tag; pin the digest it "
                f"resolves to today as `{image}@sha256:...`"
            )

    for problem in problems:
        print(f"actions-pinned: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(
        f"actions-pinned: all {pinned} action references are locked or "
        f"SHA-pinned across {len(workflows)} workflows, no `run:` script "
        f"pastes an expression, no workflow grants a write to every job, and "
        f"every image named in {len(files)} tracked Dockerfiles and YAML files is digest-pinned"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
