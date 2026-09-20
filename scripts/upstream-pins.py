#!/usr/bin/env python3
"""Every upstream this repository pins, where the pin lives, and what
upstream has moved to since.

    scripts/upstream-pins.py             # print the pins
    scripts/upstream-pins.py --check     # fail if a pin cannot be read
    scripts/upstream-pins.py --upstream  # ask upstream what is current

The pins are read from the files that use them, never typed here, so this
table cannot drift from what CI runs. --check is the guard for that: a
renamed variable or a moved file fails it rather than silently dropping a
pin from the weekly report. --upstream compares each pin with the newest
release (or the default branch's head, for the ones pinned by commit) and
says which are behind. Bumping remains a reviewed pull request: what a
newer matrix-rust-sdk or Complement asks of this server is exactly the
thing a person should read before it is asked in CI.

Dependabot covers Cargo, GitHub Actions, the Docker bases and the Go
module. These are the pins it has no ecosystem for.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# (name, file, regex with one group, upstream repo, how to read "current")
#   tag      -- the newest tag matching `tag_pattern`, by version number
#   branch   -- the head commit of `branch`
# Both are read with `git ls-remote`, so this needs no token and no API.
PINS = [
    {
        "name": "matrix-spec",
        "file": "scripts/openapi-check.py",
        "regex": r'^SPEC_PIN = "([0-9a-f]{40})"',
        "repo": "matrix-org/matrix-spec",
        "kind": "branch",
        "branch": "main",
        "note": "What openapi-check.py validates against and spec-drift.py reads. A bump rewrites docs/spec-gaps.md.",
    },
    {
        "name": "matrix-rust-sdk",
        "file": "contrib/rust-sdk/run.sh",
        "regex": r"^RUST_SDK_REV=([0-9a-f]{40})",
        "repo": "matrix-org/matrix-rust-sdk",
        "kind": "tag",
        "tag_pattern": r"^matrix-sdk-\d+\.\d+\.\d+$",
        "note": "The integration suite the nightly runs; its allowlist is the ratchet.",
    },
    {
        "name": "complement",
        "file": "scripts/complement.sh",
        "regex": r"^COMPLEMENT_REV=([0-9a-f]{40})",
        "repo": "matrix-org/complement",
        "kind": "branch",
        "branch": "main",
        "note": "The conformance suite; new tests arrive as candidates, never as failures.",
    },
    {
        "name": "element-web",
        "file": "scripts/element-web-e2e/run.sh",
        "regex": r"^ELEMENT_TAG=(v[\d.]+)",
        "repo": "element-hq/element-web",
        "kind": "tag",
        "tag_pattern": r"^v\d+\.\d+\.\d+$",
        "note": "The browser client the E2E job drives.",
    },
    {
        "name": "element-call",
        "file": "contrib/element-call/run.sh",
        "regex": r"^ELEMENT_CALL_REV=([0-9a-f]{40})",
        "repo": "element-hq/element-call",
        "kind": "branch",
        "branch": "main",
        "note": "Its Playwright suite runs with Spindle in Synapse's seat.",
    },
    {
        "name": "synapse (benchmark field)",
        "file": "scripts/bench-field.sh",
        "regex": r"^SYNAPSE_VERSION=([\d.]+)",
        "repo": "element-hq/synapse",
        "kind": "tag",
        "tag_pattern": r"^v\d+\.\d+\.\d+$",
        "note": "The reference implementation in the benchmark sittings.",
    },
    {
        "name": "continuwuity (benchmark field)",
        "file": "scripts/bench-field.sh",
        "regex": r"^CONTINUWUITY_VERSION=([\d.]+)",
        "repo": "continuwuity/continuwuity",
        "kind": "tag",
        "tag_pattern": r"^v\d+\.\d+\.\d+$",
        "note": "Benchmark competitor.",
    },
    {
        "name": "tuwunel (benchmark field)",
        "file": "scripts/bench-field.sh",
        "regex": r"^TUWUNEL_TAG=(v[\d.]+)",
        "repo": "matrix-construct/tuwunel",
        "kind": "tag",
        "tag_pattern": r"^v\d+\.\d+\.\d+$",
        "note": "Benchmark competitor, built from source.",
    },
    {
        "name": "dendrite (benchmark field)",
        "file": "scripts/bench-field.sh",
        "regex": r"^DENDRITE_TAG=(v[\d.]+)",
        "repo": "element-hq/dendrite",
        "kind": "tag",
        "tag_pattern": r"^v\d+\.\d+\.\d+$",
        "note": "Benchmark competitor.",
    },
]


def read_pin(pin: dict) -> str | None:
    text = (REPO / pin["file"]).read_text()
    match = re.search(pin["regex"], text, re.MULTILINE)
    return match.group(1) if match else None


def ls_remote(repo: str, *refs: str) -> list[tuple[str, str]]:
    """(sha, ref) pairs from upstream, or [] when the remote cannot be read."""
    options = [ref for ref in refs if ref.startswith("-")]
    names = [ref for ref in refs if not ref.startswith("-")]
    result = subprocess.run(
        ["git", "ls-remote", *options, f"https://github.com/{repo}.git", *names],
        capture_output=True, text=True, timeout=120, check=False,
    )
    if result.returncode != 0:
        print(f"upstream-pins: git ls-remote {repo}: {result.stderr.strip()}", file=sys.stderr)
        return []
    pairs = []
    for line in result.stdout.splitlines():
        sha, _, ref = line.partition("\t")
        pairs.append((sha, ref))
    return pairs


def version_of(name: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", name))


def current(pin: dict) -> str | None:
    repo = pin["repo"]
    if pin["kind"] == "tag":
        pattern = re.compile(pin["tag_pattern"])
        tags = [(sha, ref.removeprefix("refs/tags/")) for sha, ref in ls_remote(repo, "--tags", "--refs")]
        tags = [(sha, name) for sha, name in tags if pattern.match(name)]
        if not tags:
            return None
        sha, newest = max(tags, key=lambda pair: version_of(pair[1]))
        return f"{newest} ({sha[:12]})"
    if pin["kind"] == "branch":
        for sha, ref in ls_remote(repo, f"refs/heads/{pin['branch']}"):
            if ref == f"refs/heads/{pin['branch']}":
                return f"{pin['branch']} @ {sha[:12]}"
        return None
    return None


def matches(pinned: str, upstream: str | None) -> bool:
    if upstream is None:
        return False
    if len(pinned) == 40:
        return pinned[:12] in upstream
    return pinned.lstrip("v") == upstream.lstrip("v") or pinned in upstream


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if a pin cannot be read from its file")
    parser.add_argument("--upstream", action="store_true", help="compare each pin with upstream")
    args = parser.parse_args()

    unread = [pin["name"] for pin in PINS if read_pin(pin) is None]
    if unread:
        for name in unread:
            print(f"upstream-pins: cannot read the {name} pin; its file or variable moved", file=sys.stderr)
        return 1
    if args.check:
        print(f"upstream-pins: all {len(PINS)} pins read from their files")
        return 0

    if args.upstream:
        print("| Upstream | Pinned | Current | |")
        print("|---|---|---|---|")
    else:
        print("| Upstream | Pinned | Where |")
        print("|---|---|---|")
    behind = []
    for pin in PINS:
        pinned = read_pin(pin)
        shown = pinned[:12] if len(pinned) == 40 else pinned
        if not args.upstream:
            print(f"| {pin['name']} | `{shown}` | `{pin['file']}` |")
            continue
        latest = current(pin)
        state = "current" if matches(pinned, latest) else ("unknown" if latest is None else "**behind**")
        if state == "**behind**":
            behind.append(pin)
        print(f"| {pin['name']} | `{shown}` | `{latest or '?'}` | {state} |")
    if args.upstream:
        print()
        if behind:
            print("Behind upstream:")
            for pin in behind:
                print(f"- {pin['name']} — {pin['note']} Pinned in `{pin['file']}`.")
        else:
            print("Every pin is at upstream's newest.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
