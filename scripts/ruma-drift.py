#!/usr/bin/env python3
"""vendor/ruma-state-res against the release it was cut from, and against
what upstream has done since.

    scripts/ruma-drift.py             # both reports below
    scripts/ruma-drift.py --check     # CI: the vendored tree is its base plus the listed hunks
    scripts/ruma-drift.py --upstream  # upkeep: what upstream changed in src/ since the base
    scripts/ruma-drift.py --hunks     # the surface table SPINDLE-PATCH.md should hold

ADR 0006 keeps a patched copy of ruma-state-res with no upstream path for
the patch, so the fork has no end date. Two things go wrong with a fork
like that, and each mode watches one.

--check: the patch grows. SPINDLE-PATCH.md lists every hunk by file, hunk
header and a digest of its lines; the vendored tree is diffed against the
crates.io crate (verified by the checksum SPINDLE-PATCH.md records) and
any hunk not on the list fails, with its text printed. Extending the patch
is then a reviewed edit to that list, never a side effect.

--upstream: upstream fixes state resolution and nothing tells us. The
newest crates.io release's src/ is diffed against the base's; a change
there is drift, printed hunk by hunk, and the exit status is 1. ruma's
`main` is diffed the same way for warning, but does not fail: it moves
daily, and what is unreleased can still change before it ships.

docs/maintenance.md says how to act on either, including the rebase.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

REPO = pathlib.Path(__file__).resolve().parent.parent
VENDOR = REPO / "vendor" / "ruma-state-res"
NOTE = VENDOR / "SPINDLE-PATCH.md"
CRATE = "ruma-state-res"
RUMA_GIT = "https://github.com/ruma/ruma.git"
CRATE_PATH_IN_RUMA = "crates/ruma-state-res"
# crates.io refuses requests without a User-Agent naming the caller.
USER_AGENT = "spindle-upkeep (https://github.com/tuna-os/spindle)"
SURFACE_HEADING = "## The patch surface"
# A drift diff past this many lines is cut in the report: the issue body
# has a size limit, and past a few hundred lines the reader diffs locally.
DIFF_LINE_CAP = 400
# Whole-file statuses a surface row may give instead of a hunk header.
# `regenerated` accepts any content: the file is tooling output, not source.
FILE_STATUSES = ("added", "removed", "regenerated")


@dataclass(frozen=True)
class Row:
    """One line of the patch surface: a hunk, or a whole-file status."""

    file: str
    hunk: str  # "@@ -a,b +c,d @@", or one of FILE_STATUSES
    digest: str = ""
    text: str = ""  # the hunk itself, for messages; not part of identity

    def key(self) -> tuple[str, str, str]:
        return (self.file, self.hunk, self.digest)


def read_tree(root: pathlib.Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def file_hunks(name: str, old: bytes, new: bytes) -> list[Row]:
    """The unified-diff hunks turning `old` into `new`, three lines of context.

    Lines keep their endings so a newline-only change is still a hunk, and
    the digest covers exactly the hunk's lines (header excluded: it is part
    of the row's identity already)."""
    try:
        before = old.decode().splitlines(keepends=True)
        after = new.decode().splitlines(keepends=True)
    except UnicodeDecodeError:
        return [
            Row(
                name,
                "binary",
                hashlib.sha256(new).hexdigest()[:16],
                "(binary file differs)",
            )
        ]
    rows: list[Row] = []
    header = None
    body: list[str] = []
    for line in difflib.unified_diff(before, after, n=3):
        if line.startswith(("---", "+++")) and header is None and not body:
            continue
        if line.startswith("@@"):
            if header is not None:
                rows.append(hunk_row(name, header, body))
            header, body = line.strip(), []
            continue
        body.append(line)
    if header is not None:
        rows.append(hunk_row(name, header, body))
    return rows


def hunk_row(name: str, header: str, body: list[str]) -> Row:
    digest = hashlib.sha256("".join(body).encode()).hexdigest()[:16]
    text = "\n".join([header, *(line.rstrip("\n") for line in body)])
    return Row(name, header, digest, text)


def surface(base: dict[str, bytes], vendored: dict[str, bytes]) -> list[Row]:
    """Every difference between the base crate and the vendored tree."""
    rows: list[Row] = []
    for name in sorted(base.keys() | vendored.keys()):
        if name not in vendored:
            rows.append(Row(name, "removed"))
        elif name not in base:
            rows.append(Row(name, "added"))
        elif base[name] != vendored[name]:
            rows.extend(file_hunks(name, base[name], vendored[name]))
    return rows


ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*`?([^`|]+?)`?\s*\|\s*`?([0-9a-f]*)`?\s*\|")


def listed(note: str) -> list[Row]:
    """The surface table under SURFACE_HEADING in SPINDLE-PATCH.md."""
    _, found, section = note.partition(SURFACE_HEADING)
    if not found:
        raise SystemExit(
            f"ruma-drift: {NOTE.relative_to(REPO)} has no '{SURFACE_HEADING}' section"
        )
    section = re.split(r"^## ", section, maxsplit=1, flags=re.MULTILINE)[0]
    return [
        Row(*match.groups()) for match in map(ROW.match, section.splitlines()) if match
    ]


def compare(actual: list[Row], expected: list[Row]) -> list[str]:
    """What differs between the tree's surface and the listed one, as messages."""
    regenerated = {row.file for row in expected if row.hunk == "regenerated"}
    wanted = {row.key() for row in expected if row.hunk != "regenerated"}
    problems = []
    seen = set()
    for row in actual:
        if row.file in regenerated:
            continue
        seen.add(row.key())
        if row.key() in wanted:
            continue
        if row.hunk in FILE_STATUSES:
            problems.append(
                f"{row.file}: {row.hunk} against the base, and SPINDLE-PATCH.md does not list it"
            )
        else:
            problems.append(
                f"{row.file}: hunk {row.hunk} (digest {row.digest}) is not listed in SPINDLE-PATCH.md:\n"
                + indent(row.text)
            )
    for file, hunk, digest in sorted(wanted - seen):
        what = hunk if hunk in FILE_STATUSES else f"hunk {hunk} (digest {digest})"
        problems.append(
            f"{file}: SPINDLE-PATCH.md lists {what}, and the vendored tree no longer has it"
        )
    return problems


def indent(text: str) -> str:
    return "\n".join(f"    {line}" for line in text.splitlines())


@dataclass(frozen=True)
class Base:
    version: str
    checksum: str
    commit: str


def read_base() -> Base:
    """The base, from the files that record it: the vendored Cargo.toml's
    version, and SPINDLE-PATCH.md's crate checksum and upstream commit."""
    manifest = (VENDOR / "Cargo.toml").read_text()
    note = NOTE.read_text()
    version = re.search(r'^version = "([^"]+)"', manifest, re.MULTILINE)
    checksum = re.search(r"^([0-9a-f]{64})$", note, re.MULTILINE)
    commit = re.search(r"^Upstream commit: `([0-9a-f]{40})`", note, re.MULTILINE)
    missing = [
        name
        for name, match in (
            ("version", version),
            ("checksum", checksum),
            ("commit", commit),
        )
        if not match
    ]
    if missing:
        raise SystemExit(
            f"ruma-drift: cannot read the base's {', '.join(missing)}; Cargo.toml or SPINDLE-PATCH.md moved it"
        )
    return Base(version.group(1), checksum.group(1), commit.group(1))


def get(url: str) -> bytes:
    """One GET, retried: crates.io and its CDN drop the odd request, and a
    report that fails on one dropped packet teaches people to ignore it."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(1, 5):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            if attempt == 4 or (
                isinstance(error, urllib.error.HTTPError)
                and error.code < 500
                and error.code != 429
            ):
                raise SystemExit(f"ruma-drift: GET {url}: {error}") from error
            time.sleep(2**attempt)
    raise AssertionError("unreachable")


def fetch_crate(version: str, checksum: str, into: pathlib.Path) -> dict[str, bytes]:
    """The published crate's files, refused unless its sha256 is `checksum`."""
    data = get(f"https://static.crates.io/crates/{CRATE}/{CRATE}-{version}.crate")
    actual = hashlib.sha256(data).hexdigest()
    if actual != checksum:
        raise SystemExit(
            f"ruma-drift: {CRATE} {version} has sha256 {actual}, expected {checksum}"
        )
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        archive.extractall(into, filter="data")
    return read_tree(into / f"{CRATE}-{version}")


def newest_release() -> tuple[str, str]:
    """(version, checksum) of the newest stable, unyanked release."""
    index = json.loads(get(f"https://crates.io/api/v1/crates/{CRATE}"))
    version = index["crate"]["max_stable_version"]
    for entry in index["versions"]:
        if entry["num"] == version and not entry["yanked"]:
            return version, entry["checksum"]
    raise SystemExit(
        f"ruma-drift: crates.io names {version} newest but lists no unyanked release of it"
    )


def git(*args: str, cwd: pathlib.Path) -> str:
    for attempt in range(1, 4):
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout
        if attempt < 3:
            time.sleep(2**attempt)
    raise SystemExit(f"ruma-drift: git {' '.join(args)}: {result.stderr.strip()}")


def fetch_main(into: pathlib.Path) -> tuple[str, dict[str, bytes]]:
    """ruma `main`'s head and its ruma-state-res tree. A sparse, blobless,
    depth-one fetch: only this crate's files cross the network, not ruma's."""
    git("init", "-q", str(into), cwd=into.parent)
    git("remote", "add", "origin", RUMA_GIT, cwd=into)
    git("sparse-checkout", "set", "--no-cone", f"/{CRATE_PATH_IN_RUMA}/", cwd=into)
    git("fetch", "-q", "--depth=1", "--filter=blob:none", "origin", "main", cwd=into)
    git("checkout", "-q", "FETCH_HEAD", cwd=into)
    head = git("rev-parse", "HEAD", cwd=into).strip()
    return head, read_tree(into / CRATE_PATH_IN_RUMA)


def src(tree: dict[str, bytes]) -> dict[str, bytes]:
    return {name: data for name, data in tree.items() if name.startswith("src/")}


def drift_report(
    label: str, base: dict[str, bytes], other: dict[str, bytes], patched: set[str]
) -> list[str]:
    """Markdown for one comparison of src/: the files, then the hunks."""
    rows = surface(src(base), src(other))
    if not rows:
        return [f"**{label}:** `src/` is unchanged from the base."]
    files = sorted({row.file for row in rows})
    lines = [f"**{label}:** `src/` differs from the base in {len(files)} file(s):", ""]
    body: list[str] = []
    for name in files:
        mine = [row for row in rows if row.file == name]
        status = (
            mine[0].hunk if mine[0].hunk in FILE_STATUSES else f"{len(mine)} hunk(s)"
        )
        clash = (
            " — **Spindle patches this file; the rebase will touch the patch**"
            if name in patched
            else ""
        )
        lines.append(f"- `{name}`: {status}{clash}")
        body += [f"--- a/{name}", f"+++ b/{name}"]
        for row in mine:
            body.extend((row.text or f"({row.hunk})").splitlines())
    if len(body) > DIFF_LINE_CAP:
        cut = len(body) - DIFF_LINE_CAP
        body = [
            *body[:DIFF_LINE_CAP],
            f"... {cut} more lines; diff the two trees locally",
        ]
    lines += [
        "",
        "<details><summary>The hunks</summary>",
        "",
        "```diff",
        *body,
        "```",
        "",
        "</details>",
    ]
    return lines


def upstream_report(
    base_info: Base,
    base: dict[str, bytes],
    release: tuple[str, dict[str, bytes]],
    main: tuple[str, dict[str, bytes]],
    patched: set[str],
) -> tuple[list[str], int]:
    """The drift report, and 1 when the newest release changed src/.

    Only the release decides the status: `main` is shown so a fix on its way
    is seen early, but what is unreleased can still change before it ships."""
    (version, release_tree), (main_head, main_tree) = release, main
    lines = [
        f"Vendored base: {CRATE} {base_info.version}, ruma commit `{base_info.commit[:12]}`.",
        f"Newest release: {version}. ruma `main`: `{main_head[:12]}`.",
        "",
        *drift_report(f"Release {version}", base, release_tree, patched),
        "",
        *drift_report(
            f"`main` @ {main_head[:12]} (unreleased; for warning)",
            base,
            main_tree,
            patched,
        ),
        "",
    ]
    if surface(src(base), src(release_tree)):
        lines.append(
            f"**Drift:** upstream released state-resolution changes in {version}. Rebase the patch "
            'onto it: docs/maintenance.md, "Rebasing vendor/ruma-state-res".'
        )
        return lines, 1
    lines.append("No drift: the newest release's `src/` is the vendored base's.")
    return lines, 0


def upstream(base_info: Base, base: dict[str, bytes], work: pathlib.Path) -> int:
    version, checksum = newest_release()
    if version == base_info.version:
        release_tree = base
    else:
        (work / "release").mkdir()
        release_tree = fetch_crate(version, checksum, work / "release")
    (work / "main").mkdir()
    main = fetch_main(work / "main")
    patched = {
        row.file for row in listed(NOTE.read_text()) if row.hunk not in FILE_STATUSES
    }
    lines, status = upstream_report(
        base_info, base, (version, release_tree), main, patched
    )
    print("\n".join(lines))
    return status


def check(base: dict[str, bytes], vendored: dict[str, bytes], note: str) -> list[str]:
    """Why the vendored tree is not the base plus the listed surface; empty if it is."""
    problems = compare(surface(base, vendored), listed(note))
    if problems:
        problems.append(
            "the patch surface changed. Keep the patch to the listed hunks, or list the new ones "
            "in SPINDLE-PATCH.md with why (`scripts/ruma-drift.py --hunks` prints the rows)."
        )
    return problems


def report_check(base_info: Base, base: dict[str, bytes]) -> int:
    note = NOTE.read_text()
    problems = check(base, read_tree(VENDOR), note)
    for problem in problems:
        print(f"ruma-drift: {problem}", file=sys.stderr)
    if problems:
        return 1
    hunks = sum(1 for row in listed(note) if row.hunk not in FILE_STATUSES)
    print(
        f"ruma-drift: vendor/{CRATE} is {CRATE} {base_info.version} plus the {hunks} listed hunks"
    )
    return 0


def print_hunks(base: dict[str, bytes]) -> int:
    """The surface table as it stands, with each row's reason carried over
    from SPINDLE-PATCH.md where the row is unchanged. A row printed with an
    empty reason is new: write one before committing it."""
    note = NOTE.read_text()
    _, _, section = note.partition(SURFACE_HEADING)
    reasons = {}
    for line in section.splitlines():
        match = ROW.match(line)
        if match:
            reasons[Row(*match.groups()).key()] = (
                line.rstrip().rstrip("|").rsplit("|", 1)[-1].strip()
            )
    regenerated = [row for row in listed(note) if row.hunk == "regenerated"]
    skipped = {row.file for row in regenerated}
    rows = [row for row in surface(base, read_tree(VENDOR)) if row.file not in skipped]
    print("| File | Hunk | Digest | Why |")
    print("|---|---|---|---|")
    for row in [*rows, *regenerated]:
        hunk = f"`{row.hunk}`" if row.hunk.startswith("@@") else row.hunk
        digest = f"`{row.digest}`" if row.digest else ""
        print(f"| `{row.file}` | {hunk} | {digest} | {reasons.get(row.key(), '')} |")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="fail unless the vendored tree is the base plus the listed hunks",
    )
    mode.add_argument(
        "--upstream",
        action="store_true",
        help="report what upstream changed in src/ since the base",
    )
    mode.add_argument(
        "--hunks",
        action="store_true",
        help="print the surface table SPINDLE-PATCH.md should hold",
    )
    args = parser.parse_args()

    base_info = read_base()
    with tempfile.TemporaryDirectory(prefix="ruma-drift-") as tmp:
        work = pathlib.Path(tmp)
        (work / "base").mkdir()
        base = fetch_crate(base_info.version, base_info.checksum, work / "base")
        if args.check:
            return report_check(base_info, base)
        if args.hunks:
            return print_hunks(base)
        if args.upstream:
            return upstream(base_info, base, work)
        status = report_check(base_info, base)
        print()
        return upstream(base_info, base, work) or status


if __name__ == "__main__":
    sys.exit(main())
