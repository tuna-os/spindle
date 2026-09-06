#!/usr/bin/env python3
"""Hold contrib/msc/ledger.toml to the code, and to upstream.

    scripts/msc-ledger.py              # rewrite docs/mscs.md from the ledger
    scripts/msc-ledger.py --check      # fail on a claim the code does not back
    scripts/msc-ledger.py --upstream   # ask GitHub what became of each MSC

--check, run in CI:
  * every `org.matrix.mscNNNN` flag in surface::UNSTABLE_FEATURES has a
    ledger entry that is served or partial;
  * every route the router serves under `unstable/org.matrix.mscNNNN` has one;
  * every evidence file exists, and a served or partial entry has at least
    one test file among them that mentions the MSC number;
  * docs/mscs.md is what this ledger renders.

--upstream, run weekly by upkeep.yml (GITHUB_TOKEN raises the rate limit):
  the proposal's pull request on matrix-org/matrix-spec-proposals is read
  and the ledger's view compared with it. A merged proposal whose ledger
  entry has no `stable` version is the one worth acting on: the stable
  spelling exists and clients will start sending it. A closed, unmerged
  proposal marked planned is one to stop planning for.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import pathlib
import re
import sys
import tomllib
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
dashboard = importlib.import_module("coverage-dashboard")

LEDGER = REPO / "contrib" / "msc" / "ledger.toml"
SURFACE = REPO / "crates" / "spindle-server" / "src" / "surface.rs"
OUT = REPO / "docs" / "mscs.md"
STATUSES = ("served", "partial", "planned", "design", "superseded", "declined")
BUILT = ("served", "partial")
PROPOSALS = "matrix-org/matrix-spec-proposals"


def load() -> list[dict]:
    with LEDGER.open("rb") as handle:
        entries = tomllib.load(handle)["msc"]
    seen = set()
    for entry in entries:
        if entry["status"] not in STATUSES:
            sys.exit(f"msc-ledger: MSC{entry['number']} has status {entry['status']!r}; one of {STATUSES}")
        if entry["number"] in seen:
            sys.exit(f"msc-ledger: MSC{entry['number']} is listed twice")
        seen.add(entry["number"])
    return sorted(entries, key=lambda e: e["number"])


def advertised_flags() -> list[str]:
    """The unstable_features flags surface.rs advertises as true."""
    text = SURFACE.read_text()
    block = text[text.index("UNSTABLE_FEATURES"):]
    block = block[: block.index("];")]
    return re.findall(r'\("([^"]+)",\s*true\)', block)


def msc_of(text: str) -> int | None:
    match = re.search(r"msc(\d{4})", text)
    return int(match.group(1)) if match else None


def check(entries: list[dict]) -> int:
    by_number = {entry["number"]: entry for entry in entries}
    problems: list[str] = []

    for flag in advertised_flags():
        number = msc_of(flag)
        entry = by_number.get(number) if number else None
        if number is None:
            # Vendor flags (im.nheko.summary) are matched by the `unstable`
            # field instead of by number.
            owners = [e for e in entries if flag in e.get("unstable", [])]
            if not owners:
                problems.append(f"/versions advertises {flag} and no ledger entry lists it under `unstable`")
            elif owners[0]["status"] not in BUILT:
                problems.append(f"/versions advertises {flag} but MSC{owners[0]['number']} is {owners[0]['status']}")
            continue
        if entry is None:
            problems.append(f"/versions advertises {flag} and the ledger has no MSC{number}")
        elif entry["status"] not in BUILT:
            problems.append(f"/versions advertises {flag} but the ledger says MSC{number} is {entry['status']}")
        elif flag not in entry.get("unstable", []):
            problems.append(f"MSC{number} does not list {flag} under `unstable`, and /versions advertises it")

    for path, _ in dashboard.parse_routes():
        if "/unstable/" not in path:
            continue
        number = msc_of(path)
        if number is None:
            continue
        entry = by_number.get(number)
        if entry is None:
            problems.append(f"router serves {path} and the ledger has no MSC{number}")
        elif entry["status"] not in BUILT + ("superseded",):
            # A superseded entry may still own a route: MSC4186 kept
            # MSC3575's prefix, and the entry's notes say so.
            problems.append(f"router serves {path} but the ledger says MSC{number} is {entry['status']}")

    for entry in entries:
        number = entry["number"]
        evidence = entry.get("evidence", [])
        for rel in evidence:
            if not (REPO / rel).exists():
                problems.append(f"MSC{number} names evidence {rel}, which does not exist")
        if entry["status"] in BUILT:
            tests = [rel for rel in evidence if "/tests/" in rel and (REPO / rel).exists()]
            if not tests:
                problems.append(f"MSC{number} is {entry['status']} and names no test file as evidence")
            elif not any(re.search(rf"MSC[\d/, ]*(?<!\d){number}(?!\d)", (REPO / rel).read_text()) for rel in tests):
                problems.append(f"MSC{number} is {entry['status']} and none of its test files mentions MSC{number}")
        for flag in entry.get("unstable", []):
            if flag not in advertised_flags():
                problems.append(f"MSC{number} lists {flag} under `unstable` and /versions does not advertise it")

    rendered = render(entries)
    if not OUT.exists() or OUT.read_text() != rendered:
        problems.append(f"{OUT.relative_to(REPO)} is stale; run scripts/msc-ledger.py")

    for problem in problems:
        print(f"msc-ledger: {problem}", file=sys.stderr)
    if problems:
        return 1
    built = sum(1 for e in entries if e["status"] in BUILT)
    print(f"msc-ledger: {len(entries)} MSCs in the ledger, {built} served or partial, every claim backed")
    return 0


def render(entries: list[dict]) -> str:
    lines = [
        "# MSCs",
        "",
        "<!-- Generated by scripts/msc-ledger.py from contrib/msc/ledger.toml. Do not edit by hand. -->",
        "",
        "What Spindle serves of the Matrix spec proposals, held to the code by",
        "`scripts/msc-ledger.py --check`: an advertised flag or an `unstable/`",
        "route with no served entry here fails CI, and so does a served entry",
        "with no test that names the MSC. The weekly upkeep run asks upstream",
        "what became of each proposal.",
        "",
    ]
    order = ["served", "partial", "planned", "design", "superseded", "declined"]
    titles = {
        "served": "Served",
        "partial": "Partly served",
        "planned": "Planned",
        "design": "Design basis",
        "superseded": "Superseded",
        "declined": "Declined",
    }
    for status in order:
        group = [e for e in entries if e["status"] == status]
        if not group:
            continue
        lines += [f"## {titles[status]}", "", "| MSC | Title | Stable in | Flags | Evidence | Notes |", "|---|---|---|---|---|---|"]
        for e in group:
            link = f"[MSC{e['number']}](https://github.com/{PROPOSALS}/pull/{e['number']})"
            stable = f"v{e['stable']}" if e.get("stable") else "—"
            flags = ", ".join(f"`{f}`" for f in e.get("unstable", [])) or "—"
            evidence = ", ".join(f"`{pathlib.Path(rel).name}`" for rel in e.get("evidence", [])) or "—"
            notes = e.get("notes", "").replace("|", "\\|")
            lines.append(f"| {link} | {e['title']} | {stable} | {flags} | {evidence} | {notes} |")
        lines.append("")
    return "\n".join(lines)


def github(path: str) -> dict | None:
    request = urllib.request.Request(f"https://api.github.com/{path}", headers={"Accept": "application/vnd.github+json"})
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        print(f"msc-ledger: GET {path}: HTTP {error.code}", file=sys.stderr)
        return None


def upstream(entries: list[dict]) -> int:
    """Compare the ledger's view of each MSC with its pull request."""
    findings = []
    unread = []
    print("| MSC | Ledger | Upstream | Labels |")
    print("|---|---|---|---|")
    for entry in entries:
        number = entry["number"]
        pr = github(f"repos/{PROPOSALS}/pulls/{number}")
        if pr is None:
            unread.append(number)
            continue
        labels = sorted(label["name"] for label in pr.get("labels", []))
        if pr.get("merged"):
            state = "merged"
        elif pr.get("state") == "closed":
            state = "closed"
        else:
            state = "open"
        print(f"| MSC{number} | {entry['status']} | {state} | {', '.join(labels)} |")
        spec_merged = "spec-pr-merged" in labels or state == "merged"
        if spec_merged and not entry.get("stable") and entry["status"] in BUILT:
            findings.append(f"MSC{number} ({entry['title']}) has landed upstream and the ledger has no `stable` version: adopt the stable spelling and record the version")
        if state == "closed" and entry["status"] == "planned":
            findings.append(f"MSC{number} ({entry['title']}) was closed unmerged upstream and is still `planned` here")
        if "obsolete" in labels and entry["status"] in BUILT + ("planned",):
            findings.append(f"MSC{number} ({entry['title']}) is labelled obsolete upstream; the ledger says {entry['status']}")
    print()
    if unread:
        print(f"Could not read {len(unread)} of {len(entries)} proposals from GitHub (set GITHUB_TOKEN for the rate limit): "
              + ", ".join(f"MSC{n}" for n in unread))
    if findings:
        print("Findings:")
        for finding in findings:
            print(f"- {finding}")
    elif not unread:
        print("Findings: none; the ledger agrees with upstream.")
    return 1 if unread and len(unread) == len(entries) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--upstream", action="store_true")
    args = parser.parse_args()
    entries = load()
    if args.upstream:
        return upstream(entries)
    if args.check:
        return check(entries)
    OUT.write_text(render(entries))
    print(f"msc-ledger: wrote {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
