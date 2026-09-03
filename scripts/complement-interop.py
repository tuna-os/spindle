#!/usr/bin/env python3
"""Read a heterogeneous Complement run against the homogeneous baseline.

A run with a real Synapse on the other end of the wire (docs/conformance-
testing.md §5.1, #16) legitimately does not match the homogeneous result set,
which is why it is a report-only board and not a second ratchet. But a raw
ledger from such a run is unreadable for the one question it exists to
answer -- *did federating with a different implementation break something
that works between two Spindles?* -- because most of what fails in it fails
in the homogeneous run too, and some of what fails is the peer's own
behaviour and not ours.

So this diffs the interop ledger against the baseline ledger the same
commit produced, and sorts every test into one of five piles:

  shared passes       pass in both -- the interop path works there
  baseline gaps       not passing in either -- known debt, not interop's
  peer-side           passed homogeneous, failed here, and the name is in
                      complement/interop-known.txt with a reason: a peer
                      deprecation or difference that is not a Spindle bug
  regressions         passed homogeneous, failed here, and nobody has said
                      why -- the only pile that is news
  gained              not passing homogeneous, passing here -- the peer
                      did the work, which is worth knowing and not a pass

Tests the interop run skipped are listed on their own: a skip is a test
that ran nothing, and reading it as either pass or fail would be wrong.

The regressions carry the tail of their captured output, the way
scripts/complement-check.py prints a red ratchet's, so the report can be
acted on without downloading the artifact.

Usage:
    scripts/complement-interop.py --baseline tmp/complement-results.jsonl \\
        --interop tmp/compliance-interop.jsonl [--known FILE] [--peer NAME] \\
        [--report FILE] [--fail-on-regression]
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_KNOWN = HERE.parent / "complement" / "interop-known.txt"


def load_check():
    """The ratchet's ledger reader and failure formatter, reused.

    One ledger format, one parser: the script's name is not an identifier,
    so it is imported by path rather than copied.
    """
    spec = importlib.util.spec_from_file_location("complement_check", HERE / "complement-check.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def read_known(path: Path) -> dict[str, str]:
    """Test name (or top-level prefix) -> why the peer fails it.

    A name matches itself and every subtest under it, so one line covers a
    parallel test's whole tree. Test names carry no whitespace -- Complement
    replaces spaces in subtest names with underscores -- so the first run of
    whitespace separates the name from the reason.
    """
    known: dict[str, str] = {}
    if not path.exists():
        return known
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, reason = line.partition(" ")
        reason = reason.strip()
        if not reason:
            raise SystemExit(
                f"complement-interop: {path}: `{name}` has no reason; a peer-side "
                "entry without one is a regression nobody has explained"
            )
        known[name] = reason
    return known


def known_reason(test: str, known: dict[str, str]) -> str | None:
    if test in known:
        return known[test]
    for name, reason in known.items():
        if test.startswith(name + "/"):
            return reason
    return None


@dataclass
class Report:
    shared: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    peer_side: list[tuple[str, str]] = field(default_factory=list)
    regressions: list[str] = field(default_factory=list)
    gained: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def compare(
    baseline: dict[str, str],
    interop: dict[str, str],
    known: dict[str, str],
) -> Report:
    """Sort every test either run saw into the piles above."""
    report = Report()
    for test in sorted(set(baseline) | set(interop)):
        before = baseline.get(test) == "pass"
        after = interop.get(test)
        if after == "skip":
            report.skipped.append(test)
        elif before and after == "pass":
            report.shared.append(test)
        elif before:
            reason = known_reason(test, known)
            if reason is None:
                report.regressions.append(test)
            else:
                report.peer_side.append((test, reason))
        elif after == "pass":
            report.gained.append(test)
        else:
            report.gaps.append(test)
    return report


def render(report: Report, output: dict[str, list[str]], peer: str, detail) -> str:
    lines = [
        f"## Complement interop: {peer}",
        "",
        "| Pile | Tests | Meaning |",
        "|---|---:|---|",
        f"| Shared passes | {len(report.shared)} | pass with two Spindles and with the peer |",
        f"| Baseline gaps | {len(report.gaps)} | not passing homogeneous either: debt, not interop |",
        f"| Peer-side | {len(report.peer_side)} | fail only with the peer, for a reason in complement/interop-known.txt |",
        f"| **Regressions** | {len(report.regressions)} | pass with two Spindles, fail with the peer, unexplained |",
        f"| Gained | {len(report.gained)} | pass only with the peer: the peer did the work |",
        f"| Skipped | {len(report.skipped)} | ran nothing in the interop run |",
        "",
    ]
    if report.regressions:
        lines.append("### Regressions")
        lines.append("")
        for test in report.regressions:
            lines.append(f"- `{test}`")
            for line in detail(output.get(test, [])):
                lines.append(f"      {line}")
        lines.append("")
    if report.peer_side:
        lines.append("### Peer-side")
        lines.append("")
        for test, reason in report.peer_side:
            lines.append(f"- `{test}`: {reason}")
        lines.append("")
    if report.gained:
        lines.append("### Gained")
        lines.append("")
        for test in report.gained:
            lines.append(f"- `{test}`")
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True, help="homogeneous ledger")
    parser.add_argument("--interop", type=Path, required=True, help="heterogeneous ledger")
    parser.add_argument("--known", type=Path, default=DEFAULT_KNOWN, help="peer-side reasons")
    parser.add_argument("--peer", default="synapse", help="what was on the other end")
    parser.add_argument("--report", type=Path, help="also write the markdown here")
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="exit 1 when the regressions pile is not empty",
    )
    arguments = parser.parse_args()

    check = load_check()
    for name, path in (("baseline", arguments.baseline), ("interop", arguments.interop)):
        if not path.exists():
            print(f"complement-interop: no {name} ledger at {path}", file=sys.stderr)
            return 1
    baseline, _ = check.read_ledger(arguments.baseline)
    interop, output = check.read_ledger(arguments.interop)
    for name, outcomes in (("baseline", baseline), ("interop", interop)):
        if not outcomes:
            # A crashed run writes no results, and "nothing regressed" would
            # be the worst possible reading of that.
            print(f"complement-interop: the {name} ledger holds no results at all", file=sys.stderr)
            return 1

    report = compare(baseline, interop, read_known(arguments.known))
    text = render(report, output, arguments.peer, check.failure_detail)
    print(text)
    if arguments.report:
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(text + "\n", encoding="utf-8")

    if arguments.fail_on_regression and report.regressions:
        print(
            f"complement-interop: {len(report.regressions)} tests pass between two "
            "Spindles and fail with the peer",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
