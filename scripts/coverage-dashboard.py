#!/usr/bin/env python3
"""Generate the coverage and feature dashboard from the route table.

The implemented column is *parsed out of the router*, not typed: an endpoint
appears here because `routes.rs` registers it, so the dashboard cannot claim
a surface the server does not serve. What still needs human judgement — which
endpoints are in scope but missing, and where each milestone stands — lives
in the curated tables below, where a pull request reviews it like any other
claim. A CI gate regenerates this file and fails on drift, so the published
page and the code move together or not at all.

Usage:
    scripts/coverage-dashboard.py                 # rewrite docs/dashboard.md
    scripts/coverage-dashboard.py --check         # fail if docs/dashboard.md is stale
    scripts/coverage-dashboard.py --html out.html # also render the page form
"""

from __future__ import annotations

import argparse
import html
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
ROUTES = REPO / "crates" / "spindle-server" / "src" / "routes.rs"
DASHBOARD = REPO / "docs" / "dashboard.md"

# ---------------------------------------------------------------------------
# Curated: milestone standing. Statuses are claims, and claims get reviewed —
# that is why they live in a script a pull request diffs rather than in prose
# nobody re-reads. Issue numbers refer to tuna-os/spindle.
MILESTONES = [
    ("M0", "Prove the core", "**Done**",
     "Fork resolution vs ruma-state-res and HAMT-vs-im benchmarks published on the "
     "[benchmark site](https://tuna-os.github.io/spindle/); durability and recovery "
     "covered by restart and torn-write tests."),
    ("M1", "Usable local homeserver", "**Done**",
     "Full local CS-API surface with classic `/sync`; leftovers tracked on #7 "
     "(room upgrade, spaces, search, pushers, OpenAPI validation, Element Web rig). "
     "Benchmarked vs Synapse and Continuwuity — see docs/benchmarks.md."),
    ("M2", "Modern encrypted clients", "**Done**",
     "Media + thumbnails (#99, #104), Simplified Sliding Sync (#105), E2EE "
     "transport (#106), fallback keys + device lists (#107), key backup + "
     "cross-signing (#108), URL previews (#109), S3 media backend (#110). "
     "Close-out benchmark: four-way vs Synapse, Continuwuity and Tuwunel "
     "(built from source) — 60 of 63 cells won; the one real loss became "
     "#113's unread-index fix (11.79 ms → 1.00 ms); the three residual cells "
     "are within measured noise. See docs/benchmarks.md and the comparisons "
     "page. Element X client-gate work continues as #112."),
    ("M3", "Ordinary Matrix federation", "In progress",
     "Started with #14's identity layer: X-Matrix request signing and "
     "verification against fetched-and-cached peer keys (self-signature, "
     "name binding, capped validity all enforced; every failure a uniform "
     "401), /version, and the first authenticated query. Inbound /send "
     "receives foreign PDUs through the same authorization predicate local "
     "events pass, with per-origin transaction replay and spec-correct "
     "redact-on-hash-mismatch; the outbound queue delivers local events to "
     "every live-member server with ack-before-delete, deterministic "
     "transaction IDs and per-destination backoff — #14 is functionally "
     "complete. #15 under way: state reads (/state, /state_ids, /event) "
     "serve peers from the materialized log, and the make_join/send_join "
     "handshake admits remote users — template previews the real "
     "authorization, the sent join faces the same judgement chain as any "
     "PDU, and the response carries the state before the join with its "
     "transitive auth chain. Backfill and get_missing_events serve history "
     "as bounded range reads on the linear log, and 8448 serves TLS. "
     "Remote joins work in both roles: the server walks "
     "make_join/send_join as the joining side and seeds the room from the "
     "response — proven by a two-instance Spindle-to-Spindle test with "
     "messages flowing both ways. Next: #16's fork-proof rig — where the no-state-resolution claim meets "
     "adversarial evidence."),
    ("M4", "Ecosystem integration", "Not started", "#18 appservices, #17 MAS/OIDC."),
    ("M5", "Production lifecycle", "Not started",
     "#19 #20 #21; #42's parity gate vs Synapse and Tuwunel is part of the "
     "definition of done."),
    ("M6", "Optional differentiators", "Not started", "#22 hub mode, #23 MLS."),
    ("M7", "MatrixRTC", "Not started",
     "#36–#41 — delayed events (MSC4140) first; no Rust homeserver has them."),
]

# ---------------------------------------------------------------------------
# Curated: what each area still owes. An endpoint listed here is *in scope*
# for the roadmap and absent from the router; endpoints that are neither
# implemented nor listed are out of scope (deprecated surfaces, bundled
# services the roadmap explicitly refuses). Keep entries tuple-of-(method,
# path, note); the generator cross-checks every entry against the router and
# fails if one has since been implemented, so this list can only rot loudly.
PLANNED = {
    "Accounts, devices & auth": [
        ("POST", "/_matrix/client/v3/account/password", "password change (M1 leftover)"),
        ("POST", "/_matrix/client/v3/account/deactivate", "deactivation (M1 leftover)"),
        ("POST", "/_matrix/client/v3/delete_devices", "bulk device logout (M2)"),
    ],
    "Profiles & presence": [
        ("GET", "/_matrix/client/v3/presence/{user_id}/status", "presence (M2/M3)"),
    ],
    "Rooms & membership": [
        ("POST", "/_matrix/client/v3/knock/{room_id_or_alias}", "knocking"),
        ("POST", "/_matrix/client/v3/rooms/{room_id}/upgrade", "room upgrade (#7)"),
        ("GET", "/_matrix/client/v3/publicRooms", "public room directory"),
        ("POST", "/_matrix/client/v3/user_directory/search", "user directory"),
        ("GET", "/_matrix/client/v1/rooms/{room_id}/hierarchy", "spaces (#7)"),
        ("GET", "/_matrix/client/v1/rooms/{room_id}/threads", "thread listing"),
        ("POST", "/_matrix/client/v3/rooms/{room_id}/report/{event_id}", "reporting (M5)"),
        ("GET", "/_matrix/client/v1/rooms/{room_id}/timestamp_to_event", "jump-to-date"),
    ],
    "Timeline, messaging & search": [
        ("POST", "/_matrix/client/v3/search", "server-side search (#7)"),
        ("GET", "/_matrix/client/v3/notifications", "notification list"),
    ],
    "Sync": [],
    "Account data, filters & push": [
        ("GET", "/_matrix/client/v3/pushers", "pusher list (#7)"),
        ("POST", "/_matrix/client/v3/pushers/set", "pusher registration (#7)"),
    ],
    "End-to-end encryption": [],
    "Media": [],
    "Server, discovery & operations": [],
    "Federation": [
        ("PUT", "/_matrix/federation/v2/invite/{roomId}/{eventId}", "federated invites (#15)"),
    ],
    "VoIP & MatrixRTC": [
        ("GET", "/_matrix/client/v3/voip/turnServer", "TURN discovery (M7)"),
    ],
}

# How implemented paths are grouped. First match wins, so more specific
# prefixes come first.
AREA_RULES = [
    ("Federation", ("/_matrix/federation/",)),
    ("End-to-end encryption", ("/_matrix/client/v3/keys/", "/_matrix/client/v3/sendToDevice/")),
    ("Sync", ("/_matrix/client/v3/sync", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync")),
    ("Account data, filters & push", ("/_matrix/client/v3/user/", "/_matrix/client/v3/pushrules/")),
    ("Media", ("/_matrix/client/v1/media/", "/_matrix/media/v3/", "/_matrix/client/v1/media/config")),
    ("Timeline, messaging & search", (
        "/_matrix/client/v3/rooms/{room_id}/messages",
        "/_matrix/client/v3/rooms/{room_id}/context/",
        "/_matrix/client/v3/rooms/{room_id}/event/",
        "/_matrix/client/v3/rooms/{room_id}/send/",
        "/_matrix/client/v3/rooms/{room_id}/redact/",
        "/_matrix/client/v1/rooms/{room_id}/relations/",
        "/_matrix/client/v3/rooms/{room_id}/receipt/",
        "/_matrix/client/v3/rooms/{room_id}/read_markers",
        "/_matrix/client/v3/rooms/{room_id}/typing/",
    )),
    ("Rooms & membership", (
        "/_matrix/client/v3/createRoom",
        "/_matrix/client/v3/rooms/",
        "/_matrix/client/v3/join/",
        "/_matrix/client/v3/joined_rooms",
        "/_matrix/client/v3/directory/",
        "/_matrix/client/v1/room_summary/",
        "/_matrix/client/unstable/im.nheko.summary/",
    )),
    ("Accounts, devices & auth", (
        "/_matrix/client/v3/register",
        "/_matrix/client/v3/login",
        "/_matrix/client/v3/logout",
        "/_matrix/client/v3/refresh",
        "/_matrix/client/v3/account/",
    )),
    ("Server, discovery & operations", (
        "/_matrix/client/versions",
        "/_matrix/client/v3/capabilities",
        "/.well-known/",
        "/_matrix/key/",
        "/health",
        "/ready",
    )),
]


def parse_routes() -> list[tuple[str, list[str]]]:
    """Every `.route("path", …)` in the router, with all chained methods.

    A balanced-paren scan rather than a one-line regex, because a third of
    the registrations chain methods (`get(x).put(y)`) across lines and a
    regex that stops at the first method under-reports the surface.
    """
    source = ROUTES.read_text()
    routes = []
    index = 0
    while True:
        index = source.find(".route(", index)
        if index < 0:
            break
        depth, end = 0, index + len(".route(") - 1
        while True:
            if source[end] == "(":
                depth += 1
            elif source[end] == ")":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        call = source[index : end + 1]
        path = re.search(r'"([^"]+)"', call).group(1)
        methods = [m.upper() for m in re.findall(r"\b(get|post|put|delete|patch)\(", call)]
        routes.append((path, methods))
        index = end
    return sorted(routes)


def area_of(path: str) -> str:
    for area, prefixes in AREA_RULES:
        if any(path.startswith(prefix) for prefix in prefixes):
            return area
    return "Server, discovery & operations"


def build_markdown() -> str:
    routes = parse_routes()
    implemented: dict[str, list[tuple[str, list[str]]]] = {}
    for path, methods in routes:
        implemented.setdefault(area_of(path), []).append((path, methods))

    # A planned entry that the router now serves is stale curation; refuse to
    # publish it. Silently dropping it instead would let the list rot quietly.
    served = {(method, path) for path, methods in routes for method in methods}
    for area, entries in PLANNED.items():
        for method, path, _ in entries:
            if (method, path) in served:
                raise SystemExit(
                    f"coverage-dashboard: PLANNED lists {method} {path} "
                    f"({area}) but the router serves it — remove the entry"
                )

    lines = [
        "# Spindle dashboard",
        "",
        "<!-- GENERATED by scripts/coverage-dashboard.py — edit the script, not this file. -->",
        "<!-- CI regenerates this and fails on drift, so what you read matches main. -->",
        "",
        "The **implemented** counts below are parsed out of the router at",
        "generation time: an endpoint is listed because `routes.rs` registers",
        "it. The **planned** lists and milestone standings are curated in the",
        "generator script, where pull requests review them; a planned entry",
        "that gets implemented breaks the build until it is removed.",
        "",
        "## Milestones",
        "",
        "Roadmap: #4. Statuses here are the current standing, not the plan.",
        "",
        "| Milestone | Scope | Status | Evidence |",
        "|---|---|---|---|",
    ]
    for name, scope, status, evidence in MILESTONES:
        lines.append(f"| {name} | {scope} | {status} | {evidence} |")

    total_impl = len(routes)
    total_planned = sum(len(v) for v in PLANNED.values())
    lines += [
        "",
        "## Endpoint coverage",
        "",
        f"**{total_impl} routes implemented; {total_planned} known gaps in scope.**",
        "Deprecated surfaces and deliberately-unbundled services (TURN, push",
        "gateway, identity server — see #4's *what not to build early*) are",
        "neither implemented nor counted.",
        "",
    ]
    for area, _ in AREA_RULES + [("VoIP & MatrixRTC", ())]:
        if area in ("Server, discovery & operations",) and area not in implemented:
            continue
        have = implemented.get(area, [])
        missing = PLANNED.get(area, [])
        lines.append(f"### {area} — {len(have)} implemented, {len(missing)} planned")
        lines.append("")
        for path, methods in have:
            lines.append(f"- `{'/'.join(methods)} {path}`")
        for method, path, note in missing:
            lines.append(f"- ⏳ `{method} {path}` — {note}")
        lines.append("")

    lines += [
        "## Benchmarks",
        "",
        "- **Micro-benchmarks** (fork resolution vs ruma-state-res, HAMT vs im,",
        "  storage ops): published automatically to the",
        "  [benchmark site](https://tuna-os.github.io/spindle/) on every push",
        "  to main — the numbers in the open are the numbers from the code.",
        "- **Server-level comparisons** vs Synapse and Continuwuity: measured",
        "  per milestone with `scripts/api-benchmark.py` (same driver, same",
        "  host, same sitting); raw results are committed under",
        "  docs/benchmarks/data/ and rendered to the",
        "  [comparisons page](https://tuna-os.github.io/spindle/comparisons.html),",
        "  with method and caveats in",
        "  [docs/benchmarks.md](./benchmarks.md). As of the M2 close-out the",
        "  comparison covers all three siblings — Tuwunel builds from source",
        "  in the bench environment (the recipe is in docs/benchmarks.md).",
        "- What the CS-API numbers do **not** establish — the fork/state-",
        "  resolution claim — is documented in docs/benchmarks.md; it needs",
        "  #16's federated rig.",
        "",
    ]
    return "\n".join(lines)


def to_html(markdown: str) -> str:
    """A deliberately dumb page: tables and lists, no client-side anything.

    Enough markdown for this file's own structure, converted line by line —
    pulling in a renderer for one page would be a dependency with one caller.
    """
    body: list[str] = []
    in_list = False
    in_table = False
    for line in markdown.splitlines():
        if line.startswith("<!--"):
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= {"-"} for c in cells):
                continue
            if not in_table:
                body.append("<table>")
                in_table = True
                tag = "th"
            else:
                tag = "td"
            row = "".join(f"<{tag}>{inline(c)}</{tag}>" for c in cells)
            body.append(f"<tr>{row}</tr>")
            continue
        if in_table:
            body.append("</table>")
            in_table = False
        if line.startswith("- "):
            if not in_list:
                body.append("<ul>")
                in_list = True
            body.append(f"<li>{inline(line[2:])}</li>")
            continue
        if line.startswith("  ") and in_list and line.strip():
            body[-1] = body[-1][: -len("</li>")] + " " + inline(line.strip()) + "</li>"
            continue
        if in_list:
            body.append("</ul>")
            in_list = False
        if line.startswith("### "):
            body.append(f"<h3>{inline(line[4:])}</h3>")
        elif line.startswith("## "):
            body.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("# "):
            body.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.strip():
            body.append(f"<p>{inline(line)}</p>")
    if in_list:
        body.append("</ul>")
    if in_table:
        body.append("</table>")
    content = "\n".join(body)
    return f"""<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Spindle dashboard</title>
<style>
body {{ font: 15px/1.5 system-ui, sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
table {{ border-collapse: collapse; margin: 1rem 0; }}
th, td {{ border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; vertical-align: top; }}
code {{ background: #f3f3f3; padding: .1rem .3rem; border-radius: 3px; font-size: .9em; }}
nav {{ margin-bottom: 1rem; }}
</style>
<nav><a href="./comparisons.html"><strong>Spindle vs the field</strong></a> · <a href="./index.html">micro-benchmarks</a></nav>
{content}
"""


def inline(text: str) -> str:
    text = html.escape(text, quote=False)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    text = re.sub(
        r"#(\d+)\b",
        r'<a href="https://github.com/tuna-os/spindle/issues/\1">#\1</a>',
        text,
    )
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if docs/dashboard.md does not match")
    parser.add_argument("--html", type=pathlib.Path,
                        help="also write the HTML page form here")
    arguments = parser.parse_args()

    markdown = build_markdown() + "\n"
    if arguments.check:
        current = DASHBOARD.read_text() if DASHBOARD.exists() else ""
        if current != markdown:
            print(
                "coverage-dashboard: docs/dashboard.md is stale.\n"
                "Run scripts/coverage-dashboard.py and commit the result.",
                file=sys.stderr,
            )
            return 1
        print("coverage-dashboard: docs/dashboard.md matches the router")
    else:
        DASHBOARD.write_text(markdown)
        print(f"coverage-dashboard: wrote {DASHBOARD}")
    if arguments.html:
        arguments.html.parent.mkdir(parents=True, exist_ok=True)
        arguments.html.write_text(to_html(markdown))
        print(f"coverage-dashboard: wrote {arguments.html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
