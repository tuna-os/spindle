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

import sitetheme

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
    ("M4", "Ecosystem integration", "In progress",
     "Both halves are built and under test, which is why this no longer reads "
     "*not started*. #18: appservice registration, authentication and "
     "namespaces, transactions with per-appservice queues, MSC2409 to-device "
     "delivery with restart redelivery, MSC4190 deviceless clients, ping "
     "(MSC2659), queries and the key proxy — six test files. #17: MSC3861 "
     "delegated authentication with introspection and gating, the "
     "`/_synapse/mas/*` homeserver-connection surface MAS drives, and a "
     "built-in OIDC provider (#159) for deployments that do not want a "
     "separate MAS. 17 of the router's endpoints come from `mas.rs` and "
     "`oidc.rs`. #17 and #18 stay open for the remaining bridge evidence."),
    ("M5", "Production lifecycle", "In progress",
     "#83's admin API is served: 18 endpoints under `/_spindle/admin/v1`, "
     "each also mounted at `/_synapse/admin/v1` for existing tooling — users, "
     "rooms, state-at, purge_history, room deletion, make_room_admin and the "
     "audit log. #166's observability landed too: a `/metrics` exposition on "
     "its own listener with the fork-case counter, append and HTTP "
     "histograms. #21 has its counting performance gate (`read_budget.rs`, "
     "#177), which asserts flat-in-membership rather than timing on CI. "
     "#20 is three-quarters done and split: `spindle backup`, `restore` and "
     "`verify-media` are served, and #230 added versioned schema migrations "
     "whose guarantees — chaining, the no-path refusal, dry runs writing "
     "nothing, and the marker never landing ahead of the data — are proven "
     "against synthetic tables; the real migration table is deliberately "
     "empty because no schema change has yet needed a data rewrite, and "
     "`docs/lifecycle.md` says so rather than implying otherwise. The "
     "Synapse importer moved to #240 and is parked behind the API surface "
     "and MatrixRTC: its fixture (#234, #237), ordering and divergence "
     "check (#235) and SQLite reader (#239) are on main, and the exit "
     "criterion has been executed end to end once. `backups.rs` is M2's "
     "E2EE key backup and not this. #42's parity gate vs Synapse and "
     "Tuwunel remains part of the definition of done."),
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
    ],
    "Profiles & presence": [
        ("GET", "/_matrix/client/v3/presence/{user_id}/status", "presence (M2/M3)"),
    ],
    "Rooms & membership": [
        ("POST", "/_matrix/client/v3/rooms/{room_id}/upgrade", "room upgrade (#7)"),
        ("POST", "/_matrix/client/v3/rooms/{room_id}/report/{event_id}", "reporting (M5)"),
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
    # Federated invites came out of this list, not because the gap was
    # waived but because #15 shipped it — `federation_invite` has been
    # routed all along, and only the placeholder spelling
    # (`{roomId}` here against `{room_id}` in the router) kept the
    # stale-entry check from saying so.
    "Federation": [],
    "VoIP & MatrixRTC": [
        ("GET", "/_matrix/client/v3/voip/turnServer", "TURN discovery (M7)"),
    ],
}

# How implemented paths are grouped. First match wins, so more specific
# prefixes come first.
AREA_RULES = [
    # Widening the parser to follow the router's merges (admin, MAS, OIDC)
    # put 73 of 154 endpoints into the catch-all, which is not a breakdown --
    # it is a pile. These four areas are the milestones those endpoints
    # belong to, so the page shows M4's and M5's surfaces as their own rows
    # instead of burying them under "server and operations".
    ("Admin & moderation", ("/_spindle/admin/", "/_synapse/admin/")),
    ("Delegated auth & OIDC", (
        "/_synapse/mas/",
        "/_matrix/client/v1/auth_metadata",
        "/_matrix/client/unstable/org.matrix.msc2965/",
        "/.well-known/openid-configuration",
        "/_matrix/client/unstable/org.matrix.msc2964/",
        "/oauth2/",
        "/_spindle/oidc/",
    )),
    ("Appservices", ("/_matrix/app/", "/_matrix/client/v1/appservice/")),
    ("Key backup", ("/_matrix/client/v3/room_keys/",)),
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
        "/_matrix/client/v3/knock/",
        "/_matrix/client/v3/joined_rooms",
        "/_matrix/client/v3/directory/",
        "/_matrix/client/v1/room_summary/",
        "/_matrix/client/unstable/im.nheko.summary/",
    )),
    # `profile/` had no rule at all, so three served endpoints fell into the
    # catch-all and "Profiles & presence" drew a 0%% bar next to its one
    # planned entry -- an area reading as untouched while three quarters of
    # it shipped.
    ("Profiles & presence", (
        "/_matrix/client/v3/profile/",
        "/_matrix/client/v3/presence/",
    )),
    ("Accounts, devices & auth", (
        "/_matrix/client/v3/register",
        "/_matrix/client/v3/login",
        "/_matrix/client/v3/logout",
        "/_matrix/client/v3/refresh",
        "/_matrix/client/v3/account/",
        "/_matrix/client/v3/devices",
        "/_matrix/client/v3/delete_devices",
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


def route_sources() -> list[pathlib.Path]:
    """Every file that contributes routes to the merged router.

    `routes.rs` is not the whole router. It ends by merging sibling modules
    that register their own:

        .merge(crate::mas::routes())
        .merge(crate::admin::routes())

    Reading only `routes.rs` missed 35 of 136 endpoints -- the entire admin
    API, the whole MAS surface, and the built-in OIDC provider. On a page
    whose premise is that the implemented column is parsed rather than
    typed, so it "cannot claim a surface the server does not serve",
    failing to show a surface it *does* serve is the same misrepresentation
    pointed the other way -- and worse here, because the page exists to say
    what is left to build.

    Derived from the merge calls rather than hand-listed, for the same
    reason `areas()` is: a hand-list is a second place to forget.

    `main.rs` is deliberately excluded. Its one `.route` is the `/metrics`
    exposition, which runs on its own listener (`[metrics] bind`) and is not
    part of the client-server surface this page inventories.
    """
    source = ROUTES.read_text()
    files = [ROUTES]
    for module in re.findall(r"\.merge\(crate::(\w+)::routes\(\)\)", source):
        path = ROUTES.parent / f"{module}.rs"
        if path.exists() and path not in files:
            files.append(path)
    return files


def parse_routes() -> list[tuple[str, list[str]]]:
    """Every `.route("path", …)` the merged router registers.

    A balanced-paren scan rather than a one-line regex, because a third of
    the registrations chain methods (`get(x).put(y)`) across lines and a
    regex that stops at the first method under-reports the surface.
    """
    routes = []
    for source_file in route_sources():
        routes.extend(_routes_in(source_file.read_text()))

    # Nothing may reach the page with an unexpanded interpolation in it. A
    # path like `{prefix}/users` is not an endpoint; publishing one would be
    # worse than the undercount this parser was widened to fix, because it
    # reads as a real route until someone tries it.
    for path, _ in routes:
        if "{prefix}" in path or path.startswith("{"):
            raise SystemExit(
                f"coverage-dashboard: {path!r} still holds an unexpanded "
                "format argument; teach `_prefixes_in` how that router is built"
            )
    return sorted(routes)


def _prefixes_in(source: str) -> list[str]:
    """The literal path prefixes a file applies its route group under.

    `admin.rs` builds one group of routes from a `format!("{prefix}/…")`
    template and mounts it twice --

        group("/_spindle/admin/v1").merge(group("/_synapse/admin/v1"))

    -- because the `/_synapse/admin/v1` alias is what existing tooling
    drives. Reading the template literally yields nine `{prefix}/…`
    non-paths instead of eighteen real ones, so the interpolation has to be
    resolved rather than printed.

    Returns an empty list for the ordinary case, where paths are literals.
    """
    closure = re.search(r"let\s+(\w+)\s*=\s*\|\s*\w+\s*:\s*&str\s*\|", source)
    if not closure:
        return []
    calls = re.findall(rf"\b{closure.group(1)}\(\s*\"(/[^\"]*)\"\s*\)", source)
    return list(dict.fromkeys(calls))


def _routes_in(source: str) -> list[tuple[str, list[str]]]:
    """The `.route(…)` registrations in one file's text.

    A templated path is emitted once per prefix the file mounts the group
    under, because that is how many endpoints the router ends up serving.
    """
    prefixes = _prefixes_in(source)
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
        if "{prefix}" in path and prefixes:
            # Inside a `format!` a literal brace is doubled, so the path
            # parameters in the template read `{{room_id}}`. Undo that, or
            # every templated route is published with braces the router
            # never had.
            path = path.replace("{{", "{").replace("}}", "}")
            for prefix in prefixes:
                routes.append((path.replace("{prefix}", prefix), methods))
        else:
            routes.append((path, methods))
        index = end
    return routes


def _shape(path: str) -> str:
    """A path with its parameter names erased.

    `/rooms/{room_id}/state` and `/rooms/{roomId}/state` are the same
    endpoint; only the placeholder spelling differs, and the spec and this
    router disagree about it in places. Comparing shapes rather than strings
    is what makes the stale-gap check actually catch a stale gap.
    """
    return re.sub(r"\{[^}]*\}", "{}", path)


def area_of(path: str) -> str:
    for area, prefixes in AREA_RULES:
        if any(path.startswith(prefix) for prefix in prefixes):
            return area
    return "Server, discovery & operations"


def survey() -> tuple[list[tuple[str, list[str]]], dict[str, list[tuple[str, list[str]]]]]:
    """The routes the server serves, and the same grouped by area.

    Shared by the markdown and the HTML so the published page and the
    committed file cannot describe different surfaces — the whole reason the
    implemented column is parsed rather than typed.
    """
    routes = parse_routes()
    implemented: dict[str, list[tuple[str, list[str]]]] = {}
    for path, methods in routes:
        implemented.setdefault(area_of(path), []).append((path, methods))

    # A planned entry that the router now serves is stale curation; refuse to
    # publish it. Silently dropping it instead would let the list rot quietly.
    #
    # Compared with parameter *names* erased, because that guarantee already
    # failed once on spelling alone: the router registers
    # `/_matrix/federation/v2/invite/{room_id}/{event_id}` and this list said
    # `{roomId}/{eventId}`, so an endpoint #15 had shipped went on being
    # published as a known gap. A list that "can only rot loudly" must not be
    # defeated by camelCase.
    served = {
        (method, _shape(path)) for path, methods in routes for method in methods
    }
    for area, entries in PLANNED.items():
        for method, path, _ in entries:
            if (method, _shape(path)) in served:
                raise SystemExit(
                    f"coverage-dashboard: PLANNED lists {method} {path} "
                    f"({area}) but the router serves it — remove the entry"
                )
    return routes, implemented


def areas() -> list[str]:
    """Every area, in the order the page presents them.

    Derived from both tables rather than hand-listed. It was hand-listed --
    `AREA_RULES` plus a literal `"VoIP & MatrixRTC"` -- and the cost of that
    was `Profiles & presence`, which exists only in `PLANNED` and so was
    never rendered at all. Its one endpoint counted toward the headline gap
    total and appeared in none of the lists below it, which is the specific
    failure a coverage page must not have: a gap it knows about and does not
    show.
    """
    ordered = [area for area, _ in AREA_RULES]
    for area in PLANNED:
        if area not in ordered:
            ordered.append(area)
    return ordered


def build_markdown() -> str:
    routes, implemented = survey()

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
    for area in areas():
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


DASHBOARD_CSS = """
.bars { display: grid; gap: 10px; margin: 16px 0 0; }
.bar { display: grid; grid-template-columns: minmax(11rem, 15rem) 1fr auto;
  gap: 12px; align-items: center; }
.bar .name { font-size: .92rem; }
/* `display: block` is load-bearing: these are spans, and an inline box
   ignores width and height, which rendered every bar as an empty sliver --
   including the areas that are complete. */
.bar .track { display: block; height: 20px; border-radius: 6px;
  background: var(--loss-bg); overflow: hidden;
  border: 1px solid var(--line); }
.bar .fill { display: block; height: 100%; min-width: 2px;
  background: var(--win-fg); opacity: .85; }
.bar .count { font-size: .85rem; color: var(--muted);
  font-variant-numeric: tabular-nums; white-space: nowrap; }

.remaining { display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px; margin-top: 16px; }
.remaining h3 { margin: 0 0 8px; font-size: .95rem; }
.remaining ul { margin: 0; padding-left: 0; list-style: none; }
.remaining li { padding: 5px 0; border-top: 1px solid var(--line);
  font-size: .87rem; }
.remaining li:first-child { border-top: 0; }
.remaining .m { display: inline-block; min-width: 3.2em; font-weight: 600;
  color: var(--loss-fg); font-size: .78rem; }
.remaining .note { color: var(--muted); display: block; margin-left: 3.2em; }

.ms { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 14px; margin-top: 16px; }
.ms .card h3 { margin: 0 0 4px; font-size: 1rem; }
.ms .card p { margin: 6px 0 0; font-size: .85rem; color: var(--muted); }
.ms .done { border-left: 4px solid var(--win-fg); }
.ms .wip { border-left: 4px solid var(--accent); }
.ms .todo { border-left: 4px solid var(--line); }

details.area { margin: 8px 0; }
details.area summary { cursor: pointer; padding: 6px 0; font-weight: 600; }
details.area .paths { columns: 2 22rem; column-gap: 24px; margin: 6px 0 12px; }
details.area .paths div { break-inside: avoid; font-size: .82rem;
  padding: 2px 0; color: var(--muted); }
details.area .paths .verb { color: var(--win-fg); font-weight: 600; }
"""


def status_class(status: str) -> str:
    """Which accent a milestone card carries, from its curated status."""
    plain = status.replace("*", "").strip().lower()
    if plain.startswith("done"):
        return "done"
    if "progress" in plain:
        return "wip"
    return "todo"


def build_html() -> str:
    """The coverage dashboard.

    Rendered from the same survey the markdown uses rather than by parsing
    the markdown back out -- the previous version did that, and it meant the
    page could only ever show what a line-by-line markdown converter could
    express, which is why it was a wall of bullet lists.

    The headline it leads with is *in-scope* coverage: implemented over
    implemented-plus-planned. That is deliberately not "percent of the Matrix
    spec", and the page says so, because the denominator here is a curated
    list of what this roadmap intends to build. Reaching 100% would mean
    nothing we have scoped is missing -- not that the spec is finished.
    """
    routes, implemented = survey()
    total_impl = len(routes)
    total_planned = sum(len(v) for v in PLANNED.values())
    total = total_impl + total_planned
    pct = round(100 * total_impl / total) if total else 100

    out: list[str] = [
        sitetheme.head("Spindle coverage", DASHBOARD_CSS),
        sitetheme.nav("dashboard.html"),
        "<main>",
        '<div class="hero"><h1>Coverage</h1>',
        '<p class="sub">Every endpoint below is read out of the router at build '
        "time, so this page cannot claim a surface the server does not serve. "
        "What is <em>missing</em> is curated, reviewed in pull requests, and "
        "cross-checked against the router — a gap that gets implemented and "
        "left listed here fails the build.</p>",
        '<div class="scoreline">',
        f'<div class="score win"><b>{total_impl}</b>routes served</div>',
        f'<div class="score loss"><b>{total_planned}</b>known gaps</div>',
        f'<div class="score"><b>{pct}%</b>of scoped surface</div>',
        "</div></div>",
    ]

    out.append("<h2>Where the gaps are</h2>")
    out.append(
        '<p class="legend">Implemented against implemented-plus-planned, per '
        "area. The denominator is what this roadmap has scoped, not the whole "
        "specification: a full bar means nothing we intend to build in that "
        "area is outstanding.</p>"
    )
    out.append('<div class="bars">')
    rows = []
    for area in areas():
        have, missing = len(implemented.get(area, [])), len(PLANNED.get(area, []))
        if have + missing:
            rows.append((area, have, missing))
    # Least-complete first: the page exists to show what is left.
    for area, have, missing in sorted(rows, key=lambda r: (r[1] / (r[1] + r[2]), -r[2])):
        share = round(100 * have / (have + missing))
        out.append(
            '<div class="bar">'
            f'<span class="name">{html.escape(area)}</span>'
            f'<span class="track"><span class="fill" style="width:{share}%"></span></span>'
            f'<span class="count">{have} served · {missing} left</span>'
            "</div>"
        )
    out.append("</div>")

    out.append("<h2>What is still missing</h2>")
    outstanding = [(a, PLANNED.get(a, [])) for a in areas() if PLANNED.get(a)]
    if outstanding:
        out.append('<div class="remaining">')
        for area, entries in outstanding:
            out.append('<div class="card">')
            out.append(f"<h3>{html.escape(area)}</h3><ul>")
            for method, path, note in entries:
                out.append(
                    f'<li><span class="m">{html.escape(method)}</span>'
                    f"<code>{html.escape(path)}</code>"
                    f'<span class="note">{inline(note)}</span></li>'
                )
            out.append("</ul></div>")
        out.append("</div>")
    else:
        out.append("<p>Nothing in scope is outstanding.</p>")
    out.append(
        '<p class="legend">Deprecated surfaces and deliberately-unbundled '
        "services — TURN, the push gateway, an identity server; see #4's "
        "<em>what not to build early</em> — are neither implemented nor "
        "counted here.</p>"
    )

    out.append("<h2>Milestones</h2>")
    out.append(
        '<p class="legend">Roadmap: #4. These are the current standing rather '
        "than the plan.</p>"
    )
    out.append('<div class="ms">')
    for name, scope, status, evidence in MILESTONES:
        out.append(
            f'<div class="card {status_class(status)}">'
            f"<h3>{html.escape(name)} — {html.escape(scope)}</h3>"
            f"<div>{inline(status)}</div>"
            f"<p>{inline(evidence)}</p></div>"
        )
    out.append("</div>")

    out.append("<h2>Every endpoint</h2>")
    out.append(
        '<p class="legend">The served surface in full, by area, as parsed from '
        "<code>routes.rs</code>.</p>"
    )
    for area in areas():
        have = implemented.get(area, [])
        if not have:
            continue
        out.append(
            f'<details class="area"><summary>{html.escape(area)} '
            f"({len(have)})</summary><div class=\"paths\">"
        )
        for path, methods in have:
            verbs = html.escape("/".join(methods))
            out.append(
                f'<div><span class="verb">{verbs}</span> {html.escape(path)}</div>'
            )
        out.append("</div></details>")

    out.append("</main>")
    out.append(
        sitetheme.footer(
            "endpoints parsed from <code>routes.rs</code>; gaps and milestones "
            "curated in <code>scripts/coverage-dashboard.py</code>"
        )
    )
    return "\n".join(out) + "\n"


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
        arguments.html.write_text(build_html())
        print(f"coverage-dashboard: wrote {arguments.html}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
