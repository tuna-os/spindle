#!/usr/bin/env python3
"""Hold contrib/limits/ledger.toml to the router and to the limiter.

    scripts/limits-ledger.py --check

A route that is in no rate limiter was found by reading, one route at a
time, nine times in one week (#953). Nothing failed when a new route
arrived with no limit, because "no limit" was never written down: it was
the absence of a call. The ledger makes it a row. Every route the router
serves has one, and the row either names the limits its handler spends or
says `none` and gives a reason somebody can disagree with.

--check, run in CI, fails when:
  * the router serves a route that has no row;
  * a row names a route the router no longer serves;
  * a row names a limit that `ratelimit.rs` does not define, or one that
    its handler does not reach;
  * a `none` row gives a reason the ledger does not define, or a reason
    with a `sees` list of which its handler reaches no name (a row cannot
    say "only an admin can call it" of a handler that never asks for one).

"Reach" is read out of the source: the handler's own text, and the text
of every function it calls by name, followed through `use`. Method calls
(`value.method()`) are not followed. That is enough here because a limit
is spent by a free function that takes the state, and it errs to the
strict side: a spend this cannot see fails the check and is fixed by
naming the function in a way it can follow.

What this does not prove is on the other side. A handler that reaches a
limit may spend it on one branch only, so a row can say `none` of a route
whose shared helper holds a spend the route never takes; the legacy media
routes are that case, and their rows say why. And no row says a limit is
the right size.

The route list is `coverage-dashboard.py`'s, so the two cannot disagree
about what the router serves. Like that page, it leaves out the fallback
and the routes of a build behind a Cargo feature.
"""

from __future__ import annotations

import argparse
import importlib
import pathlib
import re
import sys
import tomllib

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
dashboard = importlib.import_module("coverage-dashboard")

LEDGER = REPO / "contrib" / "limits" / "ledger.toml"
SOURCE = REPO / "crates" / "spindle-server" / "src"
# These two define the limits and so name every one of them. Their text
# is no evidence that a handler spends anything.
DEFINERS = ("ratelimit.rs", "config.rs")


def strip(source: str) -> str:
    """`source` with comments and literals blanked, every offset kept.

    A limit named in a doc comment or a log line is not a spend, and a
    brace inside a string is not a block.
    """
    out = list(source)
    size = len(source)

    def blank(start: int, end: int) -> None:
        for index in range(start, min(end, size)):
            if out[index] != "\n":
                out[index] = " "

    index = 0
    while index < size:
        char = source[index]
        pair = source[index : index + 2]
        after_word = index > 0 and (source[index - 1].isalnum() or source[index - 1] == "_")
        raw = None if after_word else re.match(r'b?r(#*)"', source[index:])
        if pair == "//":
            end = source.find("\n", index)
            end = size if end < 0 else end
        elif pair == "/*":
            depth, end = 1, index + 2
            while end < size and depth:
                if source[end : end + 2] == "/*":
                    depth, end = depth + 1, end + 2
                elif source[end : end + 2] == "*/":
                    depth, end = depth - 1, end + 2
                else:
                    end += 1
        elif raw:
            close = '"' + raw.group(1)
            end = source.find(close, index + raw.end())
            end = size if end < 0 else end + len(close)
        elif char == '"':
            end = index + 1
            while end < size and source[end] != '"':
                end += 2 if source[end] == "\\" else 1
            end += 1
        elif char == "'":
            # A char literal, and not a lifetime: `'a'` closes, `'a` does not.
            literal = re.match(r"'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'])'", source[index:])
            if not literal:
                index += 1
                continue
            end = index + literal.end()
        else:
            index += 1
            continue
        blank(index, end)
        index = end
    return "".join(out)


def functions(text: str) -> list[tuple[str, str]]:
    """(name, text) of every `fn` that has a body, signature included."""
    found = []
    for match in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)", text):
        index, depth = match.end(), 0
        # To the body's brace. A `{` inside the parameters or a generic
        # list is a pattern or a const expression, not the body.
        while index < len(text):
            char = text[index]
            if char in "(<[":
                depth += 1
            elif char in ")]" or (char == ">" and text[index - 1] not in "-="):
                depth -= 1
            elif depth <= 0 and char in ";{":
                break
            index += 1
        if index >= len(text) or text[index] == ";":
            continue
        end, depth = index, 0
        while end < len(text):
            depth += {"{": 1, "}": -1}.get(text[end], 0)
            if depth == 0:
                break
            end += 1
        found.append((match.group(1), text[match.start() : end + 1]))
    return found


def use_paths(tree: str, prefix: tuple[str, ...] = ()) -> list[tuple[str, tuple[str, ...]]]:
    """(local name, full path) for every item one `use` tree brings in."""
    tree = tree.strip()
    if "{" not in tree:
        tree, _, alias = tree.partition(" as ")
        path = prefix + tuple(part.strip() for part in tree.split("::") if part.strip())
        if path and path[-1] == "self":
            path = path[:-1]
        return [(alias.strip() or path[-1], path)] if path else []
    head, rest = tree.split("{", 1)
    prefix = prefix + tuple(part.strip() for part in head.split("::") if part.strip())
    paths, depth, item = [], 0, ""
    for char in rest[: rest.rindex("}")] + ",":
        if char == "," and depth == 0:
            paths.extend(use_paths(item, prefix) if item.strip() else [])
            item = ""
            continue
        depth += {"{": 1, "}": -1}.get(char, 0)
        item += char
    return paths


def file_uses(text: str) -> list[str]:
    """The `use` trees at the top level of a file.

    Those inside a block belong to that block. `use super::*` in a file's
    own test module would otherwise make every bare name in the file
    resolve against the whole directory.
    """
    trees, depth, index = [], 0, 0
    statement = re.compile(r"use\s+([^;]+);")
    while index < len(text):
        found = statement.match(text, index) if depth == 0 and text[index] == "u" else None
        if found and (index == 0 or not (text[index - 1].isalnum() or text[index - 1] == "_")):
            trees.append(found.group(1))
            index = found.end()
            continue
        depth += {"{": 1, "}": -1}.get(text[index], 0)
        index += 1
    return trees


class Crate:
    """The server crate's functions, and which of them each one calls."""

    CALL = re.compile(r"(?<![.\w])((?:\w+::)*)([a-z_][a-z0-9_]*)\s*(?:::<[^>]*>)?\s*\(")

    def __init__(self, sources: dict[pathlib.Path, str]) -> None:
        self.files = {path: strip(text) for path, text in sources.items()}
        # name -> [(file, text)]; one name can be several functions.
        self.defined: dict[str, list[tuple[pathlib.Path, str]]] = {}
        self.imports: dict[pathlib.Path, dict[str, tuple[str, ...]]] = {}
        for path, text in self.files.items():
            for name, body in functions(text):
                self.defined.setdefault(name, []).append((path, body))
            self.imports[path] = dict(pair for statement in file_uses(text) for pair in use_paths(statement))

    @classmethod
    def read(cls) -> Crate:
        return cls({path: path.read_text() for path in sorted(SOURCE.rglob("*.rs"))})

    def module(self, path: pathlib.Path, segments: tuple[str, ...]) -> list[pathlib.Path]:
        """The files a module path names, seen from `path`."""
        names = [segment for segment in segments if segment not in ("crate", "self")]
        if not names:
            return [path]
        if names[-1] == "super":
            return [other for other in self.files if other.parent == path.parent or other.stem == path.parent.name]
        return [
            other
            for other in self.files
            if other.stem == names[-1] or (other.stem == "mod" and other.parent.name == names[-1])
        ]

    def resolve(self, path: pathlib.Path, qualifier: str, name: str) -> list[tuple[pathlib.Path, str]]:
        """The functions a call to `qualifier::name` in `path` can mean.

        By the rules the compiler uses, as far as text allows: a qualified
        call goes to that module, a bare one to this file or to what this
        file imported under the name. A name that is neither is a local, a
        closure or a tuple struct, and resolves to nothing. Resolving it to
        every function of that name in the crate would join unrelated
        handlers and let a row claim a limit its handler never comes near.
        """
        candidates = self.defined.get(name, [])
        imports = self.imports[path]
        parts = tuple(part for part in qualifier.split("::") if part)
        if parts and parts[-1] == "Self":
            where = [path]
        elif parts and parts[-1][0].isupper():
            return []  # `Type::function`: an associated function, not followed
        elif parts:
            where = self.module(path, imports.get(parts[0], parts[:1]) + parts[1:])
        elif any(file == path for file, _ in candidates):
            where = [path]
        elif name in imports:
            where = self.module(path, imports[name][:-1])
        elif "*" in imports:
            where = self.module(path, imports["*"][:-1])
        else:
            return []
        return [candidate for candidate in candidates if candidate[0] in where]

    def reach(self, path: pathlib.Path, handler: str) -> str:
        """The text of `handler` and of every function it calls, to any depth."""
        seen: dict[tuple[pathlib.Path, str], None] = {}
        queue = self.resolve(path, "", handler)
        while queue:
            file, body = queue.pop()
            if (file, body) in seen or file.name in DEFINERS:
                continue
            seen[(file, body)] = None
            for call in self.CALL.finditer(body):
                queue.extend(self.resolve(file, call.group(1), call.group(2)))
        return "\n".join(body for _, body in seen)


def routed_handlers() -> dict[str, tuple[pathlib.Path, str]]:
    """`METHOD path` -> (file, handler) for every route the router serves.

    The dashboard's scan, kept to the handler names it throws away. The
    two are compared below, so this one cannot quietly see a different
    router.
    """
    handlers = {}
    for source_file in dashboard.route_sources():
        source = source_file.read_text()
        prefixes = dashboard._prefixes_in(source)
        index = 0
        while (index := source.find(".route(", index)) >= 0:
            depth, end = 0, index + len(".route(") - 1
            while True:
                depth += {"(": 1, ")": -1}.get(source[end], 0)
                if depth == 0:
                    break
                end += 1
            call = source[index : end + 1]
            index = end
            path = re.search(r'"([^"]+)"', call).group(1)
            paths = [path]
            if "{prefix}" in path and prefixes:
                path = path.replace("{{", "{").replace("}}", "}")
                paths = [path.replace("{prefix}", prefix) for prefix in prefixes]
            for method, handler in re.findall(r"\b(get|post|put|delete|patch)\(\s*(\w+)\s*\)", call):
                for path in paths:
                    handlers[f"{method.upper()} {path}"] = (source_file, handler)
    served = {f"{method} {path}" for path, methods in dashboard.parse_routes() for method in methods}
    if served != set(handlers):
        odd = sorted(served ^ set(handlers))
        sys.exit(
            "limits-ledger: the dashboard and this script read different routers; "
            f"teach `routed_handlers` the registration behind {odd[:5]}"
        )
    return handlers


def defined_limits(crate: Crate) -> set[str]:
    """Every name a row may put under `spends`, as the handler writes it."""
    limiter = crate.files[SOURCE / "ratelimit.rs"]
    config = crate.files[SOURCE / "config.rs"]
    budgets = limiter[limiter.index("pub enum Budget") :]
    budgets = budgets[: budgets.index("}")]
    settings = config[config.index("pub struct RateLimitConfig") :]
    settings = settings[: settings.index("\n}")]
    return (
        set(re.findall(r"\bpub const ([A-Z][A-Z0-9_]*): Limit\b", limiter))
        | {f"Budget::{variant}" for variant in re.findall(r"^\s*([A-Z]\w*),", budgets, re.MULTILINE)}
        # A count in `[ratelimit]` that a handler turns into a `Limit` of
        # its own; the `Rate` fields are spent through `Budget`.
        | set(re.findall(r"\bpub (\w+): u32\b", settings))
    )


def names(text: str, name: str) -> bool:
    return re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text) is not None


def problems_in(ledger: dict, handlers: dict[str, tuple[pathlib.Path, str]], crate: Crate) -> list[str]:
    rows = ledger.get("routes", {})
    reasons = ledger.get("reasons", {})
    limits = defined_limits(crate)
    problems = []

    for route in sorted(set(handlers) - set(rows)):
        file, handler = handlers[route]
        reached = crate.reach(file, handler)
        spent = sorted(limit for limit in limits if names(reached, limit))
        hint = f"it reaches {', '.join(spent)}" if spent else "it reaches no limit"
        problems.append(f"the router serves `{route}` and the ledger has no row for it ({handler}: {hint})")
    for route in sorted(set(rows) - set(handlers)):
        problems.append(f"the ledger has a row for `{route}`, which the router does not serve")

    for route in sorted(set(rows) & set(handlers)):
        row = rows[route]
        file, handler = handlers[route]
        if sorted(row) not in (["none"], ["spends"]):
            problems.append(f"`{route}` must have `spends` or `none`, and only one of them")
            continue
        reached = crate.reach(file, handler)
        if "spends" in row:
            if not row["spends"]:
                problems.append(f"`{route}` spends an empty list; write `none` and a reason")
            for limit in row["spends"]:
                if limit not in limits:
                    problems.append(f"`{route}` spends {limit}, which ratelimit.rs does not define")
                elif not names(reached, limit):
                    problems.append(f"`{route}` spends {limit}, and its handler {handler} does not reach it")
            continue
        reason = reasons.get(row["none"])
        if reason is None:
            problems.append(f"`{route}` gives the reason {row['none']!r}, which `[reasons]` does not define")
        elif "sees" in reason and not any(names(reached, proof) for proof in reason["sees"]):
            problems.append(
                f"`{route}` gives the reason {row['none']!r}, and its handler {handler} "
                f"does not reach {' or '.join(reason['sees'])}"
            )

    used = {row.get("none") for row in rows.values()}
    for name, reason in sorted(reasons.items()):
        if not reason.get("text", "").strip():
            problems.append(f"the reason {name!r} has no `text`")
        if name not in used:
            problems.append(f"no row gives the reason {name!r}; remove it")
    return problems


def check() -> int:
    with LEDGER.open("rb") as handle:
        ledger = tomllib.load(handle)
    handlers = routed_handlers()
    problems = problems_in(ledger, handlers, Crate.read())
    for problem in problems:
        print(f"limits-ledger: {problem}", file=sys.stderr)
    if problems:
        return 1
    limited = sum(1 for row in ledger["routes"].values() if "spends" in row)
    print(f"limits-ledger: {len(handlers)} routes in the ledger, {limited} spend a limit, every row backed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    return check()


if __name__ == "__main__":
    sys.exit(main())
