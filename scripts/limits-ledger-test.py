#!/usr/bin/env python3
"""Tests for `limits-ledger.py`, run in CI as a plain script.

No pytest, for the reason complement-check-test.py gives: plain asserts
and a non-zero exit read the same way in a CI log.

The check is a rule about a call that is missing, so every way it could
come to pass a ledger that is wrong is held here: a route with no row, a
row that outlived its route, a limit the handler never comes near, and a
reason whose proof the handler does not hold. The source reader is held
to the two mistakes that would make those checks meaningless -- joining
handlers through a name they only happen to share, and counting a limit
that is named in a comment or in the file that defines it.

Usage: python3 scripts/limits-ledger-test.py
"""

from __future__ import annotations

import copy
import importlib.util
import pathlib
import sys
import tomllib

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("limits_ledger", HERE / "limits-ledger.py")
ledger = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = ledger
spec.loader.exec_module(ledger)

SOURCE = ledger.SOURCE

# A crate small enough to read: one limited handler that spends through a
# helper in another module, one admin handler, one that asks for nobody.
RATELIMIT = """
pub const LOGIN_PER_SOURCE: Limit = Limit::new(5, Duration::from_secs(60));
pub enum Budget {
    /// A send.
    Message,
    Join,
}
pub(crate) fn limit_write(state: &AppState, class: Budget) -> Result<(), E> {
    let all = [Budget::Message, Budget::Join];
    Ok(())
}
"""
CONFIG = """
pub struct RateLimitConfig {
    pub enabled: bool,
    pub rings_per_minute: u32,
    pub messages: Rate,
}
"""
ROUTES = """
use crate::ratelimit::{Budget, limit_write};
use crate::web;

async fn send(State(state): State<AppState>, Authenticated(who): Authenticated) -> R {
    limit_write(&state, Budget::Message)?;
    Ok(())
}

async fn login(State(state): State<AppState>) -> R {
    web::spend(&state)
}

async fn users(State(state): State<AppState>, _admin: AdminActor) -> R {
    // LOGIN_PER_SOURCE is not spent here, whatever this comment says.
    let label = "Budget::Message";
    Ok(())
}

async fn open(State(state): State<AppState>) -> R {
    let refused = |reason: &str| reason.len();
    refused("no")
}

#[cfg(test)]
mod tests {
    use super::*;
}
"""
WEB = """
use crate::ratelimit::LOGIN_PER_SOURCE;

pub(crate) fn spend(state: &AppState) -> R {
    state.limiter.check("source", LOGIN_PER_SOURCE)
}
"""
# `open` calls a closure named `refused`. This file has a function of that
# name which spends a limit; the two have nothing to do with each other.
OTHER = """
use crate::ratelimit::{Budget, limit_write};

pub(crate) fn refused(state: &AppState) -> R {
    limit_write(state, Budget::Join)
}
"""


def crate() -> object:
    return ledger.Crate(
        {
            SOURCE / "ratelimit.rs": RATELIMIT,
            SOURCE / "config.rs": CONFIG,
            SOURCE / "routes.rs": ROUTES,
            SOURCE / "web.rs": WEB,
            SOURCE / "other.rs": OTHER,
        }
    )


HANDLERS = {
    "PUT /send": (SOURCE / "routes.rs", "send"),
    "POST /login": (SOURCE / "routes.rs", "login"),
    "GET /users": (SOURCE / "routes.rs", "users"),
    "GET /open": (SOURCE / "routes.rs", "open"),
}
GOOD = {
    "reasons": {
        "admin": {"text": "Only a server admin can call it.", "sees": ["AdminActor"]},
        "open": {"text": "It needs no account."},
    },
    "routes": {
        "PUT /send": {"spends": ["Budget::Message"]},
        "POST /login": {"spends": ["LOGIN_PER_SOURCE"]},
        "GET /users": {"none": "admin"},
        "GET /open": {"none": "open"},
    },
}


def problems(change) -> list[str]:
    book = copy.deepcopy(GOOD)
    change(book)
    return ledger.problems_in(book, HANDLERS, crate())


def test_a_ledger_that_matches_the_code_passes() -> None:
    assert problems(lambda book: None) == []


def test_a_route_with_no_row_fails_and_says_what_it_reaches() -> None:
    found = problems(lambda book: book["routes"].pop("POST /login"))
    assert len(found) == 1, found
    assert "`POST /login`" in found[0] and "no row" in found[0]
    # The message does the reading for whoever adds the row.
    assert "it reaches LOGIN_PER_SOURCE" in found[0], found[0]
    found = problems(lambda book: book["routes"].pop("GET /open"))
    assert "it reaches no limit" in found[0], found[0]


def test_a_row_for_a_route_that_is_gone_fails() -> None:
    found = problems(lambda book: book["routes"].update({"GET /gone": {"none": "open"}}))
    assert found == ["the ledger has a row for `GET /gone`, which the router does not serve"], found


def test_a_limit_the_handler_does_not_reach_fails() -> None:
    # The claim that would hide an unlimited route: a real limit, on a
    # handler that never spends it.
    found = problems(lambda book: book["routes"].update({"GET /open": {"spends": ["Budget::Message"]}}))
    assert len(found) == 2 and "does not reach it" in found[0], found
    # ...and `open` no longer being cited is reported with it.
    assert "no row gives the reason 'open'" in found[1], found


def test_a_limit_that_is_not_defined_fails() -> None:
    found = problems(lambda book: book["routes"].update({"PUT /send": {"spends": ["Budget::Missing"]}}))
    assert found == ["`PUT /send` spends Budget::Missing, which ratelimit.rs does not define"], found


def test_a_reason_needs_its_proof() -> None:
    # "Only an admin" of a handler that takes no admin.
    found = problems(lambda book: book["routes"].update({"GET /open": {"none": "admin"}}))
    assert len(found) == 2 and "does not reach AdminActor" in found[0], found
    found = problems(lambda book: book["routes"].update({"GET /open": {"none": "because"}}))
    assert "which `[reasons]` does not define" in found[0], found


def test_a_row_says_one_thing() -> None:
    both = {"spends": ["Budget::Message"], "none": "open"}
    found = problems(lambda book: book["routes"].update({"PUT /send": both}))
    assert found == ["`PUT /send` must have `spends` or `none`, and only one of them"], found
    found = problems(lambda book: book["routes"].update({"PUT /send": {"spends": []}}))
    assert "empty list" in found[0], found


def test_a_reason_nobody_gives_and_one_with_no_text_fail() -> None:
    found = problems(lambda book: book["reasons"].update({"spare": {"text": "Nobody cites it."}}))
    assert found == ["no row gives the reason 'spare'; remove it"], found
    found = problems(lambda book: book["reasons"]["open"].update({"text": " "}))
    assert found == ["the reason 'open' has no `text`"], found


def test_the_limits_are_read_from_the_limiter() -> None:
    assert ledger.defined_limits(crate()) == {
        "LOGIN_PER_SOURCE",
        "Budget::Message",
        "Budget::Join",
        "rings_per_minute",
    }


def test_reach_follows_imports_and_nothing_else() -> None:
    code = crate()
    routes = SOURCE / "routes.rs"
    # Through `use crate::web;` and a qualified call.
    assert "LOGIN_PER_SOURCE" in code.reach(routes, "login")
    # A comment and a string are not a spend.
    users = code.reach(routes, "users")
    assert "LOGIN_PER_SOURCE" not in users and "Budget::Message" not in users, users
    # `refused` is a closure in `open`; other.rs's function of that name
    # is not what it calls. Nor does the test module's `use super::*`
    # make every bare name resolve against the directory.
    assert "Budget::Join" not in code.reach(routes, "open")
    # The limiter's own text names every budget, and is not evidence.
    assert "Budget::Join" not in code.reach(routes, "send")


def test_strip_keeps_code_and_offsets() -> None:
    source = 'fn a<\'x>(s: &\'x str) { let c = \'}\'; let t = r#"}"#; /* } */ b("}") } // }\n'
    stripped = ledger.strip(source)
    assert len(stripped) == len(source)
    assert stripped.count("}") == 1 and stripped.count("{") == 1, stripped
    assert "'x" in stripped, "a lifetime is not a char literal"


def test_a_function_body_starts_after_its_signature() -> None:
    text = ledger.strip(
        """
fn first(State(state): State<AppState>, Path(Ids { room, user }): Path<Ids>) -> Result<(), E>
where
    E: From<Error>,
{
    inner()
}
fn declared(x: u32);
fn second() -> impl Fn(u32) -> u32 { |x| x }
"""
    )
    found = dict(ledger.functions(text))
    assert sorted(found) == ["first", "second"], sorted(found)
    assert "inner()" in found["first"] and "second" not in found["first"]


def test_use_trees() -> None:
    paths = dict(ledger.use_paths("crate::{ratelimit::{self, Budget, limit_write as spend}, web}"))
    assert paths == {
        "ratelimit": ("crate", "ratelimit"),
        "Budget": ("crate", "ratelimit", "Budget"),
        "spend": ("crate", "ratelimit", "limit_write"),
        "web": ("crate", "web"),
    }, paths
    assert ledger.file_uses("use a::b;\nmod tests {\n    use super::*;\n}\nuse c::{d, e};\n") == ["a::b", "c::{d, e}"]


def test_the_repository_passes() -> None:
    assert ledger.check() == 0


def test_the_repository_ledger_is_held_to_the_real_router() -> None:
    # The same three failures, on the real tree: the check is only worth
    # its CI step if the real ledger cannot drift either.
    with ledger.LEDGER.open("rb") as handle:
        real = tomllib.load(handle)
    handlers = ledger.routed_handlers()
    code = ledger.Crate.read()

    def with_change(change) -> list[str]:
        book = copy.deepcopy(real)
        change(book)
        return ledger.problems_in(book, handlers, code)

    login = "POST /_matrix/client/v3/login"
    whoami = "GET /_matrix/client/v3/account/whoami"
    assert real["routes"][login] == {"spends": ["FAILED_LOGIN_PER_ACCOUNT", "FAILED_LOGIN_PER_SOURCE"]}
    found = with_change(lambda book: book["routes"].pop(login))
    assert len(found) == 1 and "FAILED_LOGIN_PER_ACCOUNT, FAILED_LOGIN_PER_SOURCE" in found[0], found
    found = with_change(lambda book: book["routes"].update({whoami: {"spends": ["Budget::Message"]}}))
    assert found == [f"`{whoami}` spends Budget::Message, and its handler whoami does not reach it"], found
    found = with_change(lambda book: book["routes"].update({whoami: {"none": "admin"}}))
    assert found == [f"`{whoami}` gives the reason 'admin', and its handler whoami does not reach AdminActor"], found


def main() -> int:
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
        print(f"ok {test.__name__}")
    print(f"limits-ledger-test: {len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
