//! Pagination and sync tokens.
//!
//! SPEC §10.2 and §10.4 give the two kinds different shapes — `t{li}` for
//! `/messages`, `s{...}` for `/sync` — and that is not decoration. The spec
//! calls tokens opaque to clients, which means a client will store one and
//! hand it back later without inspecting it; the one thing it can get wrong is
//! handing back the *other* one. Bare integers make that mistake invisible,
//! because a stream position and a linear index are both just numbers and each
//! is a plausible value for the other. A one-character tag makes it a 400 with
//! a reason instead of a silently wrong page.
//!
//! They are still opaque: the tag says which endpoint minted the token, not
//! what is inside it.

use std::fmt;

/// A `/messages` token: a position in one room's linear index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pagination(pub i64);

/// A `/sync` token: a position in the server-global stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sync(pub u64);

impl fmt::Display for Pagination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "t{}", self.0)
    }
}

impl fmt::Display for Sync {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "s{}", self.0)
    }
}

/// Why a token could not be read.
#[derive(Debug, Eq, PartialEq)]
pub enum TokenError {
    /// The right shape, but for the other endpoint.
    WrongKind {
        expected: char,
        found: char,
    },
    Malformed,
}

impl fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKind { expected, found } => write!(
                formatter,
                "this endpoint takes a `{expected}` token; that is a `{found}` token from another one"
            ),
            Self::Malformed => write!(formatter, "the token is not one this server issued"),
        }
    }
}

fn parse(text: &str, expected: char) -> Result<&str, TokenError> {
    let mut characters = text.chars();
    match characters.next() {
        Some(tag) if tag == expected => Ok(&text[tag.len_utf8()..]),
        // A tag we do use, on the wrong endpoint: the client kept the right
        // token and sent it to the wrong place, which is worth saying.
        Some(tag @ ('t' | 's')) => Err(TokenError::WrongKind {
            expected,
            found: tag,
        }),
        _ => Err(TokenError::Malformed),
    }
}

impl std::str::FromStr for Pagination {
    type Err = TokenError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse(text, 't')?
            .parse()
            .map(Self)
            .map_err(|_| TokenError::Malformed)
    }
}

impl std::str::FromStr for Sync {
    type Err = TokenError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        parse(text, 's')?
            .parse()
            .map(Self)
            .map_err(|_| TokenError::Malformed)
    }
}
