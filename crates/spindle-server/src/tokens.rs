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

/// Where a client's stored stream token says to resume from.
///
/// A client keeps its `since` (or `pos`, or to-device `since`) across
/// restarts, so the first request after this server takes over from
/// another homeserver carries a token the other server minted:
/// Synapse's `s1600473_59519903_…` or `20489/s1600473_…`. That token is
/// not a client bug and not garbage worth a 400. Answering it with an
/// error leaves the client retrying the same token forever, which is an
/// outage that only signing out ends. It names a position in a stream
/// that no longer exists, and each endpoint has a way to say "start
/// over" (see [`Sync::resume`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resume {
    /// No token: the client is starting from nothing.
    Start,
    /// One of ours.
    From(u64),
    /// Not a token this server minted: another server's, carried across
    /// a migration.
    Foreign,
}

impl Resume {
    /// The stream position to read after, if there is one.
    #[must_use]
    pub const fn position(self) -> Option<u64> {
        match self {
            Self::From(position) => Some(position),
            Self::Start | Self::Foreign => None,
        }
    }
}

impl Sync {
    /// Read an optional stream token for resuming.
    ///
    /// # Errors
    ///
    /// [`TokenError::WrongKind`] for a pagination token sent where a sync
    /// token belongs: that is this server's own token on the wrong
    /// endpoint, a client bug worth naming. [`TokenError::Malformed`] for
    /// anything that is neither ours nor shaped like Synapse's: garbage is
    /// still a 400, and only a token a real predecessor could have minted
    /// is [`Resume::Foreign`].
    pub fn resume(token: Option<&str>) -> Result<Resume, TokenError> {
        let Some(token) = token else {
            return Ok(Resume::Start);
        };
        match token.parse::<Self>() {
            Ok(Self(position)) => Ok(Resume::From(position)),
            Err(TokenError::Malformed) if synapse_shaped(token) => Ok(Resume::Foreign),
            Err(error) => Err(error),
        }
    }
}

/// Where a `/messages` (or `/relations`, `/threads`) token says to page
/// from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageFrom {
    /// One of ours: a gap in this room's linear index.
    Ours(i64),
    /// A position Synapse minted before a migration (#568). Clients keep
    /// these with the gaps in their cached timelines -- Element X's event
    /// cache stores them in `SQLite` -- and send them back after the switch.
    Synapse(SynapsePosition),
}

/// The room-stream part of a Synapse pagination token.
///
/// Synapse orders a room by `(topological_ordering, stream_ordering)`,
/// where the topological ordering is the event's depth and the stream
/// ordering a server-wide counter. A `/messages` or `/context` token is
/// `t{depth}-{stream}`; a `/sync` `prev_batch` is a stream token whose
/// first part is `s{stream}` or `t{depth}-{stream}`, followed by the
/// other streams' positions (`_59480933_…`). With several event writers
/// the room part is `m{stream}~{writer}.{position}~…`, whose first number
/// is the position every writer has passed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SynapsePosition {
    /// The depth, for a topological token.
    pub topological: Option<i64>,
    /// The stream ordering the token sits at.
    pub stream: i64,
}

impl Pagination {
    /// Read a `from`/`to` pagination token, ours or Synapse's.
    ///
    /// # Errors
    ///
    /// [`TokenError::WrongKind`] for one of our sync tokens, and
    /// [`TokenError::Malformed`] for anything that is neither ours nor
    /// shaped like Synapse's.
    pub fn resume(token: &str) -> Result<PageFrom, TokenError> {
        match token.parse::<Self>() {
            Ok(Self(position)) => Ok(PageFrom::Ours(position)),
            Err(error) => synapse_position(token).map(PageFrom::Synapse).ok_or(error),
        }
    }
}

/// The room position in a Synapse pagination or stream token, if `token`
/// is shaped like one. Ours are a tag and digits only (`t17`, `s42`); a
/// Synapse token always has a `-`, `_` or `~` after its first number,
/// which is what tells the two apart.
fn synapse_position(token: &str) -> Option<SynapsePosition> {
    let number = |text: &str| -> Option<i64> {
        let digits = text.strip_prefix('-').unwrap_or(text);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    };
    if !token.contains(['-', '_', '~']) {
        return None;
    }
    let room = token.split('_').next()?;
    let position = match room.as_bytes().first()? {
        b't' => {
            let (depth, stream) = room[1..].split_once('-')?;
            SynapsePosition {
                topological: Some(number(depth)?),
                stream: number(stream.split('~').next()?)?,
            }
        }
        b's' | b'm' => SynapsePosition {
            topological: None,
            stream: number(room[1..].split('~').next()?)?,
        },
        _ => return None,
    };
    Some(position)
}

/// Whether `token` has the shape of a Synapse stream token: a `/sync`
/// `since` (`s1600473_59519903_…`, or `m…~…_…` with several writers), a
/// sliding sync `pos` (the same behind a connection position, `20489/…`),
/// or a to-device `since` (a bare stream ID, `8005`). None of these can be
/// one of ours, which are always `s` followed by digits only.
fn synapse_shaped(token: &str) -> bool {
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    if digits(token) {
        return true;
    }
    let stream = match token.split_once('/') {
        Some((connection, rest)) if digits(connection) => rest,
        Some(_) => return false,
        None => token,
    };
    (stream.starts_with('s') || stream.starts_with('m'))
        && stream.contains('_')
        && stream
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'~' | b'.' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{PageFrom, Pagination, Resume, SynapsePosition, Sync, TokenError};

    #[test]
    fn pagination_reads_our_tokens_and_synapse_positions() {
        assert_eq!(Pagination::resume("t17"), Ok(PageFrom::Ours(17)));
        assert_eq!(Pagination::resume("t-3"), Ok(PageFrom::Ours(-3)));
        let synapse = |topological, stream| {
            Ok(PageFrom::Synapse(SynapsePosition {
                topological,
                stream,
            }))
        };
        // `/messages` and `/context` tokens, and `/sync` `prev_batch`es.
        assert_eq!(
            Pagination::resume("t426-2633508"),
            synapse(Some(426), 2_633_508)
        );
        assert_eq!(
            Pagination::resume(
                "t16750-1590636_59480933_23_1472883_8005_125_9029_4969314_0_165_2_1_1"
            ),
            synapse(Some(16750), 1_590_636)
        );
        assert_eq!(
            Pagination::resume("s1600473_59519903_23_1472883_8005_125_9029_4969314_0_165_2_1_1"),
            synapse(None, 1_600_473)
        );
        assert_eq!(
            Pagination::resume("m1600473~1.1600470~2.1600473_59519903_23_1472883"),
            synapse(None, 1_600_473)
        );
        // Backfilled events have negative stream orderings.
        assert_eq!(Pagination::resume("t12--40"), synapse(Some(12), -40));
        // Ours on the wrong endpoint, and garbage, are still refused.
        assert_eq!(
            Pagination::resume("s42"),
            Err(TokenError::WrongKind {
                expected: 't',
                found: 's'
            })
        );
        for garbage in ["banana", "", "t", "t1-", "t-", "x1_2", "t1-2x_3", "s_1"] {
            assert!(Pagination::resume(garbage).is_err(), "{garbage}");
        }
    }

    #[test]
    fn resume_reads_our_tokens_and_names_foreign_ones() {
        assert_eq!(Sync::resume(None), Ok(Resume::Start));
        assert_eq!(Sync::resume(Some("s42")), Ok(Resume::From(42)));
        // Synapse's /sync, sliding sync and to-device tokens.
        for synapse in [
            "s1600473_59519903_23_1472883_8005_125_9029_4969314_0_165_2_1_1",
            "20489/s1600473_59519903_23_1472883_8005_125_9029_4969314_0_165_2_1_1",
            "8005",
            "m1600473~1.1600470~2.1600473_59519903_23_1472883_8005_125_9029_4969314_0_165_2_1_1",
        ] {
            assert_eq!(
                Sync::resume(Some(synapse)),
                Ok(Resume::Foreign),
                "{synapse}"
            );
        }
        // Garbage is still garbage.
        for garbage in ["banana", "", "s12x", "x/s1_2", "s1_2 3"] {
            assert_eq!(
                Sync::resume(Some(garbage)),
                Err(TokenError::Malformed),
                "{garbage}"
            );
        }
        // Our own pagination token on the sync endpoint is still a 400.
        assert_eq!(
            Sync::resume(Some("t17")),
            Err(TokenError::WrongKind {
                expected: 's',
                found: 't'
            })
        );
        assert_eq!(Resume::Foreign.position(), None);
        assert_eq!(Resume::From(7).position(), Some(7));
    }
}
