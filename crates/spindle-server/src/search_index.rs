//! The optional word index behind `/search` (`[search] index`, #830).
//!
//! `/search` is case-insensitive containment over `content.body`. The index
//! only has to narrow the events that walk would read, so it answers with a
//! superset of the matches and the caller verifies every candidate with the
//! ordinary predicate. Results are then identical to the scan by
//! construction, and a stale row can cost a read but never a wrong answer.
//!
//! A row is `(room, word, li)`: the lowercase alphanumeric runs of a body.
//! Containment is not word matching, so a query is turned into constraints
//! that hold for any text that contains it. A word fenced in by punctuation
//! or spaces inside the query must be a whole word of the text, and is
//! looked up. The first and last word of a query may be cut at the edge of
//! a text word, so they are found through the room's vocabulary instead.
//! Words too long to index are recorded under the empty word, which is a
//! candidate for every query.

use std::collections::BTreeSet;

use serde_json::Value;
use spindle_core::{
    LinearIndex,
    keys::{self, Keyspace},
};
use spindle_store::{Durability, ReadView, Record, Store, StoreError};

/// Longest word, in characters, that is indexed. A longer one is covered
/// by the empty word's postings.
pub const MAX_WORD_CHARS: usize = 64;

/// The empty word: the events that hold a word too long to index.
const LONG: &str = "";

fn lower_words(lowered: &str) -> impl Iterator<Item = &str> {
    lowered
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
}

/// The body text the scan searches by default, if the event has any.
#[must_use]
pub fn body_of(event: &Value) -> Option<&str> {
    event["content"]["body"].as_str()
}

/// The words an event's body adds to the index.
fn words_of(body: &str) -> BTreeSet<String> {
    let lowered = body.to_lowercase();
    lower_words(&lowered)
        .map(|word| {
            if word.chars().count() > MAX_WORD_CHARS {
                LONG.to_owned()
            } else {
                word.to_owned()
            }
        })
        .collect()
}

/// The rows that index `body` at `li`: one posting and one vocabulary row
/// for each word.
#[must_use]
pub fn rows(room_id: &str, li: LinearIndex, body: &str) -> Vec<Record> {
    let mut out = Vec::new();
    for word in words_of(body) {
        out.push((keys::search_posting(room_id, &word, li), Vec::new()));
        if word != LONG {
            out.push((keys::search_vocab(room_id, &word), Vec::new()));
        }
    }
    out
}

/// Remove the postings of `body` at `li`. The vocabulary stays: a stale
/// word costs one empty scan.
///
/// # Errors
///
/// Returns [`StoreError`] if a delete fails.
pub fn remove<S: Store>(
    store: &S,
    room_id: &str,
    li: LinearIndex,
    body: &str,
) -> Result<(), StoreError> {
    for word in words_of(body) {
        store.delete(&keys::search_posting(room_id, &word, li))?;
    }
    Ok(())
}

/// How far a room is indexed, if it is.
///
/// # Errors
///
/// Returns [`StoreError`] if the read fails.
pub fn marker<S: ReadView>(store: &S, room_id: &str) -> Result<Option<i64>, StoreError> {
    Ok(store
        .get(&keys::search_marker(room_id))?
        .and_then(|bytes| bytes.try_into().ok())
        .map(i64::from_be_bytes))
}

/// The marker row that records `li` as indexed through.
#[must_use]
pub fn marker_row(room_id: &str, li: i64) -> Record {
    (keys::search_marker(room_id), li.to_be_bytes().to_vec())
}

/// The marker an append at `li` leaves. `previous` is the entry before it.
/// The marker moves only from the entry just before, so an entry written
/// while the index was off is never covered by a marker that skips it.
#[must_use]
pub fn next_marker(current: Option<i64>, previous: Option<i64>, li: i64) -> Option<i64> {
    match current {
        Some(marked) => (previous == Some(marked) && li > marked).then_some(li),
        None => previous.is_none().then_some(li),
    }
}

/// One word of a query and whether text must hold it as a whole word.
struct Term {
    word: String,
    whole: bool,
}

fn terms_of(needle: &str) -> Vec<Term> {
    let chars: Vec<char> = needle.chars().collect();
    let mut out = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        if !chars[at].is_alphanumeric() {
            at += 1;
            continue;
        }
        let start = at;
        while at < chars.len() && chars[at].is_alphanumeric() {
            at += 1;
        }
        out.push(Term {
            word: chars[start..at].iter().collect(),
            whole: start > 0 && at < chars.len(),
        });
    }
    out
}

fn postings<S: ReadView>(
    store: &S,
    room_id: &str,
    word: &str,
) -> Result<BTreeSet<i64>, StoreError> {
    let mut out = BTreeSet::new();
    store.visit_prefix(
        &keys::search_posting_prefix(room_id, word),
        &mut |key, _| {
            out.extend(keys::li_from_key(key));
            Ok(())
        },
    )?;
    Ok(out)
}

/// The positions in `room_id` that may hold `needle` (already lowercase),
/// or `None` when the index cannot narrow it: the caller scans.
///
/// # Errors
///
/// Returns [`StoreError`] if a read fails.
pub fn candidates<S: ReadView>(
    store: &S,
    room_id: &str,
    needle: &str,
) -> Result<Option<BTreeSet<i64>>, StoreError> {
    let terms = terms_of(needle);
    let usable = |term: &&Term| term.word.chars().count() <= MAX_WORD_CHARS;
    let whole: Vec<&Term> = terms
        .iter()
        .filter(|term| term.whole)
        .filter(usable)
        .collect();
    let mut found: Option<BTreeSet<i64>> = None;
    if whole.is_empty() {
        let Some(edge) = terms
            .iter()
            .filter(|term| !term.whole)
            .filter(usable)
            .max_by_key(|term| term.word.len())
        else {
            return Ok(None);
        };
        let mut words = Vec::new();
        store.visit_prefix(&keys::search_vocab_prefix(room_id), &mut |key, _| {
            let prefix = keys::search_vocab_prefix(room_id).len();
            if let Some(word) = key
                .get(prefix..)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                && word.contains(edge.word.as_str())
            {
                words.push(word.to_owned());
            }
            Ok(())
        })?;
        let mut union = BTreeSet::new();
        for word in words {
            union.extend(postings(store, room_id, &word)?);
        }
        found = Some(union);
    } else {
        for term in whole {
            let rows = postings(store, room_id, &term.word)?;
            found = Some(match found {
                Some(previous) => previous.intersection(&rows).copied().collect(),
                None => rows,
            });
            if found.as_ref().is_some_and(BTreeSet::is_empty) {
                break;
            }
        }
    }
    let mut found = found.unwrap_or_default();
    found.extend(postings(store, room_id, LONG)?);
    Ok(Some(found))
}

/// What [`reindex`] wrote.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct ReindexReport {
    /// Rooms indexed.
    pub rooms: u64,
    /// Log entries read.
    pub entries: u64,
    /// Index rows written.
    pub rows: u64,
}

/// Rebuild every room's index from its log: clear the old rows, index each
/// body that is still stored and set the marker to the newest entry. Run
/// offline, because a live append would race the clearing.
///
/// # Errors
///
/// Returns [`StoreError`] if a read or a write fails.
pub fn reindex<S: Store>(store: &S) -> Result<ReindexReport, StoreError> {
    let mut rooms = Vec::new();
    store.visit_prefix(&keys::keyspace_prefix(Keyspace::RoomMeta), &mut |key, _| {
        rooms.extend(keys::room_from_prefixed(key).map(str::to_owned));
        Ok(())
    })?;
    let mut report = ReindexReport::default();
    for room in rooms {
        reindex_room(store, &room, &mut report)?;
    }
    Ok(report)
}

fn reindex_room<S: Store>(
    store: &S,
    room: &str,
    report: &mut ReindexReport,
) -> Result<(), StoreError> {
    for keyspace in [Keyspace::SearchPosting, Keyspace::SearchVocab] {
        for (key, _) in store.scan_prefix(&keys::room_prefix(keyspace, room))? {
            store.delete(&key)?;
        }
    }
    store.delete(&keys::search_marker(room))?;
    let Some(restored) = spindle_store::RoomStore::new(store, room).load()? else {
        return Ok(());
    };
    report.rooms += 1;
    let mut batch: Vec<Record> = Vec::new();
    let mut newest = None;
    for entry in restored.log.entries() {
        report.entries += 1;
        newest = Some(newest.map_or(entry.li.get(), |seen: i64| seen.max(entry.li.get())));
        let mut body_key = keys::room_prefix(Keyspace::EventIndex, room);
        body_key.extend_from_slice(entry.event_id.as_str().as_bytes());
        // A purged body is nothing to find.
        let Some(bytes) = store.get(&body_key)? else {
            continue;
        };
        let Ok(event) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if let Some(body) = body_of(&event) {
            batch.extend(rows(room, entry.li, body));
        }
        if batch.len() >= 2000 {
            report.rows += batch.len() as u64;
            store.commit(&std::mem::take(&mut batch), Durability::Relaxed)?;
        }
    }
    if let Some(newest) = newest {
        batch.push(marker_row(room, newest));
    }
    report.rows += batch.len() as u64;
    store.commit(&batch, Durability::Strict)
}
