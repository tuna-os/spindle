//! What a replay pass learns that the next pass does not need to learn again.
//!
//! A room replays in passes until the log's fold settles, and each pass
//! derives every event's state again. The marks that separate one pass from
//! the next only change which events are folded or seeded. They change
//! neither the room version's resolution of a fork nor what Synapse's state
//! groups say, and those are the slow parts: one hard room took about 2.6 h
//! a pass. The cache keeps them for the length of one room, across the
//! passes and the retry at the head.
//!
//! Each entry is keyed by its inputs, never by position or by pass, so a
//! lookup that the inputs do not match is a miss and reads again. The
//! replay still compares the log's fold with the derived state in every
//! pass, so the check that no new mark appears is unchanged.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use spindle_core::StateSnapshot;

use crate::import::{Resolution, StateMap};

type Print = [u8; 32];

/// Results kept for one room.
#[derive(Default)]
pub struct ReplayCache {
    /// Resolver answers, by a print of the full sets they were asked for.
    resolutions: HashMap<Print, Resolution>,
    /// Synapse's state on a few slots, by event and slots.
    keyed: HashMap<(String, Vec<(String, String)>), StateMap>,
    /// A print of Synapse's full state after an event. The map itself is
    /// not kept: a room with tens of thousands of members would hold one
    /// per event.
    sources: HashMap<String, Print>,
    /// Lookups answered from the cache, for tests and the pass log.
    pub hits: u64,
}

impl ReplayCache {
    /// The resolver's answer for `sets`, asking `resolve` only on a miss.
    /// `None` from `resolve` (no resolver) is not kept.
    ///
    /// # Errors
    ///
    /// The error of `resolve`; a failure is not kept.
    pub fn resolution(
        &mut self,
        sets: &[&StateSnapshot],
        resolve: impl FnOnce() -> Option<Result<Resolution, String>>,
    ) -> Option<Result<Resolution, String>> {
        let print = sets_print(sets);
        if let Some(found) = self.resolutions.get(&print) {
            self.hits += 1;
            return Some(Ok(found.clone()));
        }
        let answer = resolve()?;
        if let Ok(resolution) = &answer {
            self.resolutions.insert(print, resolution.clone());
        }
        Some(answer)
    }

    /// Synapse's state after `event_id` on `keys`, reading only on a miss.
    ///
    /// # Errors
    ///
    /// The error of `read`; a failure is not kept.
    pub fn keyed(
        &mut self,
        event_id: &str,
        keys: &[(String, String)],
        read: impl FnOnce() -> Result<StateMap, String>,
    ) -> Result<StateMap, String> {
        let key = (event_id.to_owned(), keys.to_vec());
        if let Some(found) = self.keyed.get(&key) {
            self.hits += 1;
            return Ok(found.clone());
        }
        let state = read()?;
        self.keyed.insert(key, state.clone());
        Ok(state)
    }

    /// Note Synapse's full state after `event_id`, read in this pass.
    pub fn remember_source(&mut self, event_id: &str, map: &StateMap) {
        self.sources.insert(event_id.to_owned(), map_print(map));
    }

    /// Whether an earlier read showed that Synapse's state after `event_id`
    /// is exactly `state`. `false` means unknown or different, and the
    /// caller reads the state.
    pub fn source_matches(&mut self, event_id: &str, state: &StateSnapshot) -> bool {
        let known = self
            .sources
            .get(event_id)
            .is_some_and(|print| *print == state_print(state));
        if known {
            self.hits += 1;
        }
        known
    }
}

fn entry(hasher: &mut Sha256, kind: &str, key: &str, value: &str) {
    for part in [kind, key, value] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
}

/// A print of the entries of `state`, equal to [`map_print`] of the same map.
fn state_print(state: &StateSnapshot) -> Print {
    let mut entries: Vec<(String, String, String)> = Vec::with_capacity(state.len());
    state.for_each(|key, value| {
        entries.push((
            key.event_type().as_str().to_owned(),
            key.state_key().to_owned(),
            value.to_owned(),
        ));
    });
    entries.sort_unstable();
    print_of(
        entries
            .iter()
            .map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str())),
    )
}

fn map_print(map: &StateMap) -> Print {
    print_of(
        map.iter()
            .map(|((kind, key), value)| (kind.as_str(), key.as_str(), value.as_str())),
    )
}

/// `entries` must come in sorted order.
fn print_of<'a>(entries: impl Iterator<Item = (&'a str, &'a str, &'a str)>) -> Print {
    let mut hasher = Sha256::new();
    for (kind, key, value) in entries {
        entry(&mut hasher, kind, key, value);
    }
    hasher.finalize().into()
}

/// A print of every set in order. It reads whole sets, not only the
/// contested slots, because the auth chain of a whole set decides the answer.
fn sets_print(sets: &[&StateSnapshot]) -> Print {
    let mut hasher = Sha256::new();
    for set in sets {
        hasher.update(state_print(set));
    }
    hasher.update((sets.len() as u64).to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use spindle_core::{MemStateKeyTable, StateKey, StateSnapshot};

    use super::*;

    fn snapshot(entries: &[(&str, &str, &str)]) -> StateSnapshot {
        // A new table each time: the print must not depend on key numbering.
        let mut state = StateSnapshot::new(MemStateKeyTable::shared());
        for (kind, key, value) in entries {
            state = state.apply(
                &StateKey::new((*kind).to_owned(), (*key).to_owned()),
                (*value).to_owned(),
            );
        }
        state
    }

    fn resolution(contested: usize) -> Resolution {
        Resolution {
            contested: (0..contested)
                .map(|n| StateKey::new("m.room.member".to_owned(), format!("@u{n}:x")))
                .collect(),
            slots: Vec::new(),
        }
    }

    #[test]
    fn a_second_pass_does_not_ask_the_resolver_again() {
        let one = snapshot(&[("m.room.topic", "", "$a")]);
        let two = snapshot(&[("m.room.topic", "", "$b")]);
        let mut cache = ReplayCache::default();
        let mut asked = 0;
        for _ in 0..3 {
            let answer = cache.resolution(&[&one, &two], || {
                asked += 1;
                Some(Ok(resolution(1)))
            });
            assert_eq!(answer.unwrap().unwrap().contested.len(), 1);
        }
        assert_eq!(asked, 1);
        assert_eq!(cache.hits, 2);
    }

    #[test]
    fn other_sets_or_another_order_are_a_miss() {
        let one = snapshot(&[("m.room.topic", "", "$a")]);
        let two = snapshot(&[("m.room.topic", "", "$b")]);
        let mut cache = ReplayCache::default();
        let mut asked = 0;
        for sets in [[&one, &two], [&two, &one], [&one, &one]] {
            let _ = cache.resolution(&sets, || {
                asked += 1;
                Some(Ok(resolution(0)))
            });
        }
        assert_eq!(asked, 3);
    }

    #[test]
    fn no_resolver_and_failures_are_not_kept() {
        let one = snapshot(&[("m.room.topic", "", "$a")]);
        let mut cache = ReplayCache::default();
        assert!(cache.resolution(&[&one], || None).is_none());
        assert!(
            cache
                .resolution(&[&one], || Some(Err("boom".to_owned())))
                .unwrap()
                .is_err()
        );
        let mut asked = 0;
        let _ = cache.resolution(&[&one], || {
            asked += 1;
            Some(Ok(resolution(0)))
        });
        assert_eq!(asked, 1);
    }

    #[test]
    fn keyed_reads_are_kept_by_event_and_slots() {
        let mut cache = ReplayCache::default();
        let slots = vec![("m.room.topic".to_owned(), String::new())];
        let other = vec![("m.room.name".to_owned(), String::new())];
        let mut reads = 0;
        let mut read = |cache: &mut ReplayCache, event: &str, keys: &[(String, String)]| {
            cache
                .keyed(event, keys, || {
                    reads += 1;
                    Ok(StateMap::new())
                })
                .unwrap();
        };
        read(&mut cache, "$e", &slots);
        read(&mut cache, "$e", &slots);
        read(&mut cache, "$e", &other);
        read(&mut cache, "$f", &slots);
        assert_eq!(reads, 3);
    }

    #[test]
    fn a_source_state_read_once_answers_equal_derivations_only() {
        let derived = snapshot(&[("m.room.topic", "", "$a"), ("m.room.name", "", "$n")]);
        let mut map = StateMap::new();
        map.insert(("m.room.topic".to_owned(), String::new()), "$a".to_owned());
        map.insert(("m.room.name".to_owned(), String::new()), "$n".to_owned());
        let mut cache = ReplayCache::default();
        assert!(!cache.source_matches("$e", &derived), "nothing read yet");
        cache.remember_source("$e", &map);
        assert!(cache.source_matches("$e", &derived));
        // Same slots, in another table: still equal.
        assert!(cache.source_matches(
            "$e",
            &snapshot(&[("m.room.name", "", "$n"), ("m.room.topic", "", "$a")])
        ));
        assert!(!cache.source_matches("$e", &snapshot(&[("m.room.topic", "", "$a")])));
        assert!(!cache.source_matches(
            "$e",
            &snapshot(&[("m.room.topic", "", "$z"), ("m.room.name", "", "$n")])
        ));
        assert!(!cache.source_matches("$other", &derived));
    }
}
