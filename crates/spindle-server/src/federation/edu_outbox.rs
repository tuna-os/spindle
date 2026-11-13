//! The outbound EDUs that must arrive (#739).
//!
//! Typing, presence and receipts are claims about the present: one that
//! failed to go is dropped, because whoever is still typing says so again
//! within seconds and a stale one redelivered late is a lie. A to-device
//! message, a device-list update and a cross-signing key update are not
//! like that. The first is an Olm session or a room key a client is
//! waiting on; the other two are how a peer learns which keys to encrypt
//! to, and a peer that missed one has no reason to ask again. Losing them
//! on a refused transaction or a restart is an undecryptable message
//! later, so they get the PDU outbox's contract instead: a row per EDU per
//! destination ([`keys::edu_outbox`]), delivered in the order queued under
//! the destination's ordinary backoff, and deleted only once the
//! destination acknowledged the transaction that carried it.

use std::collections::{BTreeMap, HashMap, hash_map::Entry};
use std::sync::Mutex;

use serde_json::Value;
use spindle_core::keys;
use spindle_store::{FjallStore, ReadView, Store, StoreError};

/// Durable EDUs one transaction carries at most: half the spec's hundred,
/// so typing and receipts riding along always have room, and a fixed
/// number, so a retry over an unchanged queue rebuilds the same batch and
/// with it the same transaction ID.
pub(super) const PER_TRANSACTION: usize = 50;

/// Whether `edu` is one of the classes that must survive a failed
/// transaction and a restart.
pub(super) fn is_durable(edu: &Value) -> bool {
    matches!(
        edu["edu_type"].as_str(),
        Some(
            "m.direct_to_device"
                | "m.device_list_update"
                | "m.signing_key_update"
                | "org.matrix.signing_key_update"
        )
    )
}

/// What makes two queued EDUs the same one, and whether the newer replaces
/// the older (`true`) or is the older queued twice (`false`).
///
/// A to-device message is named by its `message_id`, which is the sender's
/// client transaction: a client retrying `/sendToDevice` must not put a
/// second copy on the wire. A device-list update is named by the change it
/// reports, so a re-announcement of the same change is the same EDU. A
/// cross-signing update carries the user's whole current key set, so a
/// newer one supersedes the waiting one rather than queueing behind it --
/// and goes to the back, so it still lands after whatever preceded it.
pub(super) fn identity(edu: &Value) -> Option<(String, bool)> {
    let content = &edu["content"];
    match edu["edu_type"].as_str()? {
        "m.direct_to_device" => {
            let sender = content["sender"].as_str()?;
            let message_id = content["message_id"].as_str()?;
            Some((format!("t\0{sender}\0{message_id}"), false))
        }
        "m.device_list_update" => {
            let user_id = content["user_id"].as_str()?;
            let device_id = content["device_id"].as_str()?;
            Some((
                format!("d\0{user_id}\0{device_id}\0{}", content["stream_id"]),
                false,
            ))
        }
        "m.signing_key_update" | "org.matrix.signing_key_update" => {
            Some((format!("s\0{}", content["user_id"].as_str()?), true))
        }
        _ => None,
    }
}

/// One destination's queue as this process knows it: the next sequence to
/// write and which identity each waiting row holds.
struct Queue {
    next_seq: u64,
    identities: HashMap<String, u64>,
}

impl Queue {
    /// Read a destination's waiting rows back, the first time this process
    /// queues for it: the next sequence to issue, and the identities still
    /// waiting.
    fn load(store: &FjallStore, destination: &str) -> Result<Self, StoreError> {
        let mut queue = Self {
            next_seq: 0,
            identities: HashMap::new(),
        };
        let mark = keys::edu_outbox_next(destination);
        ReadView::visit_prefix(
            store,
            &keys::edu_outbox_prefix(destination),
            &mut |key, value| {
                if key == mark.as_slice() {
                    let next = value.try_into().map_or(0, u64::from_be_bytes);
                    queue.next_seq = queue.next_seq.max(next);
                    return Ok(());
                }
                let Some((_, seq)) = keys::edu_outbox_parts(key) else {
                    return Ok(());
                };
                queue.next_seq = queue.next_seq.max(seq + 1);
                if let Some((identity, _)) = serde_json::from_slice::<Value>(value)
                    .ok()
                    .as_ref()
                    .and_then(identity)
                {
                    // In key order, so a superseding row left beside the one
                    // it replaced by a crash between the two writes wins.
                    queue.identities.insert(identity, seq);
                }
                Ok(())
            },
        )?;
        Ok(queue)
    }
}

/// The durable EDU queue: rows in the store, and per destination what
/// enqueue needs to deduplicate without a read.
///
/// Every write to the rows goes through `queues`' lock -- enqueue,
/// supersede and acknowledgement -- so the identities can never claim a
/// row an acknowledgement already deleted.
#[derive(Default)]
pub(super) struct EduOutbox {
    queues: Mutex<HashMap<String, Queue>>,
}

/// One durable EDU a transaction carries: its row, and the identity to
/// forget once the row is acknowledged.
pub(super) type Carried = (u64, Option<String>);

impl EduOutbox {
    /// Queue `edu` for `destination`, behind everything already waiting
    /// for it, unless the same EDU is already waiting.
    pub(super) fn push(
        &self,
        store: &FjallStore,
        destination: &str,
        edu: &Value,
    ) -> Result<(), StoreError> {
        let mut queues = self
            .queues
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let queue = match queues.entry(destination.to_owned()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(Queue::load(store, destination)?),
        };
        let identity = identity(edu);
        let replaced = match &identity {
            Some((name, supersedes)) => match queue.identities.get(name) {
                Some(_) if !supersedes => return Ok(()),
                waiting => waiting.copied(),
            },
            None => None,
        };
        let seq = queue.next_seq;
        // The row and the mark in one batch: a sequence the store holds a
        // row under is always below the mark a restart reads back. Journalled
        // without a sync of its own, like the PDU outbox's rows and the local
        // to-device inbox: the next group commit's sync covers it.
        Store::commit_deferred(
            store,
            &[
                (
                    keys::edu_outbox(destination, seq),
                    edu.to_string().into_bytes(),
                ),
                (
                    keys::edu_outbox_next(destination),
                    (seq + 1).to_be_bytes().to_vec(),
                ),
            ],
        )?;
        queue.next_seq += 1;
        if let Some((name, _)) = identity {
            queue.identities.insert(name, seq);
        }
        // The new row first, then the old one gone: a crash between the
        // two sends both, older first, which ends where the newer says.
        if let Some(old) = replaced {
            Store::delete(store, &keys::edu_outbox(destination, old))?;
        }
        Ok(())
    }

    /// The first [`PER_TRANSACTION`] rows waiting for each destination, in
    /// the order they were queued.
    ///
    /// The whole keyspace, every pass, for the reason the PDU outbox scan
    /// gives: it holds only what is undelivered, so an idle server reads an
    /// empty prefix. Rows past a destination's batch are visited but not
    /// copied.
    pub(super) fn waiting(store: &FjallStore) -> BTreeMap<String, Vec<(u64, Value)>> {
        let mut waiting: BTreeMap<String, Vec<(u64, Value)>> = BTreeMap::new();
        let scanned = ReadView::visit_prefix(store, &keys::edu_outbox_all(), &mut |key, value| {
            let Some((destination, seq)) = keys::edu_outbox_parts(key) else {
                return Ok(());
            };
            let rows = waiting.entry(destination).or_default();
            if rows.len() < PER_TRANSACTION
                && let Ok(edu) = serde_json::from_slice(value)
            {
                rows.push((seq, edu));
            }
            Ok(())
        });
        if let Err(error) = scanned {
            tracing::warn!("durable EDU outbox scan: {error}");
        }
        waiting
    }

    /// `destination` acknowledged a transaction carrying `carried`: delete
    /// their rows.
    pub(super) fn acknowledge(&self, store: &FjallStore, destination: &str, carried: &[Carried]) {
        let mut queues = self
            .queues
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut queue = queues.get_mut(destination);
        for (seq, identity) in carried {
            if let Err(error) = Store::delete(store, &keys::edu_outbox(destination, *seq)) {
                // Left in place, the row is sent again: the peer dedups it.
                tracing::warn!("durable EDU outbox delete for {destination}: {error}");
                continue;
            }
            if let (Some(queue), Some(identity)) = (queue.as_deref_mut(), identity)
                && queue.identities.get(identity) == Some(seq)
            {
                queue.identities.remove(identity);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn to_device(message_id: &str) -> Value {
        json!({
            "edu_type": "m.direct_to_device",
            "content": { "sender": "@a:x", "type": "m.room_key", "message_id": message_id, "messages": {} },
        })
    }

    fn signing(master: &str) -> Value {
        json!({
            "edu_type": "m.signing_key_update",
            "content": { "user_id": "@a:x", "master_key": master },
        })
    }

    fn bodies(store: &FjallStore) -> Vec<Value> {
        EduOutbox::waiting(store)
            .remove("peer")
            .unwrap_or_default()
            .into_iter()
            .map(|(_, edu)| edu)
            .collect()
    }

    #[test]
    fn only_the_classes_a_peer_cannot_recover_are_durable() {
        assert!(is_durable(&to_device("m1")));
        assert!(is_durable(&signing("k")));
        assert!(is_durable(&json!({ "edu_type": "m.device_list_update" })));
        for ephemeral in ["m.typing", "m.presence", "m.receipt"] {
            assert!(
                !is_durable(&json!({ "edu_type": ephemeral })),
                "{ephemeral}"
            );
        }
    }

    #[test]
    fn a_to_device_message_queued_twice_waits_once_and_order_is_kept() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let outbox = EduOutbox::default();
        outbox.push(&store, "peer", &to_device("m1")).unwrap();
        outbox.push(&store, "peer", &to_device("m2")).unwrap();
        outbox.push(&store, "peer", &to_device("m1")).unwrap();
        let ids: Vec<_> = bodies(&store)
            .iter()
            .map(|edu| edu["content"]["message_id"].clone())
            .collect();
        assert_eq!(ids, vec![json!("m1"), json!("m2")]);
    }

    #[test]
    fn a_newer_signing_key_update_replaces_the_waiting_one_at_the_back() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let outbox = EduOutbox::default();
        outbox.push(&store, "peer", &signing("old")).unwrap();
        outbox.push(&store, "peer", &to_device("m1")).unwrap();
        outbox.push(&store, "peer", &signing("new")).unwrap();
        let waiting = bodies(&store);
        assert_eq!(waiting.len(), 2, "{waiting:?}");
        assert_eq!(waiting[0]["content"]["message_id"], "m1");
        assert_eq!(waiting[1]["content"]["master_key"], "new");
    }

    #[test]
    fn a_fresh_queue_over_old_rows_continues_their_order_and_their_dedup() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        EduOutbox::default()
            .push(&store, "peer", &to_device("m1"))
            .unwrap();
        // A restart: nothing in memory, the rows in the store.
        let outbox = EduOutbox::default();
        outbox.push(&store, "peer", &to_device("m1")).unwrap();
        outbox.push(&store, "peer", &to_device("m2")).unwrap();
        let waiting = EduOutbox::waiting(&store).remove("peer").unwrap();
        let ids: Vec<_> = waiting
            .iter()
            .map(|(_, edu)| edu["content"]["message_id"].clone())
            .collect();
        assert_eq!(ids, vec![json!("m1"), json!("m2")]);

        // Acknowledged rows are gone, and the name is free again.
        let carried: Vec<Carried> = waiting
            .iter()
            .map(|(seq, edu)| (*seq, identity(edu).map(|(name, _)| name)))
            .collect();
        outbox.acknowledge(&store, "peer", &carried);
        assert!(bodies(&store).is_empty());
        outbox.push(&store, "peer", &to_device("m1")).unwrap();
        assert_eq!(bodies(&store).len(), 1);
    }

    #[test]
    fn a_drained_queue_never_issues_a_sequence_twice_across_a_restart() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FjallStore::open(dir.path()).unwrap();
        let outbox = EduOutbox::default();
        outbox.push(&store, "peer", &to_device("m1")).unwrap();
        let first = EduOutbox::waiting(&store).remove("peer").unwrap();
        let carried: Vec<Carried> = first.iter().map(|(seq, _)| (*seq, None)).collect();
        outbox.acknowledge(&store, "peer", &carried);
        // Nothing waits, and a fresh process queues the next one: its
        // sequence -- and so the transaction ID built from it -- must not
        // be the drained one's, or the peer takes it for a replay.
        EduOutbox::default()
            .push(&store, "peer", &to_device("m2"))
            .unwrap();
        let second = EduOutbox::waiting(&store).remove("peer").unwrap();
        assert!(second[0].0 > first[0].0, "{second:?} after {first:?}");
    }
}
