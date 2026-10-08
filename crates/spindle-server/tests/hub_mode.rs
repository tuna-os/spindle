//! MSC3995 linearized hub mode between Spindles: the first slice (#22).
//!
//! Built only with `--features hub-mode`; `hub_mode_disabled.rs` is its
//! counterpart for the default build. Every test here runs real servers on
//! loopback, each behind a proxy that can cut it off (`support/hub_rig.rs`).
//!
//! What is under test, from SPEC section 12.6:
//!
//! - the capability probe and the routes exist only with the switch on;
//! - a participant's events are placed by the room's hub, so two servers
//!   sending at once still produce one chain, in the same order on both,
//!   with the hub's signed attestation for every entry;
//! - a server that does not speak hub mode, in the same room, receives only
//!   ordinary events and nothing namespaced, and the room converges;
//! - a participant cut off from its hub keeps sending, ordinarily, and the
//!   room heals once the partition does;
//! - a hub that signs two different things for one position is caught,
//!   with a proof anyone holding its key can check;
//! - a planned handoff moves the hub and opens the next epoch, co-signed by
//!   the outgoing hub;
//! - when the hub is unreachable its first backup claims the next epoch,
//!   starting from the highest entry anyone in the room holds an
//!   attestation for -- and a claim that drops an attested entry is refused
//!   with a proof;
//! - a participant with no history anchors on a signed checkpoint;
//! - the counters reach `/metrics`.

#![cfg(feature = "hub-mode")]

#[path = "support/hub_rig.rs"]
mod hub_rig;

use hub_rig::{Node, eventually};
use serde_json::{Value, json};

/// A room hubbed by `hub`, with `alice` (on `hub`) and one user per other
/// node joined: `(room, alice's token, the joiners' tokens)`.
async fn hub_room(hub: &Node, others: &[&Node]) -> (String, String, Vec<String>) {
    hub_room_with(hub, others, &json!({})).await
}

/// [`hub_room`], with the first `m.room.hub`'s content given.
async fn hub_room_with(
    hub: &Node,
    others: &[&Node],
    genesis: &Value,
) -> (String, String, Vec<String>) {
    let (alice, _) = hub.register("alice").await;
    let room = hub.create_room(&alice).await;
    hub.designate_hub_with(&alice, &room, genesis).await;
    let mut tokens = Vec::new();
    for (index, node) in others.iter().enumerate() {
        let (token, user) = node.register(&format!("user{index}")).await;
        node.join(&token, &room, hub).await;
        // The join reaches every server already in the room before anyone
        // relies on it there.
        for server in std::iter::once(hub).chain(others[..=index].iter().copied()) {
            assert!(
                eventually(10, async || {
                    server
                        .state
                        .rooms
                        .joined_member_ids(&room)
                        .is_ok_and(|members| members.contains(&user))
                })
                .await,
                "{user}'s join reaches {}",
                server.name
            );
        }
        tokens.push(token);
    }
    // Every server reads the same hub off the room's state.
    for server in std::iter::once(hub).chain(others.iter().copied()) {
        assert_eq!(
            hub_of(server, &room).await,
            Some(hub.name.clone()),
            "{} sees the hub",
            server.name
        );
    }
    (room, alice, tokens)
}

/// The hub `node` reads off the room, if it trusts one.
async fn hub_of(node: &Node, room: &str) -> Option<String> {
    spindle_server::hub::designation(&node.state, room)
        .await
        .map(|hub| hub.server)
}

/// Every event in `ids` has exactly one parent at `node`: a chain.
fn single_parent(node: &Node, room: &str, ids: &[String]) -> bool {
    ids.iter().all(|id| {
        node.pdu(room, id)["prev_events"]
            .as_array()
            .is_some_and(|parents| parents.len() == 1)
    })
}

/// The event IDs `node` holds attestations for in `room`.
fn attested(node: &Node, room: &str) -> Vec<String> {
    spindle_server::hub::attestations(&node.store, room)
        .iter()
        .filter_map(|attestation| attestation["event_id"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn the_hub_surface_exists_only_with_the_switch_on() {
    let on = Node::start(true).await;
    let off = Node::start(false).await;
    let path = "/_matrix/federation/unstable/org.spindle.msc3995/capabilities";

    let (status, body) = on.request(reqwest::Method::GET, path, None, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["org.spindle.msc3995"]["hub"], json!(true), "{body}");

    // Same binary, switch off: the path is one the server does not speak.
    let (status, body) = off.request(reqwest::Method::GET, path, None, None).await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["errcode"], "M_UNRECOGNIZED", "{body}");
    let (status, body) = off
        .request(
            reqwest::Method::POST,
            "/_matrix/federation/unstable/org.spindle.msc3995/submit/!r:x",
            None,
            Some(&json!({})),
        )
        .await;
    assert_eq!(status, 404, "{body}");
}

#[tokio::test]
async fn two_spindles_sending_at_once_get_one_chain_in_the_hubs_order() {
    let hub = Node::start(true).await;
    let participant = Node::start(true).await;
    let (room, alice, tokens) = hub_room(&hub, &[&participant]).await;
    let bob = &tokens[0];

    // Both servers send at once, interleaved, messages and state alike.
    // Without a hub, concurrent sends from two servers fork the DAG
    // whenever one lands before the other's arrives.
    let from_hub = async {
        let mut ids = Vec::new();
        for n in 0..6 {
            ids.push(hub.say(&alice, &room, &format!("hub {n}")).await);
        }
        ids
    };
    let from_participant = async {
        let mut ids = Vec::new();
        for n in 0..6 {
            if n == 3 {
                ids.push(participant.set_topic(bob, &room, "set via the hub").await);
            } else {
                ids.push(
                    participant
                        .say(bob, &room, &format!("participant {n}"))
                        .await,
                );
            }
        }
        ids
    };
    let (hub_ids, participant_ids) = tokio::join!(from_hub, from_participant);
    let all: Vec<String> = hub_ids.iter().chain(&participant_ids).cloned().collect();

    assert!(
        eventually(15, async || all
            .iter()
            .all(|id| hub.holds(&room, id) && participant.holds(&room, id)))
        .await,
        "every event reaches both servers"
    );

    // The hub placed every one of the participant's events; none needed the
    // ordinary fallback.
    let counts = participant.state.metrics.hub().counts();
    assert_eq!(counts.submitted, 6, "{counts:?}");
    assert_eq!(counts.fallbacks, 0, "{counts:?}");
    assert!(hub.state.metrics.hub().counts().sequenced >= 6);

    // One chain: every event names exactly one parent, on both servers,
    // and neither server is left with a fork.
    assert!(single_parent(&hub, &room, &all), "the hub's log is a chain");
    assert!(single_parent(&participant, &room, &all));
    for node in [&hub, &participant] {
        assert_eq!(
            node.state.rooms.forward_extremity_count(&room).unwrap(),
            1,
            "{} has one head",
            node.name
        );
    }

    // In the same order on both.
    let at_hub = hub.messages(&alice, &room).await;
    let at_participant = participant.messages(bob, &room).await;
    assert_eq!(at_hub, at_participant, "both servers show one order");
    assert_eq!(
        hub.state_ids(&alice, &room).await,
        participant.state_ids(bob, &room).await
    );

    // The hub attested every entry it ordered -- its own users' events and
    // the participant's alike -- and the attestations chain.
    assert!(
        eventually(10, async || {
            let held = attested(&participant, &room);
            all.iter().all(|id| held.contains(id))
        })
        .await,
        "the participant holds an attestation for every event: {:?}",
        attested(&participant, &room)
    );
    let counts = participant.state.metrics.hub().counts();
    assert_eq!(counts.equivocations, 0, "{counts:?}");
    assert_eq!(counts.attestations_rejected, 0, "{counts:?}");
    assert!(spindle_server::hub::proofs(&participant.store, &room).is_empty());
    // And the counters reach the scrape, under fixed labels only.
    let scrape = participant.state.metrics.render();
    assert!(
        scrape.contains("spindle_hub_submissions_total{result=\"placed\"} 6"),
        "{scrape}"
    );
    let scrape = hub.state.metrics.render();
    assert!(scrape.contains("spindle_hub_sequenced_total{result=\"appended\"}"));
    assert!(!scrape.contains(&room), "no room ever becomes a label");
    let attestations = spindle_server::hub::attestations(&participant.store, &room);
    for pair in attestations.windows(2) {
        if pair[1]["li"].as_i64() == pair[0]["li"].as_i64().map(|li| li + 1) {
            assert_eq!(pair[0]["hub"], json!(hub.name));
        }
    }
}

#[tokio::test]
async fn a_server_that_does_not_speak_hub_mode_sees_an_ordinary_room_that_converges() {
    let hub = Node::start(true).await;
    let participant = Node::start(true).await;
    // The stand-in for Synapse: a server with hub mode off. Its own events
    // name its own head, so with three servers sending at once the DAG
    // forks; that is the class-D room SPEC section 12.3 describes.
    let ordinary = Node::start(false).await;
    let (room, alice, tokens) = hub_room(&hub, &[&participant, &ordinary]).await;
    let (bob, carol) = (&tokens[0], &tokens[1]);

    let sends = async {
        let mut ids = Vec::new();
        for n in 0..4 {
            ids.push(hub.say(&alice, &room, &format!("hub {n}")).await);
        }
        ids
    };
    let submits = async {
        let mut ids = Vec::new();
        for n in 0..4 {
            ids.push(
                participant
                    .say(bob, &room, &format!("participant {n}"))
                    .await,
            );
        }
        ids
    };
    let ordinary_sends = async {
        let mut ids = Vec::new();
        for n in 0..4 {
            ids.push(ordinary.say(carol, &room, &format!("ordinary {n}")).await);
        }
        ids
    };
    let (a, b, c) = tokio::join!(sends, submits, ordinary_sends);
    let mut all: Vec<String> = a.into_iter().chain(b).chain(c).collect();
    // One more event from each hub-mode server merges whatever forked.
    all.push(hub.say(&alice, &room, "merge").await);

    let nodes = [&hub, &participant, &ordinary];
    assert!(
        eventually(20, async || {
            all.iter()
                .all(|id| nodes.iter().all(|node| node.holds(&room, id)))
        })
        .await,
        "every event reaches every server"
    );
    // Converged: the same current state everywhere, and the same events.
    assert!(
        eventually(20, async || {
            let hub_state = hub.state_ids(&alice, &room).await;
            hub_state == participant.state_ids(bob, &room).await
                && hub_state == ordinary.state_ids(carol, &room).await
        })
        .await,
        "the three servers agree on the room's state"
    );
    let mut seen: Vec<Vec<String>> = Vec::new();
    for (node, token) in [(&hub, &alice), (&participant, bob), (&ordinary, carol)] {
        let mut ids = node.messages(token, &room).await;
        ids.sort();
        seen.push(ids);
    }
    assert_eq!(seen[0], seen[1]);
    assert_eq!(seen[0], seen[2]);

    // The participant still went through the hub; forks from the ordinary
    // server only made it catch up first.
    let counts = participant.state.metrics.hub().counts();
    assert_eq!(counts.submitted, 4, "{counts:?}");
    assert_eq!(counts.fallbacks, 0, "{counts:?}");

    // Nothing hub-shaped reached the ordinary server: every event it holds
    // is an ordinary PDU with no Spindle or MSC3995 field, and it was sent
    // no hub EDU at all (the hub's probe found it does not speak hub mode).
    for id in &all {
        let pdu = ordinary.pdu(&room, id).to_string();
        assert!(
            !pdu.contains("org.spindle") && !pdu.contains("hub_server"),
            "{pdu}"
        );
    }
    let other_edus: u64 = spindle_server::metrics::EduResult::ALL
        .iter()
        .map(|result| {
            ordinary
                .state
                .metrics
                .edu_received_count(spindle_server::metrics::EduType::Other, *result)
        })
        .sum();
    assert_eq!(other_edus, 0, "the ordinary server was sent no hub EDU");
}

#[tokio::test]
async fn a_participant_cut_off_from_its_hub_keeps_sending_and_the_room_heals() {
    let hub = Node::start(true).await;
    let participant = Node::start(true).await;
    let (room, alice, tokens) = hub_room(&hub, &[&participant]).await;
    let bob = &tokens[0];

    let before = participant.say(bob, &room, "before").await;
    assert_eq!(participant.state.metrics.hub().counts().submitted, 1);

    // Partition. The participant's send is not refused and does not hang:
    // the hub cannot place it, so it goes out the ordinary way and waits in
    // the outbox. The hub keeps serving its own users meanwhile.
    hub.partition(true);
    participant.partition(true);
    let during = participant.say(bob, &room, "during").await;
    let concurrent = hub.say(&alice, &room, "concurrent").await;
    let counts = participant.state.metrics.hub().counts();
    assert_eq!(counts.fallbacks, 1, "{counts:?}");
    assert!(!hub.holds(&room, &during), "the partition holds");
    assert!(!participant.holds(&room, &concurrent));

    // Heal: both sides' outboxes deliver, and the fork the partition made
    // is merged by the hub's next event.
    hub.partition(false);
    participant.partition(false);
    assert!(
        eventually(20, async || hub.holds(&room, &during)
            && participant.holds(&room, &concurrent))
        .await,
        "the partition's events cross once it heals"
    );
    let merge = hub.say(&alice, &room, "merge").await;
    let parents: Vec<String> = hub.pdu(&room, &merge)["prev_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect();
    assert!(
        parents.contains(&during) && parents.contains(&concurrent),
        "the hub's next event merges both sides: {parents:?}"
    );

    // And the hub orders the participant's events again.
    assert!(
        eventually(10, async || participant.holds(&room, &merge)).await,
        "the merge reaches the participant"
    );
    let after = participant.say(bob, &room, "after").await;
    let counts = participant.state.metrics.hub().counts();
    assert_eq!(counts.submitted, 2, "{counts:?}");
    assert_eq!(counts.fallbacks, 1, "{counts:?}");
    assert_eq!(
        participant.pdu(&room, &after)["prev_events"],
        json!([merge]),
        "the participant's next event extends the hub's head"
    );
    assert!(
        eventually(10, async || hub.holds(&room, &after)).await,
        "it is at the hub"
    );
    for id in [&before, &during, &concurrent, &merge, &after] {
        assert!(hub.holds(&room, id) && participant.holds(&room, id));
    }
    // The partition's two events are in arrival order on each side -- that
    // is what a fork is -- but everything from the merge on is one order.
    let (at_hub, at_participant) = (
        hub.messages(&alice, &room).await,
        participant.messages(bob, &room).await,
    );
    let mut sorted = (at_hub.clone(), at_participant.clone());
    sorted.0.sort();
    sorted.1.sort();
    assert_eq!(sorted.0, sorted.1, "the same messages on both");
    assert_eq!(
        at_hub[at_hub.len() - 2..],
        at_participant[at_participant.len() - 2..],
        "one order from the merge on"
    );
    assert_eq!(
        hub.state_ids(&alice, &room).await,
        participant.state_ids(bob, &room).await
    );
}

#[tokio::test]
async fn a_hub_that_signs_two_entries_for_one_position_is_caught_with_a_portable_proof() {
    let hub = Node::start(true).await;
    let participant = Node::start(true).await;
    let (room, _alice, tokens) = hub_room(&hub, &[&participant]).await;
    let bob = &tokens[0];
    let event = participant.say(bob, &room, "attested").await;

    let held = spindle_server::hub::attestations(&participant.store, &room);
    let honest = held
        .iter()
        .find(|attestation| attestation["event_id"] == json!(event))
        .cloned()
        .expect("the hub's answer carried an attestation");

    // The hub now claims a different event at the same position, signed
    // with its real key.
    let mut lie = honest.clone();
    lie.as_object_mut().unwrap().remove("signatures");
    lie["event_id"] = json!("$not-what-the-hub-said-before");
    let ruma::CanonicalJsonValue::Object(mut lie) =
        ruma::CanonicalJsonValue::try_from(lie).unwrap()
    else {
        unreachable!()
    };
    ruma::signatures::sign_json(&hub.name, hub.state.key.pair(), &mut lie).unwrap();
    let lie = serde_json::to_value(&lie).unwrap();
    let uri = "/_matrix/federation/v1/send/equivocate";
    let body = json!({
        "origin": hub.name,
        "origin_server_ts": 0,
        "pdus": [],
        "edus": [{
            "edu_type": "org.spindle.msc3995.attestations",
            "content": { "room_id": room, "attestations": [lie] },
        }],
    });
    let (status, answer) = hub.federation_put(&participant, uri, &body).await;
    assert_eq!(status, 200, "{answer}");

    let proofs = spindle_server::hub::proofs(&participant.store, &room);
    assert_eq!(proofs.len(), 1, "{proofs:?}");
    let proof = &proofs[0];
    assert_eq!(proof["kind"], "org.spindle.msc3995.equivocation");
    assert_eq!(proof["reason"], "conflicting_entries");
    assert_eq!(participant.state.metrics.hub().counts().equivocations, 1);
    // The first answer is what the participant keeps.
    let kept = spindle_server::hub::attestations(&participant.store, &room);
    assert!(kept.iter().any(|attestation| attestation == &honest));

    // Portable: both halves verify against nothing but the hub's public
    // key, and they name different events at one position.
    let mut keys = ruma::signatures::PublicKeyMap::new();
    keys.entry(hub.name.clone()).or_default().insert(
        hub.state.key.key_id(),
        ruma::serde::Base64::new(hub.state.key.pair().public_key().to_vec()),
    );
    let pair: Vec<Value> = proof["attestations"].as_array().unwrap().clone();
    assert_eq!(pair.len(), 2);
    for half in &pair {
        let ruma::CanonicalJsonValue::Object(object) =
            ruma::CanonicalJsonValue::try_from(half.clone()).unwrap()
        else {
            unreachable!()
        };
        ruma::signatures::verify_json(&keys, &object).expect("signed by the hub");
    }
    assert_eq!(pair[0]["li"], pair[1]["li"]);
    assert_ne!(pair[0]["event_id"], pair[1]["event_id"]);
}

/// The counters of `node`, now.
fn counts(node: &Node) -> spindle_server::hub::HubCounts {
    node.state.metrics.hub().counts()
}

/// The highest attestation `node` holds for `epoch` of `room`.
fn highest_attestation(node: &Node, room: &str, epoch: u64) -> Option<Value> {
    spindle_server::hub::attestations(&node.store, room)
        .into_iter()
        .filter(|attestation| attestation["epoch"] == json!(epoch))
        .max_by_key(|attestation| attestation["li"].as_i64())
}

/// Whether `node` holds an attestation of `epoch`, by `hub`, for `event`.
fn has_attestation(node: &Node, room: &str, epoch: u64, hub: &Node, event: &str) -> bool {
    spindle_server::hub::attestations(&node.store, room)
        .iter()
        .any(|attestation| {
            attestation["epoch"] == json!(epoch)
                && attestation["hub"] == json!(hub.name)
                && attestation["event_id"] == json!(event)
        })
}

/// `hub`'s public key, as a key map a proof is checked against.
fn key_map(node: &Node) -> ruma::signatures::PublicKeyMap {
    let mut keys = ruma::signatures::PublicKeyMap::new();
    keys.entry(node.name.clone()).or_default().insert(
        node.state.key.key_id(),
        ruma::serde::Base64::new(node.state.key.pair().public_key().to_vec()),
    );
    keys
}

fn signed_by(node: &Node, value: &Value) -> bool {
    let ruma::CanonicalJsonValue::Object(object) =
        ruma::CanonicalJsonValue::try_from(value.clone()).unwrap()
    else {
        return false;
    };
    ruma::signatures::verify_json(&key_map(node), &object).is_ok()
}

#[tokio::test]
async fn a_planned_handoff_moves_the_hub_and_opens_the_next_epoch() {
    let first = Node::start(true).await;
    let second = Node::start(true).await;
    let third = Node::start(true).await;
    let (room, alice, tokens) = hub_room(&first, &[&second, &third]).await;
    let (bob, carol) = (&tokens[0], &tokens[1]);
    let before = third.say(carol, &room, "epoch 0").await;
    first.say(&alice, &room, "from the first hub").await;

    // Bob moves the hub to his own server. The first hub co-signs.
    let handoff = second
        .designate_hub_with(bob, &room, &json!({ "org.spindle.backups": [third.name] }))
        .await;
    for node in [&first, &second, &third] {
        assert!(
            eventually(10, async || hub_of(node, &room).await
                == Some(second.name.clone()))
            .await,
            "{} follows the handoff: {:?} {}, proofs {:?}, {:?}",
            node.name,
            spindle_server::hub::designation_explained(&node.state, &room).await,
            node.state
                .rooms
                .hub_event(&room)
                .unwrap()
                .unwrap_or_default(),
            spindle_server::hub::proofs(&node.store, &room),
            counts(node)
        );
    }
    let pdu = second.pdu(&room, &handoff);
    let content = &pdu["content"];
    assert_eq!(content["org.spindle.epoch"], json!(1), "{pdu}");
    assert!(content["org.spindle.prev_hub_event"].is_string(), "{pdu}");
    assert!(
        content["org.spindle.prev_epoch_final"]["li"].is_i64(),
        "{pdu}"
    );
    assert!(
        pdu["signatures"][&first.name].is_object() && pdu["signatures"][&second.name].is_object(),
        "both hubs signed the handoff: {pdu}"
    );
    assert_eq!(counts(&first).handoffs_cosigned, 1);
    assert_eq!(counts(&second).handoffs_completed, 1);

    // The new hub orders everyone, the old hub included, in epoch 1.
    let placed_before = counts(&third).submitted;
    let from_third = third.say(carol, &room, "epoch 1 from the third").await;
    let from_first = first.say(&alice, &room, "epoch 1 from the first").await;
    assert_eq!(counts(&third).submitted, placed_before + 1);
    assert_eq!(
        counts(&first).submitted,
        1,
        "the old hub is a participant now"
    );
    assert!(counts(&second).sequenced >= 2);
    assert!(
        eventually(10, async || {
            has_attestation(&third, &room, 1, &second, &from_third)
                && has_attestation(&third, &room, 1, &second, &from_first)
                && has_attestation(&third, &room, 0, &first, &before)
        })
        .await,
        "epoch 0 attested by the first hub, epoch 1 by the second: {:?}",
        spindle_server::hub::attestations(&third.store, &room)
    );
    assert!(spindle_server::hub::proofs(&third.store, &room).is_empty());
    assert_eq!(counts(&third).equivocations, 0);
}

/// A room hubbed by `hub` with `backup` as its first backup, `others`
/// joined, and `backup` and every other server warm: each has sent once
/// through the hub, so each knows it speaks hub mode.
async fn backed_up_room(
    hub: &Node,
    backup: &Node,
    others: &[&Node],
) -> (String, String, Vec<String>) {
    let mut joiners = vec![backup];
    joiners.extend_from_slice(others);
    let (room, alice, tokens) = hub_room_with(
        hub,
        &joiners,
        &json!({ "org.spindle.backups": [backup.name] }),
    )
    .await;
    for (node, token) in joiners.iter().zip(&tokens) {
        node.say(token, &room, "warm").await;
    }
    (room, alice, tokens)
}

#[tokio::test]
async fn when_the_hub_is_unreachable_its_backup_takes_over_from_the_highest_attested_entry() {
    let hub = Node::start(true).await;
    let backup = Node::start(true).await;
    let other = Node::start(true).await;
    let (room, alice, tokens) = backed_up_room(&hub, &backup, &[&other]).await;
    let (bob, carol) = (&tokens[0], &tokens[1]);

    // The backup misses the hub's last entry; the other participant holds
    // its attestation.
    backup.partition(true);
    let last = hub.say(&alice, &room, "attested to one participant").await;
    assert!(
        eventually(10, async || has_attestation(&other, &room, 0, &hub, &last)).await,
        "the other participant holds the last attestation"
    );
    assert!(!backup.holds(&room, &last));

    // The hub goes away. The backup's sends fall back; once the hub has
    // been silent for failover_after_ms, the next one claims epoch 1.
    hub.partition(true);
    backup.partition(false);
    backup.say(bob, &room, "the hub is gone").await;
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    backup.say(bob, &room, "still gone").await;
    assert_eq!(counts(&backup).failovers, 1, "{:?}", counts(&backup));
    for node in [&backup, &other] {
        assert!(
            eventually(10, async || hub_of(node, &room).await
                == Some(backup.name.clone()))
            .await,
            "{} accepts the new hub",
            node.name
        );
    }

    // The claim starts from the entry only the other participant held,
    // fetched from it first: nothing attested was dropped.
    let claim = backup.state.rooms.hub_event(&room).unwrap().unwrap();
    assert_eq!(claim["content"]["org.spindle.failover"], json!(true));
    assert_eq!(
        claim["content"]["org.spindle.prev_epoch_final"]["event_id"],
        json!(last),
        "{claim}"
    );
    assert!(backup.holds(&room, &last));
    assert!(spindle_server::hub::proofs(&other.store, &room).is_empty());

    // The other participant's sends go through the new hub.
    let placed = counts(&other).submitted;
    other.say(carol, &room, "through the new hub").await;
    assert_eq!(counts(&other).submitted, placed + 1);

    // The old hub returns and agrees: it attested nothing past the final.
    hub.partition(false);
    assert!(
        eventually(20, async || hub_of(&hub, &room).await
            == Some(backup.name.clone()))
        .await,
        "the old hub accepts the epoch it lost"
    );
    hub.say(&alice, &room, "the old hub, as a participant")
        .await;
    assert_eq!(counts(&hub).submitted, 1);
    assert!(spindle_server::hub::proofs(&hub.store, &room).is_empty());
}

#[tokio::test]
async fn a_new_hub_that_drops_an_attested_entry_is_refused_with_a_portable_proof() {
    let hub = Node::start(true).await;
    let backup = Node::start(true).await;
    let other = Node::start(true).await;
    let (room, alice, tokens) = backed_up_room(&hub, &backup, &[&other]).await;
    let (bob, carol) = (&tokens[0], &tokens[1]);

    backup.partition(true);
    let last = hub.say(&alice, &room, "attested to one participant").await;
    assert!(
        eventually(10, async || has_attestation(&other, &room, 0, &hub, &last)).await,
        "the other participant holds the last attestation"
    );
    hub.partition(true);
    backup.partition(false);

    // The backup claims epoch 1 from what it alone heard, ignoring the
    // other participant: the entry before `last`.
    let own = highest_attestation(&backup, &room, 0).expect("the backup heard the hub");
    let genesis = spindle_server::hub::designation(&backup.state, &room)
        .await
        .unwrap()
        .event_id;
    let claim = backup
        .designate_hub_with(
            bob,
            &room,
            &json!({
                "org.spindle.epoch": 1,
                "org.spindle.prev_hub_event": genesis,
                "org.spindle.failover": true,
                "org.spindle.prev_epoch_final": {
                    "li": own["li"], "event_id": own["event_id"], "chain": own["chain"],
                },
                "org.spindle.backups": [hub.name],
            }),
        )
        .await;
    assert!(
        eventually(10, async || other.holds(&room, &claim)).await,
        "the claim reaches the other participant"
    );

    // The claimant believes itself; the participant that holds the dropped
    // attestation does not, and keeps the proof.
    assert_eq!(hub_of(&backup, &room).await, Some(backup.name.clone()));
    assert_eq!(
        hub_of(&other, &room).await,
        None,
        "the room is ordinary here now"
    );
    assert_eq!(counts(&other).truncations, 1);
    let proofs = spindle_server::hub::proofs(&other.store, &room);
    assert_eq!(proofs.len(), 1, "{proofs:?}");
    let proof = &proofs[0];
    assert_eq!(proof["kind"], "org.spindle.msc3995.truncation");

    // Portable: the attestation is the old hub's, by its key alone; the
    // claim is the new hub's own event, by its key alone; and the claim's
    // final position is below the attested one.
    let attestation = &proof["attestation"];
    assert!(signed_by(&hub, attestation), "{attestation}");
    assert_eq!(attestation["event_id"], json!(last));
    let mut claimed = proof["claim"].clone();
    claimed.as_object_mut().unwrap().remove("event_id");
    let ruma::CanonicalJsonValue::Object(claimed) =
        ruma::CanonicalJsonValue::try_from(claimed).unwrap()
    else {
        unreachable!()
    };
    let version = other.state.rooms.room_version(&room).unwrap();
    assert!(matches!(
        spindle_core::version::verify(&key_map(&backup), &claimed, &version),
        Ok(ruma::signatures::Verified::All)
    ));
    assert!(
        proof["claim"]["content"]["org.spindle.prev_epoch_final"]["li"].as_i64()
            < attestation["li"].as_i64()
    );

    // The participant keeps sending, ordinarily: there is no hub it trusts.
    let before = counts(&other);
    other.say(carol, &room, "no hub").await;
    assert_eq!(counts(&other).submitted, before.submitted);
}

#[tokio::test]
async fn a_participant_that_joins_late_anchors_on_a_signed_checkpoint() {
    let hub = Node::start(true).await;
    let late = Node::start(true).await;
    let (room, alice, _) = hub_room(&hub, &[]).await;
    for n in 0..9 {
        hub.say(&alice, &room, &format!("before the join {n}"))
            .await;
    }
    let (carol, carol_id) = late.register("carol").await;
    late.join(&carol, &room, &hub).await;
    assert!(
        eventually(10, async || hub
            .state
            .rooms
            .joined_member_ids(&room)
            .is_ok_and(|members| members.contains(&carol_id)))
        .await
    );
    late.say(&carol, &room, "my first").await;
    for n in 0..8 {
        hub.say(&alice, &room, &format!("after the join {n}")).await;
    }

    assert!(
        eventually(10, async || counts(&late).checkpoints_verified >= 2
            && counts(&late).checkpoint_states_matched >= 1)
        .await,
        "{:?}",
        counts(&late)
    );
    let seen = counts(&late);
    assert_eq!(seen.checkpoint_state_mismatches, 0, "{seen:?}");
    assert_eq!(seen.equivocations, 0, "{seen:?}");
    assert!(counts(&hub).checkpoints_signed >= 2);

    // Every checkpoint is the hub's, carries a state root, and the
    // attestation after it chains from it: the late participant can check
    // what follows without the history before.
    let checkpoints = spindle_server::hub::checkpoints(&late.store, &room);
    let attestations = spindle_server::hub::attestations(&late.store, &room);
    let mut anchored = 0;
    for checkpoint in &checkpoints {
        assert!(signed_by(&hub, checkpoint), "{checkpoint}");
        assert!(checkpoint["state_root"].is_string());
        let next = checkpoint["li"].as_i64().unwrap() + 1;
        if let Some(after) = attestations
            .iter()
            .find(|attestation| attestation["li"].as_i64() == Some(next))
        {
            assert!(spindle_server::hub::chain_step_holds(
                checkpoint["chain"].as_str().unwrap(),
                after["event_id"].as_str().unwrap(),
                after["chain"].as_str().unwrap(),
            ));
            anchored += 1;
        }
    }
    assert!(anchored >= 1, "{checkpoints:?}");
}
